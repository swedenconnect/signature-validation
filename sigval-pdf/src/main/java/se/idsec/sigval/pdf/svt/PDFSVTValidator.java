package se.idsec.sigval.pdf.svt;

import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.codec.binary.Base64;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.sigval.commons.algorithms.DigestAlgorithm;
import se.idsec.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.idsec.sigval.pdf.timestamp.PDFSVTDocTimeStamp;
import se.idsec.sigval.pdf.timestamp.TimeStampPolicyVerifier;
import se.idsec.sigval.pdf.utils.PDFSVAUtils;
import se.idsec.sigval.pdf.verify.PDFSingleSignatureVerifier;
import se.idsec.sigval.svt.claims.*;
import se.idsec.sigval.svt.validation.SVTValidator;
import se.idsec.sigval.svt.validation.SignatureSVTData;

import java.security.MessageDigest;
import java.text.ParseException;
import java.util.*;

/**
 * Implements a validator of Signature Validation Tokens issued to a signed PDF document
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class PDFSVTValidator extends SVTValidator {

  /** Certificate chain validator for SVA tokens **/
  private CertificateValidator svaCertVerifier;
  /** Signature verifier for signatures not supported by SVA. This verifier is also performing validation of signature timestamps **/
  private PDFSingleSignatureVerifier pdfSingleSignatureVerifier;
  /**
   * Array of document timestamp policy verifiers. A timestamp is regarded as trusted if all present policy validators returns a positive result
   * If no policy verifiers are provided, then all timestamps issued by a trusted key is regarded as valid
   **/
  private final TimeStampPolicyVerifier timeStampPolicyVerifier;
  private List<PDFSVTDocTimeStamp> svtTsList;

  /**
   * Constructor
   *
   * @param pdfSingleSignatureVerifier     The verifier used to verify signatures not supported by SVA
   * @param svaCertVerifier          Certificate verifier for the certificate used to sign SVA tokens
   * @param timeStampPolicyVerifier Time stamp policy verifiers to verify Document time stamps
   */
  public PDFSVTValidator(se.idsec.sigval.pdf.verify.PDFSingleSignatureVerifier pdfSingleSignatureVerifier, CertificateValidator svaCertVerifier,
    TimeStampPolicyVerifier timeStampPolicyVerifier) {
    this.pdfSingleSignatureVerifier = pdfSingleSignatureVerifier;
    this.svaCertVerifier = svaCertVerifier;
    this.timeStampPolicyVerifier = timeStampPolicyVerifier;
  }

  @Override protected List<SignatureSVTData> getSignatureSVTData(byte[] pdfDocBytes) throws Exception {
    PDDocument pdfDocument = PDDocument.load(pdfDocBytes);
    List<PDSignature> allSignatureList = pdfDocument.getSignatureDictionaries();
    pdfDocument.close();
    List<PDSignature> svtSigList = new ArrayList<>();
    List<PDSignature> signatureList = new ArrayList<>();

    for (PDSignature signature : allSignatureList) {
      String type = PDFSVAUtils.getSignatureType(signature, signature.getContents(pdfDocBytes));
      switch (type) {
      case PDFSVAUtils.SVT_TYPE:
        svtSigList.add(signature);
        break;
      case PDFSVAUtils.SIGNATURE_TYPE:
        signatureList.add(signature);
      }
    }

    // Obtain the SVA time stamp in this PDF that is the most recent available and valid SVA. This returns null if there is no valid SVA.
    PDFSVTDocTimeStamp svtTimeStamp = getMostRecentValidSVA(svtSigList, pdfDocBytes);

    if (svtTimeStamp == null) {
      return new ArrayList<>();
    }

    /**
     * Check that each signature is covered by a valid SVT token. Then gather data about that signature
     */

    List<SignatureSVTData> sigSVTDataList = new ArrayList<>();
    for (PDSignature signature : signatureList) {
      if (!svtTimeStamp.isSignatureCovered(signature)) {
        // This signature is not covered by the SVT. Skip signature.
        continue;
      }
      collectSVTData(signature, svtTimeStamp, pdfDocBytes, sigSVTDataList);
    }

    return sigSVTDataList;
  }

  private void collectSVTData(PDSignature signature, PDFSVTDocTimeStamp svtTimeStamp, byte[] pdfDocBytes,
    List<SignatureSVTData> sigSVTDataList) {

    SignatureSVTData.SignatureSVTDataBuilder svtDataBuilder = SignatureSVTData.builder();

    try {
      SignedJWT signedJWT = svtTimeStamp.getSignedJWT();
      SVTClaims svtClaims = svtTimeStamp.getSvtClaims();

      //Set hash algorithm
      svtDataBuilder.signedJWT(signedJWT);

      //Get basic signature data
      byte[] sigContentInfo = signature.getContents(pdfDocBytes);
      SignedData signedData = PDFSVAUtils.getSignedDataFromSignature(sigContentInfo);
      SignerInfo signerInfo = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));

      // Get signature SVA claims maching this signature
      byte[] sigValBytes = signerInfo.getEncryptedDigest().getOctets();
      DigestAlgorithm digestAlgorithm = DigestAlgorithmRegistry.get(svtClaims.getHash_algo());
      MessageDigest md = digestAlgorithm.getInstance();
      String signatureHash = Base64.encodeBase64String(md.digest(sigValBytes));
      List<SignatureClaims> sigClaims = svtClaims.getSig();

      Optional<SignatureClaims> sigSVTClaimsOptional = sigClaims.stream()
        .filter(claims -> claims.getSig_ref().getSig_hash().equals(signatureHash))
        .findFirst();

      if (!sigSVTClaimsOptional.isPresent()) {
        //There is not SVT record that matches this signature. Skip signature.
        return;
      }

      SignatureClaims sigSVTClaims = sigSVTClaimsOptional.get();
      //Store sig ref data
      byte[] sigAttrsEncBytes = signerInfo.getAuthenticatedAttributes().getEncoded("DER");
      String signedAttrHash = Base64.encodeBase64String(md.digest(sigAttrsEncBytes));
      svtDataBuilder.signatureReference(SigReferenceClaims.builder()
        .sig_hash(signatureHash)
        .sb_hash(signedAttrHash)
        .build());

      //Store signed data ref
      String signedDocBytesHashStr = Base64.encodeBase64String(md.digest(signature.getSignedContent(pdfDocBytes)));
      int[] byteRange = signature.getByteRange();
      String ref = byteRange[0] + " " + byteRange[1] + " " + byteRange[2] + " " + byteRange[3];
      svtDataBuilder.signedDataRefList(Arrays.asList(SignedDataClaims.builder()
        .hash(signedDocBytesHashStr)
        .ref(ref)
        .build()));

      List<byte[]> signatureCertificateList = PDFSVAUtils.getSignatureCertificateList(sigContentInfo);
      svtDataBuilder.signerCertChain(signatureCertificateList);
      svtDataBuilder.signatureClaims(sigSVTClaims);
      sigSVTDataList.add(svtDataBuilder.build());
    }
    catch (Exception ex) {
      return;
    }
  }

  /**
   * Retrieves the most recent valid SVA token timestamp
   *
   * @param svaSigList  list of present SVA document timestamps
   * @param pdfDocBytes bytes of the signed PDF document
   * @return the document timestamp with the most recent valid SVA token
   */
  private PDFSVTDocTimeStamp getMostRecentValidSVA(List<PDSignature> svaSigList, byte[] pdfDocBytes) {
    svtTsList = new ArrayList<>();
    List<PDFSVTDocTimeStamp> validSvaTsList = new ArrayList<>();
    for (PDSignature svaTsSig : svaSigList) {
      try {
        PDFSVTDocTimeStamp svaTs = new PDFSVTDocTimeStamp(svaTsSig, pdfDocBytes, svaCertVerifier, timeStampPolicyVerifier);
        svtTsList.add(svaTs);
        if (!svaTs.isSigValid()) {
          //SVA TS was not signed correctly by trusted authority
          continue;
        }
        List<PolicyValidationClaims> policyValidationClaimsList = svaTs.getPolicyValidationClaimsList();
        for (PolicyValidationClaims pv : policyValidationClaimsList) {
          if (!pv.getRes().equals(ValidationConclusion.PASSED)) {
            //SVA TS did not pass one of the attached TS validation policies
            continue;
          }
        }
        svaTs.verifySVA();
        // The SVA is valid
        validSvaTsList.add(svaTs);
      }
      catch (Exception e) {
        e.printStackTrace();
      }
    }
    if (validSvaTsList.isEmpty()) {
      return null;
    }
    //Sort valid SVA by date, placing the most recent SVA on top
    Collections.sort(validSvaTsList, new Comparator<PDFSVTDocTimeStamp>() {
      @Override public int compare(PDFSVTDocTimeStamp o1, PDFSVTDocTimeStamp o2) {
        try {
          Date o1Date = o1.getTstInfo().getGenTime().getDate();
          Date o2Date = o2.getTstInfo().getGenTime().getDate();
          return o1Date.after(o2Date) ? -1 : 1;
        }
        catch (ParseException e) {
          return 0;
        }
      }
    });

    return validSvaTsList.get(0);
  }
}
