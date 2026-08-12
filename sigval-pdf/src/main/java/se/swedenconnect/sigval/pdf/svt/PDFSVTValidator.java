package se.swedenconnect.sigval.pdf.svt;

import java.security.MessageDigest;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import org.apache.commons.codec.binary.Base64;
import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;

import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithm;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.swedenconnect.sigval.commons.timestamp.TimeStampPolicyVerifier;
import se.swedenconnect.sigval.commons.utils.SVAUtils;
import se.swedenconnect.sigval.pdf.timestamp.PDFSVTDocTimeStamp;
import se.swedenconnect.sigval.pdf.utils.PDFSVAUtils;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;
import se.swedenconnect.sigval.svt.claims.SVTClaims;
import se.swedenconnect.sigval.svt.claims.SigReferenceClaims;
import se.swedenconnect.sigval.svt.claims.SignatureClaims;
import se.swedenconnect.sigval.svt.claims.SignedDataClaims;
import se.swedenconnect.sigval.svt.claims.ValidationConclusion;
import se.swedenconnect.sigval.svt.validation.SVTValidator;
import se.swedenconnect.sigval.svt.validation.SignatureSVTData;

/**
 * Implements a validator of Signature Validation Tokens issued to a signed PDF document
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class PDFSVTValidator extends SVTValidator<byte[]> {

  /** Certificate chain validator for SVTs **/
  private CertificateValidator svtCertVerifier;

  /**
   * Array of document timestamp policy verifiers. A timestamp is regarded as trusted if all present policy validators returns a positive result
   * If no policy verifiers are provided, then all timestamps issued by a trusted key is regarded as valid
   **/
  private final TimeStampPolicyVerifier timeStampPolicyVerifier;
  private List<PDFSVTDocTimeStamp> svtTsList;

  /**
   * Constructor
   *
   * @param svtCertVerifier          Certificate verifier for the certificate used to sign SVTs
   * @param timeStampPolicyVerifier Time stamp policy verifiers to verify Document time stamps
   */
  public PDFSVTValidator(CertificateValidator svtCertVerifier,
    TimeStampPolicyVerifier timeStampPolicyVerifier) {
    this.svtCertVerifier = svtCertVerifier;
    this.timeStampPolicyVerifier = timeStampPolicyVerifier;
  }

  @Override protected List<SignatureSVTData> getSignatureSVTData(byte[] pdfDocBytes) throws Exception {
    PDDocument pdfDocument = Loader.loadPDF(pdfDocBytes);
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

    // Obtain the SVT time stamp in this PDF that is the most recent available and valid SVT. This returns null if there is no valid SVT.
    PDFSVTDocTimeStamp svtTimeStamp = getMostRecentValidSVT(svtSigList, pdfDocBytes);

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
      SignedData signedData = SVAUtils.getSignedDataFromSignature(sigContentInfo);
      SignerInfo signerInfo = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));

      // Get signature SVT claims maching this signature
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
      log.warn("Error collecting SVT data from signature {}", ex.getMessage());
      return;
    }
  }

  /**
   * Retrieves the most recent valid SVT timestamp
   *
   * @param svtSigList  list of present SVT document timestamps
   * @param pdfDocBytes bytes of the signed PDF document
   * @return the document timestamp with the most recent valid SVT
   */
  private PDFSVTDocTimeStamp getMostRecentValidSVT(List<PDSignature> svtSigList, byte[] pdfDocBytes) {
    svtTsList = new ArrayList<>();
    List<PDFSVTDocTimeStamp> validSvtTsList = new ArrayList<>();
    for (PDSignature svtTsSig : svtSigList) {
      try {
        PDFSVTDocTimeStamp svtTs = new PDFSVTDocTimeStamp(svtTsSig, pdfDocBytes, svtCertVerifier, timeStampPolicyVerifier);
        svtTsList.add(svtTs);
        if (!svtTs.isSigValid()) {
          //SVT TS was not signed correctly by trusted authority
          continue;
        }
        List<PolicyValidationClaims> policyValidationClaimsList = svtTs.getPolicyValidationClaimsList();
        boolean allPoliciesPassed = policyValidationClaimsList.stream()
          .allMatch(pv -> ValidationConclusion.PASSED.equals(pv.getRes()));
        if (!allPoliciesPassed) {
          //SVT TS did not pass one of the attached TS validation policies. Skip this SVT.
          continue;
        }
        svtTs.verifySVA();
        if (!svtTs.isSvaSignatureValid()) {
          //The SVT signature or the cert path validation of its signing certificate failed. Skip this SVT.
          continue;
        }
        // The SVT is valid
        validSvtTsList.add(svtTs);
      }
      catch (Exception e) {
        log.debug("Signature validation failed on this SVT JWT - {}", e.getMessage());
      }
    }
    if (validSvtTsList.isEmpty()) {
      return null;
    }
    //Sort valid SVT by date, placing the most recent SVT on top
    Collections.sort(validSvtTsList, new Comparator<PDFSVTDocTimeStamp>() {
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

    return validSvtTsList.get(0);
  }
}
