package se.idsec.sigval.pdf.svt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import se.idsec.sigval.commons.data.SignedDocumentValidationResult;
import se.idsec.sigval.commons.svt.AbstractSVTSigValClaimsIssuer;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.pdf.verify.ExtendedPDFSignatureValidator;
import se.idsec.sigval.svt.algorithms.SVTAlgoRegistry;
import se.idsec.sigval.svt.claims.*;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class PDFSVTSigValClaimsIssuer extends AbstractSVTSigValClaimsIssuer<byte[]> {

  private final ExtendedPDFSignatureValidator signatureVerifier;

  /**
   * Constructor for the PDF SVT claims issuer. This class is not thread safe and an instance of this issuer must be created for each instance of SVT creation.
   * @param algorithm the algorithm used to sign the SVT
   * @param privateKey the private key used to sign the SVT
   * @param certificates certificates for validating the signature on the SVT
   * @param signatureVerifier signature verifier used to validate the signature on the PDF document
   * @throws JOSEException on JWT errors
   * @throws NoSuchAlgorithmException if the algorithm is not supported
   */
  public PDFSVTSigValClaimsIssuer(JWSAlgorithm algorithm, Object privateKey, List<X509Certificate> certificates, ExtendedPDFSignatureValidator signatureVerifier)
    throws JOSEException, NoSuchAlgorithmException {
    super(algorithm,privateKey, certificates);
    this.signatureVerifier = signatureVerifier;
  }

  /**
   * This method is called from within the SVT Issuer to perform signature validation and to collect the signature validation claims as a
   * result of this validation process
   *
   * @param signedDocument the signed document to validate
   * @throws IOException on error
   */
  @Override protected List<SignatureClaims> verify(byte[] signedDocument, String hashAlgoUri) throws IOException, SignatureException {
    SignedDocumentValidationResult<ExtendedPdfSigValResult> pdfSigVerifyResultDocument = signatureVerifier.extendedResultValidation(
      signedDocument);

    if (pdfSigVerifyResultDocument.getSignatureCount() < 1) {
      return new ArrayList<>();
    }
    // Loop through the signature validation results
    List<ExtendedPdfSigValResult> resultList = pdfSigVerifyResultDocument.getSignatureValidationResults();
    List<SignatureClaims> claimsResultsList = new ArrayList<>();

    for (ExtendedPdfSigValResult sigResult : resultList) {
      try {
        SignatureClaims claimsData = SignatureClaims.builder()
          .sig_ref(getSigRefData(sigResult.getSignedData(), hashAlgoUri))
          .sig_val(getSignaturePolicyValidations(sigResult))
          .sig_data_ref(getDocRefHashes(sigResult, signedDocument, hashAlgoUri))
          .time_val(
            sigResult.getTimeValidationResults().stream()
            .map(pdfTimeValidationResult -> pdfTimeValidationResult.getTimeValidationClaims())
              .filter(timeValidationClaims -> isVerifiedTime(timeValidationClaims))
            .collect(Collectors.toList())
          )
          .signer_cert_ref(getCertRef(sigResult, hashAlgoUri))
          .build();
        claimsResultsList.add(claimsData);
      }
      catch (Exception e) {
        e.printStackTrace();
      }
    }
    return claimsResultsList;
  }

  /** {@inheritDoc} */
  @Override protected SVTProfile getSvtProfile() {
    return SVTProfile.PDF;
  }

  /**
   * Extract signed attributes and signature data and provide hash of both in a signature reference for an SVA claims set.
   *
   * @param contentInfoBytes CMS Content info from PDF signature (The bytes provided as signature data in a PDF signature dictionary)
   * @return SignatureReference
   * @throws IOException if the content is not legal data
   */
  private SigReferenceClaims getSigRefData(byte[] contentInfoBytes, String hashAlgoUri) throws IOException, NoSuchAlgorithmException {
    ContentInfo contentInfo = ContentInfo.getInstance(new ASN1InputStream(contentInfoBytes).readObject());
    if (!contentInfo.getContentType().equals(PKCSObjectIdentifiers.signedData)) {
      throw new IOException("Illegal content for PDF signature. Must contain SignedData");
    }
    SignedData signedData = SignedData.getInstance(contentInfo.getContent());
    SignerInfo signerInfo = SignerInfo.getInstance(signedData.getSignerInfos().getObjectAt(0));
    byte[] sigAttrsEncBytes = signerInfo.getAuthenticatedAttributes().getEncoded("DER");
    byte[] signatureBytes = signerInfo.getEncryptedDigest().getOctets();

    return SigReferenceClaims.builder()
      .sig_hash(getB64Hash(signatureBytes, hashAlgoUri))
      .sb_hash(getB64Hash(sigAttrsEncBytes, hashAlgoUri))
      .build();
  }

  private List<SignedDataClaims> getDocRefHashes(ExtendedPdfSigValResult sigVerifyResult, byte[] signedDocument, String hashAlgoUri) throws IOException, NoSuchAlgorithmException {
    return Arrays.asList(calculateDocRefHash(sigVerifyResult.getPdfSignature(), signedDocument, hashAlgoUri));
  }

  /**
   * Performs the basic calculation of the hash of signed data in a PDF document, signed by a particular signature
   *
   * @param sig Signature
   * @return Signed document data hashes
   */
  protected SignedDataClaims calculateDocRefHash(PDSignature sig, byte[] signedDocument, String hashAlgoUri) throws IOException, NoSuchAlgorithmException {
    MessageDigest md = SVTAlgoRegistry.getMessageDigestInstance(hashAlgoUri);
    byte[] digest = md.digest(sig.getSignedContent(signedDocument));
    int[] byteRange = sig.getByteRange();
    String ref = byteRange[0] + " " + byteRange[1] + " " + byteRange[2] + " " + byteRange[3];

    return SignedDataClaims.builder()
      .ref(ref)
      .hash(Base64.encodeBase64String(digest))
      .build();
  }

}
