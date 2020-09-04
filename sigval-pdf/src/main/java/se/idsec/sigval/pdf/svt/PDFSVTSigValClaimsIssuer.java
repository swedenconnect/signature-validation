package se.idsec.sigval.pdf.svt;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.sun.tools.javac.util.Assert;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;
import org.bouncycastle.asn1.cms.SignerInfo;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.sigval.commons.data.SigValIdentifiers;
import se.idsec.sigval.commons.data.SignedDocumentValidationResult;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.pdf.verify.ExtendedPDFSignatureValidator;
import se.idsec.sigval.svt.algorithms.SVTAlgoRegistry;
import se.idsec.sigval.svt.claims.*;
import se.idsec.sigval.svt.issuer.SVTIssuer;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
public class PDFSVTSigValClaimsIssuer extends SVTIssuer {

  private final ExtendedPDFSignatureValidator signatureVerifier;
  @Setter private boolean defaultBasicValidation = false;
  @Getter private SignedDocumentValidationResult<ExtendedPdfSigValResult> pdfSigVerifyResultDocument;

  /**
   * Constructor for the PDF SVT claims issuer
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
    pdfSigVerifyResultDocument = signatureVerifier.extendedResultValidation(
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
          .sig_data_ref(getDecRefHashes(sigResult, signedDocument, hashAlgoUri))
          .time_val(sigResult.getTimeValidationClaimsList())
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

  private String getB64Hash(byte[] bytes, String hashAlgoUri) throws NoSuchAlgorithmException {
    MessageDigest md = SVTAlgoRegistry.getMessageDigestInstance(hashAlgoUri);
    return Base64.encodeBase64String(md.digest(bytes));
  }

  private List<SignedDataClaims> getDecRefHashes(ExtendedPdfSigValResult sigVerifyResult, byte[] signedDocument, String hashAlgoUri) throws IOException, NoSuchAlgorithmException {
    return Arrays.asList(calculateDocRefHash(sigVerifyResult.getPdfSignature(), signedDocument, hashAlgoUri));
  }

  private CertReferenceClaims getCertRef(ExtendedPdfSigValResult sigResult, String hashAlgoUri)
    throws CertificateEncodingException, NoSuchAlgorithmException, IOException {
    X509Certificate signerCertificate = sigResult.getSignerCertificate();
    List<X509Certificate> signatureCertificateChain = sigResult.getSignatureCertificateChain();

    CertificateValidationResult certificateValidationResult;
    try {
      certificateValidationResult = Assert.checkNonNull(sigResult.getCertificateValidationResult());
    } catch (Exception ex){
      log.error("Unable to obtain the required certificate validation result object", ex);
      throw new IOException("Unable to obtain the required certificate validation result object");
    }

    List<X509Certificate> validatedCertificatePath = certificateValidationResult.getValidatedCertificatePath();
    boolean altered = !isCertPathMatch(validatedCertificatePath, signatureCertificateChain);
    boolean hasValidatedCerts = validatedCertificatePath != null && !validatedCertificatePath.isEmpty();

    if (hasValidatedCerts && altered){
      // A certificate path other than the one provided in the signature was used for signature validation
      // Store the examined certificate path
      List<String> b64Chain = new ArrayList<>();
      for (X509Certificate chainCert: validatedCertificatePath){
        b64Chain.add(Base64.encodeBase64String(chainCert.getEncoded()));
      }
      return CertReferenceClaims.builder()
        .type(CertReferenceClaims.CertRefType.chain.name())
        .ref(b64Chain)
        .build();
    }

    // In all other cases, the original signature chain is provided as hash references.
    MessageDigest md = SVTAlgoRegistry.getMessageDigestInstance(hashAlgoUri);
    String certHash = Base64.encodeBase64String(md.digest(signerCertificate.getEncoded()));
    if (signatureCertificateChain == null || signatureCertificateChain.size() < 2){
      // There is only one signerCertificate. Send it as single reference
      return CertReferenceClaims.builder()
        .type(CertReferenceClaims.CertRefType.chain_hash.name())
        .ref(Arrays.asList(certHash))
        .build();
    }
    // The chain contains more than one signerCertificate. Send chain hash ref
    for (X509Certificate chainCert: signatureCertificateChain){
      md.update(chainCert.getEncoded());
    }
    String chainHash = Base64.encodeBase64String(md.digest());
    return CertReferenceClaims.builder()
      .type(CertReferenceClaims.CertRefType.chain_hash.name())
      .ref(Arrays.asList(certHash, chainHash))
      .build();
  }

  /**
   * Compares the validated path against the signature certificate path and determines if the validated path is altered.
   * @param validatedCertificatePath the validated certificate path
   * @param signatureCertificateChain the certificates obtained from the signature
   * @return true if the signature certificate path contains all certificates of the validated certificate path
   */
  private boolean isCertPathMatch(List<X509Certificate> validatedCertificatePath, List<X509Certificate> signatureCertificateChain) {
    //The validated certificate path is considered to be equal to the signature certificate collection if all certificates in the validated certificate path
    //is found in the signature certificate list

    if (validatedCertificatePath == null || validatedCertificatePath.isEmpty()){
      log.debug("The validated certificate path is null or empty");
      return false;
    }

    for (X509Certificate validatedCert : validatedCertificatePath){
      if (!signatureCertificateChain.contains(validatedCert)){
        log.debug("The validated certificate path is different than the signature certificate path. Signature cert path does not contain {}", validatedCert.getSubjectX500Principal());
        return false;
      }
    }
    log.debug("All certificates in the validated certificate path is found in the signature certificate path");
    return true;
  }

/*
  private String getVerifiedSignerCertHash(ExtendedPdfSigValResult sigVerifyResult, String hashAlgoUri) throws CertificateEncodingException,
    NoSuchAlgorithmException {
    MessageDigest md = SVTAlgoRegistry.getMessageDigestInstance(hashAlgoUri);
    return Base64.encodeBase64String(md.digest(sigVerifyResult.getSignerCertificate().getEncoded()));
  }

  private String getCertChainHash(ExtendedPdfSigValResult sigVerifyResult, String hashAlgoUri)
    throws CertificateEncodingException, NoSuchAlgorithmException {
    MessageDigest md = SVTAlgoRegistry.getMessageDigestInstance(hashAlgoUri);
    List<X509Certificate> chain = sigVerifyResult.getSignatureCertificateChain();
    for (X509Certificate cert : chain) {
      md.update(cert.getEncoded());
    }
    return Base64.encodeBase64String(md.digest());
  }
*/

  /**
   * Perform policy validation
   *
   * @param sigVerifyResult basic validation result
   * @return signature validation result for defined policies
   */
  private List<PolicyValidationClaims> getSignaturePolicyValidations(ExtendedPdfSigValResult sigVerifyResult) {
    List<PolicyValidationClaims> pvList = sigVerifyResult.getValidationPolicyResultList();

    if (pvList.isEmpty() && defaultBasicValidation) {
      log.warn("Signature result did not provide any policy signature result. Configured to set basic validation level");
      pvList.add(PolicyValidationClaims.builder()
        .pol(SigValIdentifiers.SIG_VALIDATION_POLICY_BASIC_VALIDATION)
        .res(sigVerifyResult.isSuccess() ? ValidationConclusion.PASSED : ValidationConclusion.FAILED)
        .build());
    }

    return pvList;
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
