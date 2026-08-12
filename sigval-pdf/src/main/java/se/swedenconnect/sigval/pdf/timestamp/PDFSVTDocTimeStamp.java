package se.swedenconnect.sigval.pdf.timestamp;

import java.io.ByteArrayInputStream;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

import com.nimbusds.jwt.SignedJWT;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgorithmRegistry;
import se.swedenconnect.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.swedenconnect.sigval.cert.chain.PathValidationResult;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithm;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.swedenconnect.sigval.commons.algorithms.JWSAlgorithmRegistry;
import se.swedenconnect.sigval.commons.timestamp.TimeStampPolicyVerifier;
import se.swedenconnect.sigval.commons.utils.SVAUtils;
import se.swedenconnect.sigval.svt.claims.SVTClaims;

/**
 * Object class holding a SVT document timestamp
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Getter
@Slf4j
public class PDFSVTDocTimeStamp extends PDFDocTimeStamp {

  private SignedJWT signedJWT;
  private SVTClaims svtClaims;
  private X509Certificate svaSigCert;
  private List<X509Certificate> svaChain;
  private boolean svaSignatureValid;
  private CertificateValidator svaTokenCertVerifier;
  private CertificateValidationResult svaCertValidationResult;

  public PDFSVTDocTimeStamp(PDSignature documentTimestampSig, byte[] pdfDoc,
    CertificateValidator svtTokenCertVerifier, TimeStampPolicyVerifier tsPolicyVerifier) throws Exception {
    super(documentTimestampSig, pdfDoc, tsPolicyVerifier);
    this.svaTokenCertVerifier = svtTokenCertVerifier;
  }

  @Override
  protected void init() throws Exception {
    super.init();
    String svtjwt = SVAUtils.getSVTJWT(tstInfo);
    this.signedJWT = SignedJWT.parse(svtjwt);
    this.svtClaims = SVAUtils.getSVTClaims(signedJWT.getJWTClaimsSet());
    signedJWT.getHeader().getAlgorithm();
  }

  /**
   * Verifies the SVT: its signature is checked against the SVT signing certificate and that certificate is path
   * validated.
   * <p>
   * This method does <b>not</b> throw to signal an invalid SVT. Validation failures (a bad SVT signature or a signing
   * certificate that fails path validation) are recorded in the {@code svaSignatureValid} field and must be read by the
   * caller via {@code isSvaSignatureValid()}. A {@code false} result means the SVT must not be trusted. Any exception
   * declared here relates only to unexpected processing errors, not to a negative validation outcome.
   * </p>
   *
   * @param certificates Optional array of certificates. If more than one certificate is provided, the first certificate is used as the
   *                     signing certificate and the rest is regarded as supporting chain certificates.
   * @throws Exception on unexpected processing errors (not raised for a negative validation result)
   */
  public void verifySVA(X509Certificate... certificates) throws Exception {
    svaSignatureValid = false;
    getSvtSigningCertificate(certificates);

    // Verify cert and signature of SVT
    svaCertValidationResult = new PathValidationResult();
    try {
      SVAUtils.verifySVA(signedJWT, svaSigCert.getPublicKey());
      svaSignatureValid = true;
      log.debug("SVT signature verification succeeded");
    }
    catch (Exception ex) {
      log.warn("Error validating the SVT signature: {}", ex.getMessage());
    }
    if (svaSignatureValid){
      try {
        svaCertValidationResult = svaTokenCertVerifier.validate(svaSigCert, svaChain, null);
        log.debug("SVT signature certificate validation succeeded");
      }
      catch (Exception ex) {
        // This means that certificate validation according to certificate verifier failed
        svaSignatureValid = false;
        if (ex instanceof ExtendedCertPathValidatorException){
          svaCertValidationResult = ((ExtendedCertPathValidatorException)ex).getPathValidationResult();
        }
        log.debug("SVT signature certificate fails validation: {}", ex.getMessage());
      }
    }
  }

  /**
   * Obtain SVT validation certificates from the provided SVT
   * If the SVT does not contain any certificates, we will choose the certificate and chain used to sign the timstamp
   * that included the SVT.
   * <p>
   * There are three possible certificate sources and the SVT certificate is selected in the following order
   *
   * <ol>
   *   <li>Use certificates provided in the verifySVA function call</li>
   *   <li>Use certificates provided in the SVT</li>
   *   <li>Fallback to use the certificates used to validate the Time Stamp holding the SVT</li>
   * </ol>*
   *
   * @param certificates
   */
  private void getSvtSigningCertificate(X509Certificate[] certificates) {
    if (certificates.length > 0) {
      // Function call contained certificates. Use them
      svaSigCert = certificates[0];
      svaChain = Arrays.asList(certificates);
      return;
    }

    try {
      List<com.nimbusds.jose.util.Base64> x509CertChain = signedJWT.getHeader().getX509CertChain();
      String keyID = signedJWT.getHeader().getKeyID();
      if (keyID != null) {

        ASN1ObjectIdentifier digestAlgoOID = PDFAlgorithmRegistry.getAlgorithmProperties(
          JWSAlgorithmRegistry.getUri(signedJWT.getHeader().getAlgorithm())).getMessageDigestAlgorithm().getAlgorithmIdentifier().getAlgorithm();
        DigestAlgorithm digestAlgorithm = DigestAlgorithmRegistry.get(digestAlgoOID);
        MessageDigest svtDigestAlgo = digestAlgorithm.getInstance();
        String svtSigCertHashB64 = Base64.encodeBase64String(svtDigestAlgo.digest(sigCert.getEncoded()));
        if (keyID.equals(svtSigCertHashB64)) {
          // The keyID holds the Base64 encoded hash value of the signing cert used to sign the SVT timestamp
          svaSigCert = sigCert;
          svaChain = certList;
          return;
        }
      }
      // No Key ID. Collect and use the embedded chain
      if (x509CertChain == null || x509CertChain.isEmpty()) {
        svaSigCert = sigCert;
        svaChain = certList;
        return;
      }
      List<X509Certificate> referencedCertChain = new ArrayList<>();
      for (com.nimbusds.jose.util.Base64 x5certB64 : x509CertChain) {
        referencedCertChain.add(getCert(x5certB64.toString()));
      }
      svaSigCert = referencedCertChain.get(0);
      svaChain = referencedCertChain;
    }
    catch (Exception ignored) {
      //Error parsing embedded cert. Fallback to using the time stamp certs
      svaSigCert = null;
      svaChain = null;
    }
  }

  private X509Certificate getCert(String certBase64Str) throws CertificateException {
    return (X509Certificate) CertificateFactory.getInstance("X.509")
      .generateCertificate(new ByteArrayInputStream(Base64.decodeBase64(certBase64Str)));
  }
}
