package se.idsec.sigval.pdf.timestamp;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.sign.pdf.configuration.PDFAlgorithmRegistry;
import se.idsec.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.idsec.sigval.cert.chain.PathValidationResult;
import se.idsec.sigval.commons.algorithms.DigestAlgorithm;
import se.idsec.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.idsec.sigval.commons.algorithms.JWSAlgorithmRegistry;
import se.idsec.sigval.pdf.utils.PDFSVAUtils;
import se.idsec.sigval.svt.claims.SVTClaims;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

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
    CertificateValidator svaTokenCertVerifier, TimeStampPolicyVerifier tsPolicyVerifier) throws Exception {
    super(documentTimestampSig, pdfDoc, tsPolicyVerifier);
    this.svaTokenCertVerifier = svaTokenCertVerifier;
  }

  @Override
  protected void init() throws Exception {
    super.init();
    String svajwt = PDFSVAUtils.getSVAJWT(tstInfo);
    this.signedJWT = SignedJWT.parse(svajwt);
    this.svtClaims = PDFSVAUtils.getSVTClaims(signedJWT.getJWTClaimsSet());
    signedJWT.getHeader().getAlgorithm();
  }

  /**
   * Verifies the SVA.
   *
   * @param certificates Optional array of certificates. If more than one certificate is provided, the first certificate is used as the
   *                     signing certificate and the rest is regarded as supporting chain certificates.
   * @throws Exception if validation of SVA fails
   */
  public void verifySVA(X509Certificate... certificates) throws Exception {
    svaSignatureValid = false;
    getSvaSigningCertificate(certificates);

    // Verify cert and signature of SVA
    svaCertValidationResult = new PathValidationResult();
    try {
      verifySVA(svaSigCert.getPublicKey());
      log.debug("SVA signature verification succeeded");
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
   * Verifies the SVA.
   *
   * @param publicKey the public key used to verify the SVA token signature
   * @throws Exception if validation of SVA fails
   */
  private void verifySVA(PublicKey publicKey) throws Exception {
    //Check for expiry
    Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
    if (expirationTime != null) {
      if (new Date().after(expirationTime)) {
        throw new RuntimeException("The SVA has expired");
      }
    }

    PublicKey svaSigPublicKey = svaSigCert.getPublicKey();
    JWSVerifier verifier = svaSigPublicKey instanceof RSAPublicKey ?
      new RSASSAVerifier((RSAPublicKey) svaSigPublicKey) :
      new ECDSAVerifier((ECPublicKey) svaSigPublicKey);

    //Verify that the hash algorithm is consistent with the SVA claims
    JWSAlgorithm algorithm = signedJWT.getHeader().getAlgorithm();
    String algoUri = JWSAlgorithmRegistry.getUri(algorithm);
    PDFAlgorithmRegistry.PDFSignatureAlgorithmProperties algorithmProperties = PDFAlgorithmRegistry.getAlgorithmProperties(algoUri);

    DigestAlgorithm svaSigHashAlgo = DigestAlgorithmRegistry.get(algorithmProperties.getDigestAlgoOID());
    DigestAlgorithm svaClaimsHashAlgo = DigestAlgorithmRegistry.get(svtClaims.getHash_algo());
    if (!svaSigHashAlgo.equals(svaClaimsHashAlgo)) {
      throw new IOException(
        "SVA hahs algo mismatch. SVA algo: " + svaClaimsHashAlgo.getUri() + ", SVA token sig algo: " + svaSigHashAlgo.getUri());
    }
    svaSignatureValid = signedJWT.verify(verifier);
  }

  /**
   * Obtain SVA validation certificates from the provided SVA
   * If the SVA does not contain any certificates, we will choose the certificate and chain used to sign the timstamp
   * that included the SVA.
   * <p>
   * There are three possible certificate sources and the SVA certificate is selected in the following order
   *
   * <ol>
   *   <li>Use certificates provided in the verifySVA function call</li>
   *   <li>Use certificates provided in the SVA</li>
   *   <li>Fallback to use the certificates used to validate the Time Stamp holding the SVA</li>
   * </ol>*
   *
   * @param certificates
   */
  private void getSvaSigningCertificate(X509Certificate[] certificates) {
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

        JWSAlgorithm jwsAlgorithm = signedJWT.getHeader().getAlgorithm();
        ASN1ObjectIdentifier digestAlgoOID = PDFAlgorithmRegistry.getAlgorithmProperties(
          JWSAlgorithmRegistry.getUri(signedJWT.getHeader().getAlgorithm())).getDigestAlgoOID();
        DigestAlgorithm digestAlgorithm = DigestAlgorithmRegistry.get(digestAlgoOID);
        MessageDigest svaDigestAlgo = digestAlgorithm.getInstance();
        String svaSigCertHashB64 = Base64.encodeBase64String(svaDigestAlgo.digest(sigCert.getEncoded()));
        if (keyID.equals(svaSigCertHashB64)) {
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
