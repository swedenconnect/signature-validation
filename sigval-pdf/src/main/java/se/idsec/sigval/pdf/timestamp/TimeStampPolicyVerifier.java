package se.idsec.sigval.pdf.timestamp;

import org.bouncycastle.asn1.tsp.TSTInfo;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface for a timestamp policy verifier
 */
public interface TimeStampPolicyVerifier {

  /**
   * Verify a timestamp according to a defined policy
   * @param pdfSigBytes the bytes of the PDF signature holding the timestamp
   * @param tstInfo TSTInfo of the timestamp
   * @param sigCert the certificate used to sign the time stamp
   * @param certList a list of certificate supporting validation of the signing certificate
   * @return {@link TimeStampPolicyVerificationResult} verification result
   */
  TimeStampPolicyVerificationResult verifyTsPolicy(byte[] pdfSigBytes, TSTInfo tstInfo, X509Certificate sigCert, List<X509Certificate> certList);
}
