package se.idsec.sigval.cert.validity;

/**
 * This interface defines a function that validates that the signature of validation data is trusted through a validated path
 * to an authorized and trusted source.
 *
 * Typically this means that a CRL must be issued by the entity that issued the certificate being checked for revocation and that
 * an OCSP response is verified by a certificate that is issued directly by the CA that issued the target certificate.
 *
 * Implementations of this interface MUST apply measures to avoid recursive loops in validity checking where validity data
 * to support validation of a certificate is verified through the validated certificate.
 */
public interface ValidityPathChecker {

  /**
   * Verify the trust path used to verify the validity data used to check the revocation status of an X.509 certificate
   * @param validityStatus result of certificate validity check
   * @throws RuntimeException this exception must be thrown in all cases where trust in the validation result can't be verified
   */
  void verifyValidityStatusTrustPath(ValidationStatus validityStatus) throws RuntimeException;

}
