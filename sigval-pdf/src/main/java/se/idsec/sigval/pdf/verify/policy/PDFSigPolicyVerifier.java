package se.idsec.sigval.pdf.verify.policy;

import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;

public interface PDFSigPolicyVerifier {

  /**
   * Validates the signature result according to a defined policy. This examines the result of certificate path validation
   * but does not perform the path validation.
   * @param verifyResultSignature The result of signature validation
   * @return {@link PolicyValidationClaims} result
   */
  PolicyValidationClaims validatePolicy(ExtendedPdfSigValResult verifyResultSignature);

}
