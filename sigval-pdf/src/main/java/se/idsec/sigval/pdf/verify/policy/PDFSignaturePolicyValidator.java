package se.idsec.sigval.pdf.verify.policy;

import se.idsec.sigval.commons.data.PolicyValidationResult;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.pdf.pdfstruct.PDFSignatureContext;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;

/**
 * Interface for PDF signature policy validator
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PDFSignaturePolicyValidator {

  /**
   * Validates the signature result according to a defined policy. This examines the result of certificate path validation
   * but does not perform the path validation.
   *
   * <p>A typical task of the policy validator is to determine if a revoked certificate result is allowed if
   * the signature was time stamped before the certificate was revoked</p>
   *
   * @param verifyResultSignature The result of signature validation
   * @return {@link PolicyValidationClaims} result
   */
  PolicyValidationResult validatePolicy(ExtendedPdfSigValResult verifyResultSignature, PDFSignatureContext signatureContext);

}
