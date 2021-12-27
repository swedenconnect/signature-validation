package se.swedenconnect.sigval.pdf.verify.policy;

import se.swedenconnect.sigval.commons.data.PolicyValidationResult;
import se.swedenconnect.sigval.pdf.data.ExtendedPdfSigValResult;
import se.swedenconnect.sigval.pdf.pdfstruct.PDFSignatureContext;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;

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
   * @param signatureContext signature context data
   * @return {@link PolicyValidationClaims} result
   */
  PolicyValidationResult validatePolicy(ExtendedPdfSigValResult verifyResultSignature, PDFSignatureContext signatureContext);

}
