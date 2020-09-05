/*
 * Copyright (c) 2020. IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package se.idsec.sigval.pdf.verify.policy.impl;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.pdf.verify.policy.PDFSignaturePolicyValidator;
import se.idsec.sigval.pdf.pdfstruct.PdfSignatureContext;
import se.idsec.sigval.pdf.verify.policy.PolicyValidationResult;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;
import se.idsec.sigval.svt.claims.ValidationConclusion;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Abstract implementation of a PDF signature policy checker
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractBasicPDFSignaturePolicyChecks implements PDFSignaturePolicyValidator {

  /**
   * Validate the signature according to a defined policy.
   *
   * @param verifyResultSignature the verification result of the signature
   * @param signatureContext      pdf signature context data holding data about revisions of the signed document
   * @return {@link PolicyValidationResult} for this signature
   */
  @Override public PolicyValidationResult validatePolicy(ExtendedPdfSigValResult verifyResultSignature,
    PdfSignatureContext signatureContext) {

    PolicyValidationClaims.PolicyValidationClaimsBuilder builder = PolicyValidationClaims.builder();
    builder.pol(getValidationPolicy());

    // Check if signature validation failed
    if (!verifyResultSignature.isSuccess()) {
      //Signature validation has failed. No more checks needed
      log.debug("Basic signature validation failed");
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.FAILED)
          .msg(verifyResultSignature.getStatusMessage())
          .build(),
        SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE
      );
    }

    // Check for non signature alterations to the document afters signing
    if (signatureContext.isSignatureExtendedByNonSignatureUpdates(verifyResultSignature.getPdfSignature())) {
      log.debug("Signed document has been altered since signed");
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.FAILED)
          .msg("Document content was altered after signing")
          .build(),
        SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE
      );
    }

    CertificateValidationResult certificateValidationResult = verifyResultSignature.getCertificateValidationResult();
    List<X509Certificate> validatedCertificatePath = certificateValidationResult.getValidatedCertificatePath();
    if (validatedCertificatePath == null || validatedCertificatePath.isEmpty()) {
      log.debug("No valid certificate path was found");
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.INDETERMINATE)
          .msg("Document content was altered after signing")
          .build(),
        SignatureValidationResult.Status.ERROR_NOT_TRUSTED
      );
    }

    return performAdditionalValidityChecks(verifyResultSignature, signatureContext);
  }

  /**
   * This function is called after performing the basic validity checks in the extended abstract superclass. The basic checks done when this
   * function is called are:
   *
   * <ul>
   *   <li>Verified that basic signature validation succeeded</li>
   *   <li>Verified that no non-signature alterations was made to the document after this signature was created</li>
   *   <li>Verified that certificate path validation resulted in a trusted path</li>
   * </ul>
   *
   * <p>This function is responsible for processing any certificate validity results such as results of CRL or OCSP checking</p>
   *
   * @param verifyResultSignature
   * @param signatureContext
   * @return
   */
  protected abstract PolicyValidationResult performAdditionalValidityChecks(ExtendedPdfSigValResult verifyResultSignature,
    PdfSignatureContext signatureContext);

  /**
   * Returns the validation policy implemented by this policy validator
   *
   * @return validation policy identifier
   */
  protected abstract String getValidationPolicy();
}
