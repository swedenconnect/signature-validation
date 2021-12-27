/*
 * Copyright (c) 2020. Sweden Connect
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

package se.swedenconnect.sigval.pdf.verify.policy.impl;

import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.swedenconnect.sigval.commons.data.PolicyValidationResult;
import se.swedenconnect.sigval.commons.data.SigValIdentifiers;
import se.swedenconnect.sigval.pdf.data.ExtendedPdfSigValResult;
import se.swedenconnect.sigval.pdf.pdfstruct.PDFSignatureContext;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;
import se.swedenconnect.sigval.svt.claims.ValidationConclusion;

/**
 * Implements a basic signature policy checker
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BasicPdfSignaturePolicyValidator extends AbstractBasicPDFSignaturePolicyChecks {
  /** {@inheritDoc} */
  @Override protected PolicyValidationResult performAdditionalValidityChecks(ExtendedPdfSigValResult verifyResultSignature,
    PDFSignatureContext signatureContext) {
    return new PolicyValidationResult(
      PolicyValidationClaims.builder()
        .pol(getValidationPolicy())
        .res(ValidationConclusion.PASSED)
        .msg("OK")
        .build(),
      SignatureValidationResult.Status.SUCCESS
    );
  }

  /** {@inheritDoc} */
  @Override protected String getValidationPolicy() {
    return SigValIdentifiers.SIG_VALIDATION_POLICY_BASIC_VALIDATION;
  }
}
