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

package se.swedenconnect.sigval.jose.policy.impl;

import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.swedenconnect.sigval.jose.data.ExtendedJOSESigvalResult;
import se.swedenconnect.sigval.commons.data.PolicyValidationResult;
import se.swedenconnect.sigval.commons.data.SigValIdentifiers;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;
import se.swedenconnect.sigval.svt.claims.ValidationConclusion;

/**
 * Implements a basic signature policy checker. This policy does not apply any additional validity checks
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class BasicJOSESignaturePolicyValidator extends AbstractBasicJOSESignaturePolicyChecks {
  /**
   * These additional checks simply accepts the result of the signature validation process and pass on the result.
   * @param verifyResultSignature result of signature validation process
   * @return {@link PolicyValidationResult} result
   */
  @Override protected PolicyValidationResult performAdditionalValidityChecks(ExtendedJOSESigvalResult verifyResultSignature) {
    if (verifyResultSignature.isSuccess()) {
      return new PolicyValidationResult(
        PolicyValidationClaims.builder()
          .pol(getValidationPolicy())
          .res(ValidationConclusion.PASSED)
          .msg("OK")
          .build(),
        SignatureValidationResult.Status.SUCCESS
      );
    } else {
      return new PolicyValidationResult(
        PolicyValidationClaims.builder()
          .pol(getValidationPolicy())
          .res(ValidationConclusion.FAILED)
          .msg(verifyResultSignature.getStatusMessage())
          .build(),
        verifyResultSignature.getStatus()
      );
    }
  }

  /** {@inheritDoc} */
  @Override protected String getValidationPolicy() {
    return SigValIdentifiers.SIG_VALIDATION_POLICY_BASIC_VALIDATION;
  }
}
