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

package se.swedenconnect.sigval.jose.policy;

import se.swedenconnect.sigval.jose.data.ExtendedJOSESigvalResult;
import se.swedenconnect.sigval.commons.data.PolicyValidationResult;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;

/**
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface JOSESignaturePolicyValidator {

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
  PolicyValidationResult validatePolicy(ExtendedJOSESigvalResult verifyResultSignature);

}
