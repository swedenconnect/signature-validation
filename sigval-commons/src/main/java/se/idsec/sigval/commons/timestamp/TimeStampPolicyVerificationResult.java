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

package se.idsec.sigval.commons.timestamp;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.certificate.impl.DefaultCertificateValidationResult;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;

import java.util.ArrayList;

/**
 * Holds the result of PDF time stamp policy validation
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class TimeStampPolicyVerificationResult {
  /** The SVT claims of the policy validation */
  private PolicyValidationClaims policyValidationClaims;
  /** Result of path validation of the time stamp signature certificates */
  private CertificateValidationResult certificateValidationResult;
  /** Concludes if the timestamp was successfully validated */
  private boolean validTimestamp;
  /** Any exception encountered during validation */
  private Exception exception;

  public TimeStampPolicyVerificationResult(PolicyValidationClaims policyValidationClaims,
    CertificateValidationResult certificateValidationResult) {
    this.policyValidationClaims = policyValidationClaims;
    this.certificateValidationResult = certificateValidationResult;
    this.validTimestamp = true;
  }

  public TimeStampPolicyVerificationResult(PolicyValidationClaims policyValidationClaims, Exception exception) {
    this.policyValidationClaims = policyValidationClaims;
    this.exception = exception;
    this.validTimestamp = false;
    this.certificateValidationResult = new DefaultCertificateValidationResult(new ArrayList<>());
  }
}
