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

package se.idsec.sigval.commons.data;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.sigval.commons.timestamp.TimeStamp;
import se.idsec.sigval.svt.claims.TimeValidationClaims;

/**
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class TimeValidationResult {

  /** The time validation claims providing the validation result of the time validation */
  private TimeValidationClaims timeValidationClaims;
  /** Optional certificate validation result obtained when validating certificates used to verify the time claim */
  private CertificateValidationResult certificateValidationResult;
  /** Signature timestamps obtained through PKI validation of the signature **/
  private TimeStamp timeStamp;

}
