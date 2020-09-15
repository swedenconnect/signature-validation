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

package se.idsec.sigval.xml.timestamp;

import lombok.Data;
import lombok.NoArgsConstructor;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.sigval.commons.data.TimeValidationResult;
import se.idsec.sigval.commons.timestamp.TimeStamp;
import se.idsec.sigval.svt.claims.TimeValidationClaims;

/**
 * Time validation result for PDF time stamps
 */
@Data
@NoArgsConstructor
public class XMLTimeValidationResult extends TimeValidationResult {

  public XMLTimeValidationResult(TimeValidationClaims timeValidationClaims,
    CertificateValidationResult certificateValidationResult,
    TimeStamp timeStamp) {
    super(timeValidationClaims, certificateValidationResult);
    this.timeStamp = timeStamp;
  }

  /** Signature timestamps obtained through PKI validation of the signature **/
  private TimeStamp timeStamp;

}
