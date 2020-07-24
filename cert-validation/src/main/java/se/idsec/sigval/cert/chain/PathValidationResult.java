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
package se.idsec.sigval.cert.chain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.idsec.sigval.cert.validity.ValidationStatus;

import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Data class for path validation results
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PathValidationResult {

  /** Indicates if the validated path is valid */
  private boolean validCert;
  /** Result of path building from target certificate to a trust anchor */
  private PKIXCertPathBuilderResult pkixCertPathBuilderResult;
  /** The target certificate that is validated through the certificate path */
  private X509Certificate targetCertificate;
  /** The validated certificate chain starting from the target certificate and ending in the trust anchor certificate */
  private List<X509Certificate> chain;
  /** List of status validation results for all certificates in the chain except for the trust anchor certificate, following the same
   * order as the chain certificates */
  private List<ValidationStatus> validationStatusList;
  /** Exception thrown during path validation, if any */
  private Exception exception;
}
