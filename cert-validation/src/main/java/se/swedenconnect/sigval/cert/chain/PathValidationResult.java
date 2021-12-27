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
package se.swedenconnect.sigval.cert.chain;

import lombok.*;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.swedenconnect.sigval.cert.validity.ValidationStatus;

import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Data class for path validation results
 *
 * <p>
 * Failed certificate validation throws an exception with suitable information.
 * </p>
 *
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PathValidationResult implements CertificateValidationResult {

  /** Result of path building from target certificate to a trust anchor */
  @Getter @Setter private PKIXCertPathBuilderResult pkixCertPathBuilderResult;
  /** The target certificate that is validated through the certificate path */
  @Getter @Setter private X509Certificate targetCertificate;
  /** The validated certificate chain starting from the target certificate and ending in the trust anchor certificate */
  @Setter private List<X509Certificate> validatedCertificatePath;
  /** List of status validation results for all certificates in the chain except for the trust anchor certificate, following the same
   * order as the chain certificates */
  @Getter @Setter private List<ValidationStatus> validationStatusList;

  /** {@inheritDoc} */
  @Override public List<X509Certificate> getValidatedCertificatePath() {
    return validatedCertificatePath;
  }

  /** {@inheritDoc} */
  @Override public PKIXCertPathValidatorResult getPKIXCertPathValidatorResult() {
    if (pkixCertPathBuilderResult == null){
      return null;
    }
    return new PKIXCertPathBuilderResult(
      pkixCertPathBuilderResult.getCertPath(),
      pkixCertPathBuilderResult.getTrustAnchor(),
      pkixCertPathBuilderResult.getPolicyTree(),
      pkixCertPathBuilderResult.getPublicKey());
  }
}
