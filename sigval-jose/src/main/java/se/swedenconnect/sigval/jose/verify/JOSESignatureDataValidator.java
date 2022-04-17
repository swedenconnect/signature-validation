/*
 * Copyright (c) 2020-2022.  Sweden Connect
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

package se.swedenconnect.sigval.jose.verify;

import se.idsec.signservice.security.certificate.CertificateValidator;
import se.swedenconnect.sigval.jose.data.ExtendedJOSESigvalResult;
import se.swedenconnect.sigval.jose.data.JOSESignatureData;

/**
 * Interface for XML signature element validator
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface JOSESignatureDataValidator {

  /**
   * validates the signature represented by a single JOSE signature element
   * @param signatureData {@link JOSESignatureData} signature data extracted for this signature
   * @return {@link ExtendedJOSESigvalResult} signature validation result
   */
  ExtendedJOSESigvalResult validateSignature(final JOSESignatureData signatureData);

  /**
   * Ge the certificate validator. This function is added to support the extended interface of the JOSE document validator.
   * This is based on an assumption that signservice commons will be amended with a JOSE module that is implemented in the same manner
   * as the corresponding XML and PDF modules
   *
   * @return certificate validator
   */
  CertificateValidator getCertificateValidator();
}
