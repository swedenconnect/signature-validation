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

package se.swedenconnect.sigval.cert.validity;

/**
 * This interface defines a function that validates that the signature of validation data is trusted through a validated path
 * to an authorized and trusted source.
 *
 * Typically this means that a CRL must be issued by the entity that issued the certificate being checked for revocation and that
 * an OCSP response is verified by a certificate that is issued directly by the CA that issued the target certificate.
 *
 * Implementations of this interface MUST apply measures to avoid recursive loops in validity checking where validity data
 * to support validation of a certificate is verified through the validated certificate.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface ValidityPathChecker {

  /**
   * Verify the trust path used to verify the validity data used to check the revocation status of an X.509 certificate
   * @param validityStatus result of certificate validity check
   * @throws RuntimeException this exception must be thrown in all cases where trust in the validation result can't be verified
   */
  void verifyValidityStatusTrustPath(ValidationStatus validityStatus) throws RuntimeException;

}
