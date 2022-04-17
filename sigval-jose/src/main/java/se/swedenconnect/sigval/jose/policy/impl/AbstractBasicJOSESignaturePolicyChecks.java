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

package se.swedenconnect.sigval.jose.policy.impl;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.swedenconnect.sigval.jose.data.ExtendedJOSESigvalResult;
import se.swedenconnect.sigval.jose.policy.JOSESignaturePolicyValidator;
import se.swedenconnect.sigval.commons.data.PolicyValidationResult;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;
import se.swedenconnect.sigval.svt.claims.ValidationConclusion;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Abstract implementation of a signature policy checker implementing the {@link JOSESignaturePolicyValidator} interface
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractBasicJOSESignaturePolicyChecks implements JOSESignaturePolicyValidator {

  /**
   * Validate the signature according to the defined policy.
   *
   * @param verifyResultSignature the verification result of the signature
   * @return {@link PolicyValidationResult} for this signature
   */
  @Override public PolicyValidationResult validatePolicy(ExtendedJOSESigvalResult verifyResultSignature) {

    PolicyValidationClaims.PolicyValidationClaimsBuilder builder = PolicyValidationClaims.builder();
    builder.pol(getValidationPolicy());

    // Check if signature validation failed
    if (!verifyResultSignature.isSuccess()) {
      //Signature validation has failed. No more checks needed
      log.debug("Basic signature validation failed");
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.FAILED)
          .msg(verifyResultSignature.getStatusMessage())
          .build(),
        SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE
      );
    }

    CertificateValidationResult certificateValidationResult = verifyResultSignature.getCertificateValidationResult();
    List<X509Certificate> validatedCertificatePath = certificateValidationResult.getValidatedCertificatePath();
    if (validatedCertificatePath == null || validatedCertificatePath.isEmpty()) {
      log.debug("No valid certificate path was found");
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.INDETERMINATE)
          .msg("Document content was altered after signing")
          .build(),
        SignatureValidationResult.Status.ERROR_NOT_TRUSTED
      );
    }

    return performAdditionalValidityChecks(verifyResultSignature);
  }

  /**
   * This function is called after performing the basic validity checks in the extended abstract superclass. The basic checks done when this
   * function is called are:
   *
   * <ul>
   *   <li>Verified that basic signature validation succeeded</li>
   *   <li>Verified that no non-signature alterations was made to the document after this signature was created</li>
   *   <li>Verified that certificate path validation resulted in a trusted path</li>
   * </ul>
   *
   * <p>This function is responsible for processing any certificate validity results such as results of CRL or OCSP checking</p>
   *
   * @param verifyResultSignature result of signature validation
   * @return result of extended validation
   */
  protected abstract PolicyValidationResult performAdditionalValidityChecks(ExtendedJOSESigvalResult verifyResultSignature);

  /**
   * Returns the validation policy implemented by this policy validator
   *
   * @return validation policy identifier
   */
  protected abstract String getValidationPolicy();
}
