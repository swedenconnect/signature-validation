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

package se.swedenconnect.sigval.xml.policy.impl;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.swedenconnect.sigval.commons.data.PolicyValidationResult;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;
import se.swedenconnect.sigval.svt.claims.ValidationConclusion;
import se.swedenconnect.sigval.xml.data.ExtendedXmlSigvalResult;
import se.swedenconnect.sigval.xml.policy.XMLSignaturePolicyValidator;

/**
 * Abstract implementation of a PDF signature policy checker implementing the {@link XMLSignaturePolicyValidator}
 * interface.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractBasicXMLSignaturePolicyChecks implements XMLSignaturePolicyValidator {

  /**
   * Validate the signature according to the defined policy.
   *
   * @param verifyResultSignature
   *          the verification result of the signature
   * @return {@link PolicyValidationResult} for this signature
   */
  @Override
  public PolicyValidationResult validatePolicy(ExtendedXmlSigvalResult verifyResultSignature) {

    PolicyValidationClaims.PolicyValidationClaimsBuilder builder = PolicyValidationClaims.builder();
    builder.pol(getValidationPolicy());

    // Check if signature validation failed
    // If the result is success or indeterminate, then further checks will be done to determine status
    switch (verifyResultSignature.getStatus()) {
    case ERROR_NOT_TRUSTED:
      // Result is not trusted to a trusted root. We stop here
      log.debug("No valid certificate path was found");
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.INDETERMINATE)
          .msg("No certificate path found to a trusted root")
          .build(),
        SignatureValidationResult.Status.ERROR_NOT_TRUSTED);
    case ERROR_INVALID_SIGNATURE:
    case ERROR_SIGNER_INVALID:
    case ERROR_SIGNER_NOT_ACCEPTED:
    case ERROR_BAD_FORMAT:
      log.debug("Basic signature validation failed with status {}", verifyResultSignature.getStatus());
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.FAILED).msg(verifyResultSignature.getStatusMessage()).build(),
        verifyResultSignature.getStatus());
    default:
      // NOP
    }

    // Make sure that we have a certificate path, just to be sure nothing slips through without a path.
    CertificateValidationResult certificateValidationResult = verifyResultSignature.getCertificateValidationResult();
    List<X509Certificate> validatedCertificatePath = certificateValidationResult != null
        ? certificateValidationResult.getValidatedCertificatePath()
        : new ArrayList<>();
    if (validatedCertificatePath == null || validatedCertificatePath.isEmpty()) {
      // No valid path. Return Indeterminate
      log.debug("No valid certificate path was found");
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.INDETERMINATE)
          .msg("No certificate path found to a trusted root")
          .build(),
        SignatureValidationResult.Status.ERROR_NOT_TRUSTED);
    }

    // Now do certificate trust checking and examine validation checks, timestamps etc.
    return performAdditionalValidityChecks(verifyResultSignature);
  }

  /**
   * This function is called after performing the basic validity checks in the extended abstract superclass. The basic
   * checks done when this function is called are:
   *
   * <ul>
   * <li>Verified that basic signature validation succeeded</li>
   * <li>Verified that no non-signature alterations was made to the document after this signature was created</li>
   * <li>Verified that certificate path validation resulted in a trusted path</li>
   * </ul>
   *
   * <p>
   * This function is responsible for processing any certificate validity results such as results of CRL or OCSP
   * checking
   * </p>
   *
   * @param verifyResultSignature
   *          result of signature validation
   * @return result of extended validation
   */
  protected abstract PolicyValidationResult performAdditionalValidityChecks(ExtendedXmlSigvalResult verifyResultSignature);

  /**
   * Returns the validation policy implemented by this policy validator
   *
   * @return validation policy identifier
   */
  protected abstract String getValidationPolicy();
}
