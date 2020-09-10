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

package se.idsec.sigval.pdf.verify.policy.impl;

import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.sigval.cert.chain.PathValidationResult;
import se.idsec.sigval.cert.validity.ValidationStatus;
import se.idsec.sigval.commons.data.SigValIdentifiers;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.pdf.data.PdfTimeValidationResult;
import se.idsec.sigval.pdf.timestamp.PDFTimeStamp;
import se.idsec.sigval.pdf.pdfstruct.PDFSignatureContext;
import se.idsec.sigval.pdf.verify.policy.PolicyValidationResult;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;
import se.idsec.sigval.svt.claims.ValidationConclusion;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This is the PKIX policy for signature validation
 * <p>
 * This policy allows a certificate that was revoked if the signature was timestamped by a trusted timestamp
 * before the certificate was revoked.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@AllArgsConstructor
@Slf4j
public class PkixPdfSignaturePolicyValidator extends AbstractBasicPDFSignaturePolicyChecks {

  /**
   * Defines if validation requires a currently unrevoked signing certificate*
   * A value of true causes this policy validator to require that the signing certificate is not revoked at validation time.
   * If set to false, it will allow revoked certificates if there is a trusted time-stamp as evidence to support that the
   * signature was created before revocation time. Default value is false.
   *
   * @param enforceCurrentTimeValidation true if the signing certificate must be unrevoked at signing time regardless of time stamps (defaut false)
   */
  private boolean enforceCurrentTimeValidation = false;

  /**
   * The enforced margin between signing time and revocation time. The time in milliseconds defined by this parameter
   * must have passed since signing time before the certificate was revoked for this signature to be considered valid.
   * This parameter is only used if enforceCurrentTimeValidation is set to false;
   * The default value of this parameter is 24 hours.
   *
   * @param revocationGracePeriod sets the minimum required time between signing time and revocation time for this policy (default 24 hours)
   */
  @Setter private long revocationGracePeriod = 1000 * 60 * 60 * 24;

  /**
   * Constructor for PKIX policy validator
   * @param enforceCurrentTimeValidation true if the signing certificate must be unrevoked at signing time regardless of time stamps
   */
  public PkixPdfSignaturePolicyValidator(boolean enforceCurrentTimeValidation) {
    this.enforceCurrentTimeValidation = enforceCurrentTimeValidation;
  }

  /**
   * Validate the signature according to PKIX path validation and revocation checking.
   *
   * @param verifyResultSignature the verification result of the signature that MUST provide {@link PathValidationResult} data
   *                              for the validated certificate path
   * @param signatureContext      pdf signature context data holding data about revisions of the signed document
   * @return {@link PolicyValidationResult} for this signature
   */
  @Override protected PolicyValidationResult performAdditionalValidityChecks(ExtendedPdfSigValResult verifyResultSignature,
    PDFSignatureContext signatureContext) {

    PolicyValidationClaims.PolicyValidationClaimsBuilder builder = PolicyValidationClaims.builder();
    builder.pol(getValidationPolicy());

    try {
      PathValidationResult certValResult = (PathValidationResult) verifyResultSignature.getCertificateValidationResult();
      List<ValidationStatus> validationStatusList = certValResult.getValidationStatusList();

      // First. If any certs in the path was invalid. Fail validation
      boolean hasInvalid = validationStatusList.stream()
        .filter(validationStatus -> validationStatus.getValidity().equals(ValidationStatus.CertificateValidity.INVALID))
        .findFirst().isPresent();
      if (hasInvalid) {
        return new PolicyValidationResult(
          builder.res(ValidationConclusion.FAILED)
            .msg("Invalid certificate in certificate path")
            .build(),
          SignatureValidationResult.Status.ERROR_SIGNER_INVALID
        );
      }

      //If there is an indeterminate cert in path. Then return indeterminate
      boolean indeterminateCert = certValResult.getValidationStatusList().stream()
        .filter(validationStatus -> validationStatus.getValidity().equals(ValidationStatus.CertificateValidity.UNKNOWN))
        .findFirst().isPresent();
      if (indeterminateCert) {
        return new PolicyValidationResult(
          builder.res(ValidationConclusion.INDETERMINATE)
            .msg("Validity of the signature could not be determined")
            .build(),
          SignatureValidationResult.Status.ERROR_NOT_TRUSTED
        );
      }

      // If any certs was revoked. Allow this if there is a trusted timestamp for a time before all revocation dates
      if (!enforceCurrentTimeValidation) {
        log.debug("Processing without enforcing current time validation. Looking for valid time stamps");
        List<ValidationStatus> revokedStatusList = validationStatusList.stream()
          .filter(validationStatus -> validationStatus.getValidity().equals(ValidationStatus.CertificateValidity.REVOKED))
          .collect(Collectors.toList());
        if (!revokedStatusList.isEmpty()) {
          log.debug("Found {} revoked certificates in the cert path", revokedStatusList.size());
          // There is at least one revoked cert
          for (ValidationStatus status : revokedStatusList) {
            if (!checkRevocationTime(status, verifyResultSignature.getTimeValidationResults())) {
              // This cert was revoked before timestamp date
              log.debug("certificate was revoked before signing time or within graceperiod of signing time");
              return new PolicyValidationResult(
                builder.res(ValidationConclusion.FAILED)
                  .msg("Certificate revoked")
                  .build(),
                SignatureValidationResult.Status.ERROR_SIGNER_INVALID
              );

            }
          }
          // All revocations was after timestamp
          return new PolicyValidationResult(
            builder.res(ValidationConclusion.PASSED)
              .msg("Certificate revoked after trusted timestamp time")
              .build(),
            SignatureValidationResult.Status.ERROR_SIGNER_INVALID
          );
        }
      }

      // Fail if any exception was recorded by any prior validation process
      if (verifyResultSignature.getException() != null) {
        return new PolicyValidationResult(
          builder.res(ValidationConclusion.FAILED)
            .msg(verifyResultSignature.getException().getMessage())
            .build(),
          SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE
        );
      }
      // Reaching this point means that all certificate statuses was good
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.PASSED)
          .msg("OK")
          .build(),
        SignatureValidationResult.Status.SUCCESS
      );
    }
    catch (Exception ex) {
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.FAILED)
          .msg("Unable to obtain path validation results: " + ex.getMessage())
          .build(),
        SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE
      );
    }
  }

  @Override protected String getValidationPolicy() {
    return enforceCurrentTimeValidation
      ? SigValIdentifiers.SIG_VALIDATION_POLICY_PKIX_VALIDATION
      : SigValIdentifiers.SIG_VALIDATION_POLICY_TIMESTAMPED_PKIX_VALIDATION;
  }

  /**
   * Checks if the revoked status was applied sufficiently after signing time
   *
   * @param validationStatus       information about revocation status
   * @param pdfTimeValidationResults list of timestamps relevant for this signature
   * @return true if revocation was sufficiently after signing time
   */
  private boolean checkRevocationTime(ValidationStatus validationStatus, List<PdfTimeValidationResult> pdfTimeValidationResults) {
    if (pdfTimeValidationResults == null) {
      log.debug("No timestamps available for this signature");
      return false;
    }
    Date revocationTime = validationStatus.getRevocationTime();
    if (revocationTime == null) {
      log.debug("No revocation time available");
      return false;
    }

    List<PDFTimeStamp> validTimestamps = pdfTimeValidationResults.stream()
      .map(pdfTimeValidationResult -> pdfTimeValidationResult.getTimeStamp())
      .filter(pdfTimeStamp -> pdfTimeStamp.hasVerifiedTimestamp())
      .collect(Collectors.toList());

    log.debug("Found {} valid timestamps", validTimestamps.size());

    // earliest date we know the signature existed
    Date firstDate = new Date();

    for (PDFTimeStamp timeStamp : validTimestamps) {
      try {
        Date tsDate = timeStamp.getTstInfo().getGenTime().getDate();
        if (tsDate.before(firstDate)) {
          firstDate = tsDate;
        }
      }
      catch (ParseException e) {
        continue;
      }
    }
    log.debug("Earliest timstamp for this signature: {}", firstDate);
    firstDate = new Date(firstDate.getTime() + revocationGracePeriod);
    log.debug("Earliest allowed revocation time: {}", firstDate);
    log.debug("Actual revocation time: {}", revocationTime);

    boolean certValid = firstDate.before(revocationTime);
    log.debug("Certificate valid: {}", certValid);

    return certValid;
  }
}
