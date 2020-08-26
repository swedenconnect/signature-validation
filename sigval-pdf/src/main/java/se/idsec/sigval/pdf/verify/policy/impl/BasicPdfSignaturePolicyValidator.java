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

import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.sigval.cert.chain.PathValidationResult;
import se.idsec.sigval.cert.validity.ValidationStatus;
import se.idsec.sigval.commons.data.SigValIdentifiers;
import se.idsec.sigval.pdf.data.ExtendedPdfSigValResult;
import se.idsec.sigval.pdf.data.PdfSignatureContext;
import se.idsec.sigval.pdf.timestamp.PDFTimeStamp;
import se.idsec.sigval.pdf.verify.policy.PDFSignaturePolicyValidator;
import se.idsec.sigval.pdf.verify.policy.PolicyValidationResult;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;
import se.idsec.sigval.svt.claims.ValidationConclusion;

import java.text.ParseException;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * This is the basic policy for signature validation
 * <p>
 * This policy allows a certificate that was revoked if the signature was timestamped by a trusted timestamp
 * before the certificate was revoked.
 */
public class BasicPdfSignaturePolicyValidator implements PDFSignaturePolicyValidator {
  @Override public PolicyValidationResult validatePolicy(ExtendedPdfSigValResult verifyResultSignature,
    PdfSignatureContext signatureContext) {
    PolicyValidationClaims.PolicyValidationClaimsBuilder builder = PolicyValidationClaims.builder();
    builder.pol(SigValIdentifiers.SIG_VALIDATION_POLICY_TIMESTAMPED_PKIX_VALIDATION);

    // Check if signature validation failed
    if (!verifyResultSignature.isSuccess()) {
      //Signature validation has failed. No more checks needed
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.FAILED)
          .msg(verifyResultSignature.getStatusMessage())
          .build(),
        SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE
      );
    }

    // Check for non signature alterations to the document afters signing
    if (signatureContext.isSignatureExtendedByNonSignatureUpdates(verifyResultSignature.getPdfSignature())) {
      return new PolicyValidationResult(
        builder.res(ValidationConclusion.FAILED)
          .msg("Document content was altered after signing")
          .build(),
        SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE
      );
    }

    // If certificate was revoked. Check if revocation times was after time stamp time for any cert in the path
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
          SignatureValidationResult.Status.ERROR_SIGNER_INVALID
        );
      }

      // If any certs was revoked. Allow this if there is a trusted timestamp for a time before all revocation dates
      List<ValidationStatus> statusList = validationStatusList.stream()
        .filter(validationStatus -> validationStatus.getValidity().equals(ValidationStatus.CertificateValidity.REVOKED))
        .collect(Collectors.toList());
      if (!statusList.isEmpty()) {
        // There is at least one revoked cert
        for (ValidationStatus status : statusList) {
          if (!checkRevocationTime(status, verifyResultSignature.getSignatureTimeStampList())) {
            // This cert was revoked before timestamp date
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

      // Fail if any exception was recorded
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

  private boolean checkRevocationTime(ValidationStatus validationStatus, List<PDFTimeStamp> signatureTimeStampList) {
    if (signatureTimeStampList == null) {
      return false;
    }
    Date revocationTime = validationStatus.getRevocationTime();
    if (revocationTime == null) {
      return false;
    }

    List<PDFTimeStamp> validTimestamps = signatureTimeStampList.stream()
      .filter(pdfTimeStamp -> pdfTimeStamp.hasVerifiedTimestamp())
      .collect(Collectors.toList());

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
    return firstDate.before(revocationTime);
  }
}
