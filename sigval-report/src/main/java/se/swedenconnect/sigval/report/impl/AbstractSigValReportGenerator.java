/*
 * Copyright (c) 2022. IDsec Solutions AB
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

package se.swedenconnect.sigval.report.impl;

import com.nimbusds.jwt.SignedJWT;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.xmlbeans.XmlAnyURI;
import org.apache.xmlbeans.XmlString;
import org.bouncycastle.util.encoders.Base64;
import org.etsi.uri.x01903.v13.DigestAlgAndValueType;
import org.etsi.uri.x19102.v12.*;
import org.w3.x2000.x09.xmldsig.DigestMethodType;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.swedenconnect.sigval.cert.chain.PathValidationResult;
import se.swedenconnect.sigval.cert.validity.ValidationStatus;
import se.swedenconnect.sigval.commons.data.ExtendedSigValResult;
import se.swedenconnect.sigval.commons.data.SigValIdentifiers;
import se.swedenconnect.sigval.commons.data.SignedDocumentValidationResult;
import se.swedenconnect.sigval.commons.data.TimeValidationResult;
import se.swedenconnect.sigval.commons.utils.SVAUtils;
import se.swedenconnect.sigval.report.SigValReportGenerator;
import se.swedenconnect.sigval.report.data.MainIndication;
import se.swedenconnect.sigval.report.data.POETypeOfProof;
import se.swedenconnect.sigval.report.data.SubIndication;
import se.swedenconnect.sigval.report.validationobjects.ValidationObject;
import se.swedenconnect.sigval.report.validationobjects.ValidationObjectProcessor;
import se.swedenconnect.sigval.svt.claims.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public abstract class AbstractSigValReportGenerator<R extends ExtendedSigValResult> implements SigValReportGenerator<R> {

  private final String defaultHashAlgo;

  public AbstractSigValReportGenerator(String defaultHashAlgo) {
    this.defaultHashAlgo = defaultHashAlgo;
  }

  /**
   * Get signature quality from the signature validation result
   *
   * @param sigValResult The result of signature validation
   * @return signature quality
   */
  protected abstract String getSignatureQuality(R sigValResult);

  /**
   * Get the signature validation process identifier for this signature validation process
   *
   * @param sigValResult The result data from signature validation
   * @param pol          the policy used to do the original signature validation
   * @return the signature validation process identifier to be included in the signature validation report
   */
  protected abstract SignatureValidationProcessType getSignatureValidationProcess(R sigValResult, String pol);

  /**
   * Default implementation of the logic to get signature validation process identifier
   * @param sigValResult
   * @param pol
   * @return
   */
  protected SignatureValidationProcessType defaultGetSignatureValidationProcess(R sigValResult, String pol) {
    String methodId = pol == null ? "undefined" : pol;
    SignedJWT svtJWT = sigValResult.getSvtJWT();
    SignatureClaims signatureClaims = sigValResult.getSignatureClaims();
    if (svtJWT != null && signatureClaims != null) {
      if (pol.equalsIgnoreCase(SigValIdentifiers.SIG_VALIDATION_POLICY_PKIX_VALIDATION)) {
        methodId = SigValIdentifiers.SIG_VALIDATION_POLICY_SVT_PKIX_VALIDATION;
      }
      if (pol.equalsIgnoreCase(SigValIdentifiers.SIG_VALIDATION_POLICY_TIMESTAMPED_PKIX_VALIDATION)) {
        methodId = SigValIdentifiers.SIG_VALIDATION_POLICY_SVT_IMESTAMPED_PKIX_VALIDATION;
      }
    }
    SignatureValidationProcessType sigValProcessType = SignatureValidationProcessType.Factory.newInstance();
    sigValProcessType.setSignatureValidationProcessID(methodId);
    return sigValProcessType;
  }

  /**
   * Get the signed data object format for this signature validation result
   *
   * @return Signed data object format
   */
  protected abstract SADataObjectFormatType getDataObjectFormat();

  /**
   * Get the DTBSR (Data to be signed representation) hash value and hash algorithm according the document profile
   *
   * @param sigValResult signature validation result
   * @return digest value and algorithm for the DTBSR
   */
  protected abstract DigestAlgAndValueType getSignatureDtbsDigestAndValue(R sigValResult, String hashAlgoId) throws IOException;

  /**
   * Apply the final validation checks against any policy provided by the profile
   *
   * @param signatureValidationReportType signature validation report data before policy check
   * @param sigValResult                  signature validation result
   */
  protected abstract void applyValidationPolicy(SignatureValidationReportType signatureValidationReportType, R sigValResult);

  @Override public ValidationReportDocument getValidationReport(SignedDocumentValidationResult<R> validationResult) {

    final ValidationReportDocument validationReportDocument = ValidationReportDocument.Factory.newInstance();
    final ValidationReportType validationReport = validationReportDocument.addNewValidationReport();

    final List<R> validationResults = validationResult.getSignatureValidationResults();
    Map<String, ValidationObject> validationObjectMap = new HashMap<>();

    // Get all validation objects
    try {
      // Get all validation object data from the validation results
      validationObjectMap = getValidationObejctMap(validationResults);
      if (!validationObjectMap.isEmpty()) {
        // Create validation objects in the report if validation objects are found
        ValidationObjectListType signatureValidationObjects = validationReport.addNewSignatureValidationObjects();
        Set<String> valObjectKeySet = validationObjectMap.keySet();
        for (String valObejctId : valObjectKeySet) {
          ValidationObject validationObject = validationObjectMap.get(valObejctId);
          ValidationObjectType validationObjectType = signatureValidationObjects.addNewValidationObject();
          validationObjectType.setId(valObejctId);
          XmlAnyURI typeUri = XmlAnyURI.Factory.newInstance();
          typeUri.setStringValue(validationObject.getValidationObjectType().getUriIdentifier());
          validationObjectType.xsetObjectType(typeUri);

          // Set representation data for the validation object
          ValidationObjectRepresentationType validationObjectRepresentationType = ValidationObjectRepresentationType.Factory.newInstance();
          switch (validationObject.getRepresentationType()) {
          case base64:
            // This type is used for validation objects that are available in full, such as certificates
            validationObjectRepresentationType.setBase64(validationObject.getValidationObject());
            validationObjectType.setValidationObjectRepresentation(validationObjectRepresentationType);
            //validationObjectType.set
            break;
          case hash:
            // This type is used for validation objects that are not available in full, but just a hash of if, such as timestamp objects validated using SVT.
            DigestMethodType digestMethodType = DigestMethodType.Factory.newInstance();
            digestMethodType.setAlgorithm(validationObject.getHashAlgorithm());
            DigestAlgAndValueType digestAlgAndValueType = DigestAlgAndValueType.Factory.newInstance();
            digestAlgAndValueType.setDigestValue(validationObject.getHashValue());
            digestAlgAndValueType.setDigestMethod(digestMethodType);
            validationObjectRepresentationType.setDigestAlgAndValue(digestAlgAndValueType);
            validationObjectType.setValidationObjectRepresentation(validationObjectRepresentationType);
            break;
          default:
            throw new IOException("Validation object representation type "
              + validationObject.getRepresentationType().name() + " currently not supported");
          }

          // Set POE if applicable
          if (validationObject.getPoe() != null) {
            POEType poeType = POEType.Factory.newInstance();
            Calendar poeTime = Calendar.getInstance();
            poeTime.setTime(validationObject.getPoe());
            poeType.setPOETime(poeTime);
            poeType.setTypeOfProof(POETypeOfProof.VALIDATION.getUri());
            validationObjectType.setPOE(poeType);
          }
        }
      }
    }
    catch (Exception e) {
      log.debug("Error parsing validation object data", e);
      return validationReportDocument;
    }

    // All validation objects are extracted. Create the report
    for (R sigValResult : validationResults) {
      if (sigValResult == null) {
        // sigValResult must not be null
        log.warn("Processing signature validation result with null signature validation data. Skipping.");
        continue;
      }
      // Obtain the hash algo used to represent hashed data
      String hashAlgoId = getHashAlgo(sigValResult);
      // Create the signature validation report type for this signature
      SignatureValidationReportType signatureValidationReportType = validationReport.addNewSignatureValidationReport();
      // Set validation time
      ValidationTimeInfoType validationTime = ValidationTimeInfoType.Factory.newInstance();
      Calendar currentTime = Calendar.getInstance();
      validationTime.setValidationTime(Calendar.getInstance());
      validationTime.setBestSignatureTime(getBestSignatureTime(sigValResult, currentTime, hashAlgoId));
      signatureValidationReportType.setValidationTimeInfo(validationTime);

      // Set the status indication
      setValidationStatus(sigValResult, signatureValidationReportType);
      // SignatureIdentifier
      updateResult(addSignatureIdentifier(signatureValidationReportType, sigValResult, hashAlgoId), signatureValidationReportType,
        MainIndication.TOTAL_FAILED);
      // Set signerCertificates
      updateResult(addSignerAttributes(signatureValidationReportType, sigValResult, hashAlgoId), signatureValidationReportType, null);

      // Set signer information
      X509Certificate signerCertificate = sigValResult.getSignerCertificate();
      if (signerCertificate == null) {
        continue;
      }
      addSignerInformation(signatureValidationReportType, signerCertificate, hashAlgoId);

      // Set signature quality
      SignatureQualityType signatureQuality = SignatureQualityType.Factory.newInstance();
      signatureQuality.addNewSignatureQualityInformation().setStringValue(getSignatureQuality(sigValResult));
      signatureValidationReportType.setSignatureQuality(signatureQuality);

      // Make last final policy validation
      applyValidationPolicy(signatureValidationReportType, sigValResult);

    }
    return validationReportDocument;
  }

  @SneakyThrows
  protected void addSignerInformation(SignatureValidationReportType signatureValidationReportType, X509Certificate signerCertificate,
    String hashAlgoId) {
    SignerInformationType signerInformation = SignerInformationType.Factory.newInstance();
    VOReferenceType sigCertRef = VOReferenceType.Factory.newInstance();
    sigCertRef.setVOReference(List.of(ValidationObjectProcessor.getId(signerCertificate.getEncoded(), hashAlgoId,
      se.swedenconnect.sigval.report.validationobjects.ValidationObjectType.certificate)));
    signerInformation.setSignerCertificate(sigCertRef);
    signerInformation.setSigner(signerCertificate.getSubjectX500Principal().toString());
    signatureValidationReportType.setSignerInformation(signerInformation);
  }

  /**
   * Add signer attributes to the signature validation report
   *
   * @param signatureValidationReportType the signature validation report object for this signature
   * @param sigValResult                  signature validation result for this signature
   * @param hashAlgoId                    hash algorithm used to hash data
   * @return An error sub indication if some error is encountered or else null (no error)
   */
  protected SubIndication addSignerAttributes(SignatureValidationReportType signatureValidationReportType, R sigValResult,
    String hashAlgoId) {
    X509Certificate signerCertificate = sigValResult.getSignerCertificate();
    if (signerCertificate == null) {
      return SubIndication.NO_SIGNING_CERTIFICATE_FOUND;
    }
    // Create and set the signerAttributes element
    SignatureAttributesType signatureAttributesType = SignatureAttributesType.Factory.newInstance();
    // Set signing time if present
    if (sigValResult.getClaimedSigningTime() != null) {
      Calendar signingTime = Calendar.getInstance();
      signingTime.setTime(sigValResult.getClaimedSigningTime());
      signatureAttributesType.addNewSigningTime().setTime(signingTime);
    }
    // Set document format
    signatureAttributesType.setDataObjectFormatArray(new SADataObjectFormatType[] { getDataObjectFormat() });
    // Set the signer certificate
    try {
      VOReferenceType certificateRef = signatureAttributesType.addNewSigningCertificate().addNewAttributeObject();
      certificateRef.setVOReference(List.of(
        ValidationObjectProcessor.getId(signerCertificate.getEncoded(), hashAlgoId,
          se.swedenconnect.sigval.report.validationobjects.ValidationObjectType.certificate)));
    }
    catch (Exception ex) {
      log.warn("Error processing signature certificate", ex);
      return SubIndication.NO_SIGNING_CERTIFICATE_FOUND;
    }
    //Add timestamp references
    List<TimeValidationResult> timeValidationResults = sigValResult.getTimeValidationResults();
    if (timeValidationResults != null && !timeValidationResults.isEmpty()) {
      for (TimeValidationResult timeValidationResult : timeValidationResults) {
        String validationObjectId = ValidationObjectProcessor.getId(timeValidationResult, hashAlgoId);
        if (validationObjectId != null) {
          VOReferenceType voReferenceType = signatureAttributesType.addNewSignatureTimeStamp().addNewAttributeObject();
          voReferenceType.setVOReference(List.of(validationObjectId));
        }
      }
    }
    signatureValidationReportType.setSignatureAttributes(signatureAttributesType);
    return null;
  }

  /**
   * Obtain the signature proof of existence time (POE)
   *
   * @param sigValResult signature validation result
   * @param currentTime  current time
   * @param hashAlgoId   hash algorithm used to hash data
   * @return proof of existence time data
   */
  protected POEType getBestSignatureTime(R sigValResult, Calendar currentTime, String hashAlgoId) {
    POEType poeType = POEType.Factory.newInstance();
    List<TimeValidationResult> timeValidationResults = sigValResult.getTimeValidationResults();
    if (timeValidationResults == null || timeValidationResults.isEmpty()) {
      poeType.setPOETime(currentTime);
      poeType.setTypeOfProof(POETypeOfProof.VALIDATION.getUri());
      return poeType;
    }
    Optional<TimeValidationResult> timeValidationResultOptional = timeValidationResults.stream()
      .filter(this::isValidTime)
      .sorted((o1, o2) -> (int) (o1.getTimeValidationClaims().getTime() - o2.getTimeValidationClaims().getTime()))
      .findFirst();
    if (timeValidationResultOptional.isEmpty()) {
      // No time validation proofs are valid
      poeType.setPOETime(currentTime);
      poeType.setTypeOfProof(POETypeOfProof.VALIDATION.getUri());
      return poeType;
    }
    // We have verified time of POE
    TimeValidationResult timeValidationResult = timeValidationResultOptional.get();
    Calendar poeTime = Calendar.getInstance();
    poeTime.setTime(new Date(timeValidationResult.getTimeValidationClaims().getTime() * 1000));
    poeType.setPOETime(poeTime);
    poeType.setTypeOfProof(POETypeOfProof.VALIDATION.getUri());
    String validationObjectId = ValidationObjectProcessor.getId(timeValidationResult, hashAlgoId);
    if (validationObjectId != null) {
      VOReferenceType voReferenceType = VOReferenceType.Factory.newInstance();
      voReferenceType.setVOReference(List.of(validationObjectId));
      poeType.setPOEObject(voReferenceType);
    }
    return poeType;
  }

  protected boolean isValidTime(TimeValidationResult timeValidationResult) {
    TimeValidationClaims timeValidationClaims = timeValidationResult.getTimeValidationClaims();
    if (timeValidationClaims == null) {
      return false;
    }
    List<PolicyValidationClaims> val = timeValidationClaims.getVal();
    if (val == null || val.isEmpty()) {
      return false;
    }
    return val.stream().anyMatch(policyValidationClaims -> policyValidationClaims.getRes().equals(ValidationConclusion.PASSED));
  }

  protected void updateResult(SubIndication errorIndication, SignatureValidationReportType signatureValidationReportType,
    MainIndication mainIndication) {
    if (errorIndication == null) {
      return;
    }
    ValidationStatusType signatureValidationStatus = signatureValidationReportType.getSignatureValidationStatus();
    if (mainIndication != null) {
      signatureValidationStatus.setMainIndication(mainIndication.getUri());
    }
    String[] subIndicationArray = signatureValidationStatus.getSubIndicationArray();
    if (subIndicationArray == null || subIndicationArray.length == 0) {
      signatureValidationStatus.setSubIndicationArray(new String[] { errorIndication.getUri() });
    }
    else {
      List<String> subIndicationList = new ArrayList<>(Arrays.asList(subIndicationArray));
      subIndicationList.add(errorIndication.getUri());
      signatureValidationStatus.setSubIndicationArray(subIndicationList.toArray(String[]::new));
    }
  }

  /**
   * Add a signature identifier for a signature in the signature validation report
   *
   * @param signatureValidationReportType the signature validation report object for this signature
   * @param sigValResult                  result from validating this signature
   * @param hashAlgoId                    the hash algorithm used to hash data
   * @return An error sub indication if some error is encountered or else null (no error)
   */
  protected SubIndication addSignatureIdentifier(SignatureValidationReportType signatureValidationReportType, R sigValResult,
    String hashAlgoId) {
    try {
      SignatureIdentifierType signatureIdentifierType = SignatureIdentifierType.Factory.newInstance();
      SignatureClaims signatureClaims = sigValResult.getSignatureClaims();
      DigestAlgAndValueType dtbsrAlgAndValue;
      if (signatureClaims != null) {
        // This is an SVT validation. Get the data from SVT sig val claims
        String dtbsrB64HashStr = signatureClaims.getSig_ref().getSb_hash();
        dtbsrAlgAndValue = DigestAlgAndValueType.Factory.newInstance();
        DigestMethodType digestMethodType = DigestMethodType.Factory.newInstance();
        digestMethodType.setAlgorithm(hashAlgoId);
        dtbsrAlgAndValue.setDigestMethod(digestMethodType);
        dtbsrAlgAndValue.setDigestValue(Base64.decode(dtbsrB64HashStr));
        // Add any present id
        String id = signatureClaims.getSig_ref().getId();
        if (StringUtils.isNotBlank(id)) {
          signatureIdentifierType.setId(id);
        }
      }
      else {
        // This is direct validation. Get the DTBSR from the profile implementation.
        dtbsrAlgAndValue = getSignatureDtbsDigestAndValue(sigValResult, hashAlgoId);
      }
      // Set the DTBSR
      signatureIdentifierType.setDigestAlgAndValue(dtbsrAlgAndValue);

      signatureIdentifierType.setHashOnly(false);
      signatureIdentifierType.setDocHashOnly(false);
      signatureValidationReportType.setSignatureIdentifier(signatureIdentifierType);
      return null;
    }
    catch (Exception ex) {
      log.warn("Failed to process signature identifier data");
      return SubIndication.POLICY_PROCESSING_ERROR;
    }
  }

  /**
   * Set the validation status in the signature validation report
   *
   * @param sigValResult                  validation result for this signature
   * @param signatureValidationReportType the signature validation report object for this signature
   */
  protected void setValidationStatus(R sigValResult, SignatureValidationReportType signatureValidationReportType) {
    List<PolicyValidationClaims> validationPolicyResultList = sigValResult.getValidationPolicyResultList();
    SignatureValidationResult.Status status = sigValResult.getStatus();
    String statusMessage = sigValResult.getStatusMessage();
    MainIndication mainIndication = MainIndication.TOTAL_FAILED;
    List<String> subIndications = new ArrayList<>();
    String method = validationPolicyResultList == null
      ? null
      : validationPolicyResultList.stream()
      .map(PolicyValidationClaims::getPol)
      .findFirst()
      .orElse(null);

    switch (status) {

    case SUCCESS:
      mainIndication = MainIndication.TOTAL_PASSED;
      break;
    case INTERDETERMINE:
      mainIndication = MainIndication.INDETERMINATE;
      addCertValidationSubindications(subIndications, sigValResult);
      break;
    case ERROR_INVALID_SIGNATURE:
      subIndications.add(SubIndication.SIG_CRYPTO_FAILURE.getUri());
      break;
    case ERROR_SIGNER_INVALID:
    case ERROR_SIGNER_NOT_ACCEPTED:
      addCertValidationSubindications(subIndications, sigValResult);
      if (subIndications.isEmpty()) {
        subIndications.add(SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE.getUri());
      }
      break;
    case ERROR_NOT_TRUSTED:
      addCertValidationSubindications(subIndications, sigValResult);
      subIndications.add(SubIndication.NO_CERTIFICATE_CHAIN_FOUND.getUri());
      break;
    case ERROR_BAD_FORMAT:
      subIndications.add(SubIndication.FORMAT_FAILURE.getUri());
      break;
    }

    // Create result data
    ValidationStatusType validationStatus = ValidationStatusType.Factory.newInstance();
    validationStatus.setMainIndication(mainIndication.getUri());
    if (!subIndications.isEmpty()){
      validationStatus.setSubIndicationArray(subIndications.toArray(String[]::new));
    }
    setResultMessage(statusMessage, validationStatus);
    signatureValidationReportType.setSignatureValidationStatus(validationStatus);
    // Set the signature validation process identifier
    SignatureValidationProcessType signatureValidationProcessType = getSignatureValidationProcess(sigValResult , method);
    signatureValidationReportType.setSignatureValidationProcess(signatureValidationProcessType);
  }

  private void addCertValidationSubindications(List<String> subIndications, R sigValidationResult) {

    if (sigValidationResult.getSignerCertificate() != null){
      if (sigValidationResult.getSignerCertificate().getNotAfter().before(new Date())){
        subIndications.add(SubIndication.EXPIRED.getUri());
      }
      if (sigValidationResult.getSignerCertificate().getNotBefore().after(new Date())){
        subIndications.add(SubIndication.NOT_YET_VALID.getUri());
      }
    }

    try {
      PathValidationResult pathValidationResult = (PathValidationResult) sigValidationResult.getCertificateValidationResult();
      ValidationStatus validationStatus = pathValidationResult.getValidationStatusList().get(0);
      ValidationStatus.CertificateValidity validity = validationStatus.getValidity();

      if (validity.equals(ValidationStatus.CertificateValidity.REVOKED)){
        subIndications.add(SubIndication.REVOKED.getUri());
      }

    } catch (Exception ignored) {
      // Causing an exception is not an indication of an error
    }

  }

  /**
   * Set a result message in the validation status
   *
   * @param msg              result message
   * @param validationStatus validation status
   */
  protected void setResultMessage(String msg, ValidationStatusType validationStatus) {
    if (StringUtils.isNotBlank(msg)) {
      // Set message
      TypedDataType reportData = validationStatus
        .addNewAssociatedValidationReportData()
        .addNewAdditionalValidationReportData()
        .addNewReportData();
      reportData.setType(SigValIdentifiers.SIG_VALIDATION_REPORT_STATUS_MESSAGE);
      XmlString stringVal = XmlString.Factory.newInstance();
      stringVal.setStringValue(msg);
      reportData.setValue(stringVal);
    }
  }

  /**
   * Get all the validation objects for all associated signatures and associated timestamps.
   * <p>
   * Validation objects are stored separately in ETSI signature validation reports as a common reference source to
   * mainly certificates and timestamps referred to in the report.
   *
   * @param validationResults the signature validation results
   * @return A map of validation objects to be included in the signature validation report
   * @throws CertificateEncodingException
   * @throws NoSuchAlgorithmException
   */
  protected Map<String, ValidationObject> getValidationObejctMap(List<R> validationResults)
    throws CertificateEncodingException, NoSuchAlgorithmException {

    Map<String, ValidationObject> validationObjectMap = new HashMap<>();

    for (R validationResult : validationResults) {
      String hashAlgoId = getHashAlgo(validationResult);
      ValidationObjectProcessor.storeSigningCertificates(validationResult, validationObjectMap, hashAlgoId);
      ValidationObjectProcessor.storeTimeValidationObjects(validationResult, validationObjectMap, hashAlgoId);
    }
    return validationObjectMap;
  }

  /**
   * Determine the hash algorithm to be used to hash data and to identify hash algorithm for hashed data in the signature validation report
   *
   * @param validationResult the validation result from which hashed data may be extracted
   * @return the suitable hash algorithm to be used in the signature validation report
   */
  protected String getHashAlgo(R validationResult) {
    try {
      // Attempt to extract the hash algorithm used to hash data in any present signature validation token
      SVTClaims svtClaims = SVAUtils.getSVTClaims(validationResult.getSvtJWT().getJWTClaimsSet());
      // Return the SVT hash algorithm
      return svtClaims.getHash_algo();
    }
    catch (Exception ex) {
      // There was no valid SVT used to validate this signature. Use the default hash algorithm.
      return defaultHashAlgo;
    }

  }
}
