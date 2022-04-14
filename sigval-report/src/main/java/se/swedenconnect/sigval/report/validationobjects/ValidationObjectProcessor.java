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

package se.swedenconnect.sigval.report.validationobjects;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithm;
import se.swedenconnect.sigval.commons.algorithms.DigestAlgorithmRegistry;
import se.swedenconnect.sigval.commons.data.ExtendedSigValResult;
import se.swedenconnect.sigval.commons.data.TimeValidationResult;
import se.swedenconnect.sigval.commons.timestamp.TimeStamp;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;
import se.swedenconnect.sigval.svt.claims.TimeValidationClaims;
import se.swedenconnect.sigval.svt.claims.ValidationConclusion;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class ValidationObjectProcessor {
  public static <R extends ExtendedSigValResult> void storeSigningCertificates(
    R validationResult, Map<String, ValidationObject> validationObjectMap, String hashAlgo)
    throws CertificateEncodingException, NoSuchAlgorithmException {
    final X509Certificate signerCertificate = validationResult.getSignerCertificate();
    if (signerCertificate == null) {
      return;
    }

    addCertificate(signerCertificate, validationObjectMap, hashAlgo);
    final List<X509Certificate> additionalCertificates = validationResult.getAdditionalCertificates();
    for (X509Certificate certificate : additionalCertificates) {
      addCertificate(certificate, validationObjectMap, hashAlgo);
    }
  }

  private static void addCertificate(X509Certificate certificate, Map<String, ValidationObject> validationObjectMap, String hashAlgo)
    throws CertificateEncodingException, NoSuchAlgorithmException {
    byte[] certBytes = certificate.getEncoded();
    String id = getId(certBytes, hashAlgo, ValidationObjectType.certificate);
    if (validationObjectMap.containsKey(id)) {
      return;
    }
    ValidationObject validationObject = ValidationObject.builder()
      .id(id)
      .validationObjectType(ValidationObjectType.certificate)
      .validationObject(certBytes)
      .representationType(RepresentationType.base64)
      .build();
    validationObjectMap.put(id, validationObject);
  }

  public static String getId(byte[] objectBytes, String hashAlgo, ValidationObjectType validationObjectType)
    throws NoSuchAlgorithmException {
    final DigestAlgorithm digestAlgorithm = DigestAlgorithmRegistry.get(hashAlgo);
    final MessageDigest md = digestAlgorithm.getInstance();
    return validationObjectType.getPrefix() + "-" + Hex.toHexString(md.digest(objectBytes));
  }

  public static String getId(TimeValidationResult timeValidationResult, String hashAlgoId) {
    if (timeValidationResult == null){
      return null;
    }
    try {
      Map<String, ValidationObject> validationObjectMap = new HashMap<>();
      if (addTimeEvidenceRef(timeValidationResult, validationObjectMap, hashAlgoId)){
        return validationObjectMap.keySet().stream().findFirst().orElse(null);
      }
      return null;
    } catch (Exception ex) {
      log.warn("Error processing timeValidationResult", ex);
      return null;
    }
  }

  public static <R extends ExtendedSigValResult> void storeTimeValidationObjects(R validationResult,
    Map<String, ValidationObject> validationObjectMap, String hashAlgoId) throws NoSuchAlgorithmException {
    final List<TimeValidationResult> timeValidationResults = validationResult.getTimeValidationResults();
    if (timeValidationResults != null) {
      for (TimeValidationResult timeValidationResult : timeValidationResults) {
        if (addTimeEvidenceRef(timeValidationResult, validationObjectMap, hashAlgoId)){
          // If time evidence was added, then attempt to add time validation certificates
          addTimeValidationCertificatePath(timeValidationResult, validationObjectMap, hashAlgoId);
        }
      }
    }
  }

  /**
   * Add time validation reference object
   * @param timeValidationResult the time validation result
   * @param validationObjectMap the validation object map holding the result objects
   * @param hashAlgoId the hash algorithm used to hash data
   * @return true if a time validation reference object was added to the object map
   * @throws NoSuchAlgorithmException if illegal hash algorithm is provided
   */
  private static boolean addTimeEvidenceRef(TimeValidationResult timeValidationResult, Map<String, ValidationObject> validationObjectMap,
    String hashAlgoId) throws NoSuchAlgorithmException {
    TimeStamp timeStamp = timeValidationResult.getTimeStamp();
    TimeValidationClaims timeValidationClaims = timeValidationResult.getTimeValidationClaims();
    final List<PolicyValidationClaims> validationResult = timeValidationClaims.getVal();
    if (validationResult == null || validationResult.stream()
      .noneMatch(policyValidationClaims -> policyValidationClaims.getRes().equals(ValidationConclusion.PASSED))) {
      // Invalid time claims
      return false;
    }
    final long time = timeValidationClaims.getTime();
    final String b64Hash = timeValidationClaims.getHash();
    byte[] hashVal = null;
    // Validate data
    try {
      if (time == 0) {
        return false;
      }
      if (StringUtils.isNotBlank(b64Hash)) {
        hashVal = Base64.decode(b64Hash);
      } else {
        if (timeStamp != null) {
          hashVal = DigestAlgorithmRegistry.get(hashAlgoId).getInstance().digest(timeStamp.getTimeStampSigBytes());
        }
      }

    } catch (Exception ex) {
      log.debug("Illegal time hash base 64 in time evidence {}", b64Hash);
      return false;
    }

    ValidationObjectType validationObjectType = ValidationObjectType.timestamp;
    if (hashVal ==null) {
      validationObjectType = ValidationObjectType.verifiedTime;
      final byte[] timeBytes = String.valueOf(time).getBytes(StandardCharsets.UTF_8);
      hashVal = DigestAlgorithmRegistry.get(hashAlgoId).getInstance().digest(timeBytes);
    }
    String id = validationObjectType.getPrefix() + "-" + Hex.toHexString(hashVal);
    validationObjectMap.put(id, ValidationObject.builder()
        .id(id)
        .hashValue(hashVal)
        .hashAlgorithm(hashAlgoId)
        .validationObjectType(validationObjectType)
        .representationType(RepresentationType.hash)
      .build());
    return  true;
  }

  private static void addTimeValidationCertificatePath(TimeValidationResult timeValidationResult,
    Map<String, ValidationObject> validationObjectMap, String hashAlgoId) {
    try {
      if (timeValidationResult.getCertificateValidationResult() == null) {
        // There are no certificates validated. Don't attempt to add anything.
        return;
      }
      List<X509Certificate> validatedCertificatePath = timeValidationResult.getCertificateValidationResult().getValidatedCertificatePath();
      for (X509Certificate certificate : validatedCertificatePath){
        addCertificate(certificate, validationObjectMap, hashAlgoId);
      }
    } catch (Exception ex) {
      log.debug("Exception parsing time validation certificate path: {}", ex.toString());
    }
  }
}
