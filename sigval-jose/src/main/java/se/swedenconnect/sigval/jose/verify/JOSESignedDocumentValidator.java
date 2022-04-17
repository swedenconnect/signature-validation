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

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.util.Base64;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.impl.DefaultSignatureValidationResult;
import se.swedenconnect.sigval.jose.data.ExtendedJOSESigvalResult;
import se.swedenconnect.sigval.jose.data.JOSESignatureData;
import se.swedenconnect.sigval.commons.algorithms.JWSAlgorithmRegistry;
import se.swedenconnect.sigval.commons.data.ExtendedSigValResult;
import se.swedenconnect.sigval.commons.data.SignedDocumentValidationResult;
import se.swedenconnect.sigval.commons.utils.SVAUtils;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * XML Document signature validator for validating signatures on XML documents
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class JOSESignedDocumentValidator {

  @Setter private static Set<String> supportedCritHeaderParams = Set.of(
    "sigT","x5t#o","sigX5ts","srCms", "sigPl","srAts","adoTst","sigPId","sigD");

  /** Validator for individual signatures */
  private final JOSESignatureDataValidator joseSignatureDataValidator;

  /**
   * Constructor setting up the validator
   *
   * @param joseSignatureDataValidator signature data validator
   */
  public JOSESignedDocumentValidator(JOSESignatureDataValidator joseSignatureDataValidator) {
    this.joseSignatureDataValidator = joseSignatureDataValidator;
  }

  public SignedDocumentValidationResult<ExtendedJOSESigvalResult> extendedResultValidation(byte[] document)
    throws SignatureException {
    return getConcludingSigVerifyResult(validate(document, null));
  }

  public SignedDocumentValidationResult<ExtendedJOSESigvalResult> extendedResultValidation(byte[] document, Payload detachedPayload)
    throws SignatureException {
    return getConcludingSigVerifyResult(validate(document, detachedPayload));
  }

  /** {@inheritDoc} */
  public List<SignatureValidationResult> validate(byte[] document, Payload detachedPayload) throws SignatureException {

    List<JOSESignatureData> signatureDataList = getJOSEDocumentSignatureData(document, detachedPayload);
    try {
      List<SignatureValidationResult> results = new ArrayList<>();
      for (JOSESignatureData signatureData : signatureDataList) {
        results.add(joseSignatureDataValidator.validateSignature(signatureData));
      }
      return results;
    }
    catch (Exception e) {
      log.error("Error validating JOSE signatures: {}", e.getMessage());
      throw new SignatureException(e.getMessage(), e);
    }
  }

  public static List<JOSESignatureData> getJOSEDocumentSignatureData(byte[] document){
    return getJOSEDocumentSignatureData(document, null);
  }

  public static List<JOSESignatureData> getJOSEDocumentSignatureData(byte[] document, Payload detachedPayload){
    List<JOSESignatureData> signatureDataList = new ArrayList<>();

    boolean detached = detachedPayload != null;

    try {
      JWSObject jwsObject = detached
        ? JWSObject.parse(new String(document, StandardCharsets.UTF_8), detachedPayload)
        : JWSObject.parse(new String(document, StandardCharsets.UTF_8));
      log.debug("Found compact serialized JWS");
      signatureDataList = getSignatureDataFromJWSObject(jwsObject, detached);
    }
    catch (ParseException e) {
      log.debug("No compact serialized JWS signature");
    }

    try {
      JWSObjectJSON jwsObjectJSON = JWSObjectJSON.parse(new String(document, StandardCharsets.UTF_8));
      if (detached) {
        final Map<String, Object> jsonObjecMap = jwsObjectJSON.toGeneralJSONObject();
        jsonObjecMap.put("payload", detachedPayload.toBase64URL().toString());
        jwsObjectJSON = JWSObjectJSON.parse(jsonObjecMap);
      }
      log.debug("Found JSON serialized JWS");
      signatureDataList = getSignatureDataFromJWSJSONObject(jwsObjectJSON, detached);
    }
    catch (ParseException e) {
      log.debug("No JSON serialized JWS signature");
    }
    return signatureDataList;
  }

  private static List<JOSESignatureData> getSignatureDataFromJWSObject(JWSObject jwsObject, boolean detached) {
    JOSESignatureData signatureData = new JOSESignatureData();
    try {
      JWSVerifier verifier = getVerifierAndCerts(jwsObject.getHeader(), signatureData);
      signatureData.setVerified(jwsObject.verify(verifier));
      signatureData.setSignatureBytes(jwsObject.getSignature().decode());
      signatureData.setDetached(detached);
      signatureData.setPayload(jwsObject.getPayload());
      signatureData.setUnprotectedHeader(null);
      signatureData.setHeader(jwsObject.getHeader());
    } catch (Exception ex) {
      signatureData.setException(ex);
      log.debug("Exception while parsing JOSE signature data: {}", ex.toString());
    }
    return List.of(signatureData);
  }

  private static List<JOSESignatureData> getSignatureDataFromJWSJSONObject(JWSObjectJSON jwsObjectJSON, boolean detached) {

    List<JOSESignatureData> signatureDataList = new ArrayList<>();
    try {
      final List<JWSObjectJSON.Signature> signatures = jwsObjectJSON.getSignatures();
      for (JWSObjectJSON.Signature signature : signatures) {
        JOSESignatureData signatureData = new JOSESignatureData();
        try {
          JWSVerifier verifier = getVerifierAndCerts(signature.getHeader(), signatureData);
          signatureData.setVerified(signature.verify(verifier));
          signatureData.setSignatureBytes(signature.getSignature().decode());
          signatureData.setDetached(detached);
          signatureData.setPayload(jwsObjectJSON.getPayload());
          signatureData.setUnprotectedHeader(signature.getUnprotectedHeader());
          signatureData.setHeader(signature.getHeader());
        } catch (Exception ex2) {
          signatureData.setException(ex2);
          log.debug("Exception while parsing JOSE signature data: {}", ex2.toString());
        }
        signatureDataList.add(signatureData);
      }
    } catch (Exception ex) {
      log.debug("Fatal error parsing signature data {}", ex.toString());
      return new ArrayList<>();
    }
    return signatureDataList;
  }

  private static JWSVerifier getVerifierAndCerts(JWSHeader header, JOSESignatureData signatureData)
    throws NoSuchAlgorithmException, CertificateException, IOException, JOSEException {
    final JWSAlgorithm algorithm = header.getAlgorithm();
    boolean ec = JWSAlgorithm.Family.EC.stream()
      .anyMatch(jwsAlgorithm -> jwsAlgorithm.equals(algorithm));
    boolean rsa = JWSAlgorithm.Family.RSA.stream()
      .anyMatch(jwsAlgorithm -> jwsAlgorithm.equals(algorithm));
    final String uri = JWSAlgorithmRegistry.getUri(algorithm);
    if (uri == null){
      throw new IOException("Algoritm is not supported " + algorithm.getName());
    }
    final List<Base64> x509CertChain = header.getX509CertChain();
    List<X509Certificate> certificateChain = new ArrayList<>();
    for (Base64 base64 : x509CertChain) {
      certificateChain.add(SVAUtils.getCertificate(base64.decode()));
    }
    if (certificateChain.isEmpty()){
      throw new IOException("No signing certificate in JWS header");
    }
    signatureData.setSignerCertificate(certificateChain.get(0));
    signatureData.setSignatureCertChain(certificateChain);
    if (ec) {
      signatureData.setSignatureAlgorithm(uri);
      return new ECDSAVerifier((ECPublicKey) signatureData.getSignerCertificate().getPublicKey(), supportedCritHeaderParams);
    }
    if (rsa) {
      signatureData.setSignatureAlgorithm(uri);
      return new RSASSAVerifier((RSAPublicKey) signatureData.getSignerCertificate().getPublicKey(), supportedCritHeaderParams);
    }
    throw new IOException("Unsupported algorithm type");
  }


  /** {@inheritDoc} */
  public boolean isSigned(final byte[] document) throws IllegalArgumentException {
    try {
      JWSObject jwsObject = JWSObject.parse(new String(document, StandardCharsets.UTF_8));
      log.debug("Found compact serialized JWS");
      return jwsObject.getSignature() != null;
    }
    catch (ParseException e) {
      log.debug("No compact serialized JWS signature");
    }

    try {
      JWSObjectJSON jwsObjectJSON = JWSObjectJSON.parse(new String(document, StandardCharsets.UTF_8));
      log.debug("Found JSON serialized JWS");
      final List<JWSObjectJSON.Signature> signatures = jwsObjectJSON.getSignatures();
      return signatures != null && !signatures.isEmpty();
    }
    catch (ParseException e) {
      log.debug("No JSON serialized JWS signature");
    }
    return false;
  }

  /** {@inheritDoc} */
  public List<X509Certificate> getRequiredSignerCertificates() {
    return new ArrayList<>();
  }

  /** {@inheritDoc} */
  public CertificateValidator getCertificateValidator() {
    return joseSignatureDataValidator.getCertificateValidator();
  }

  /**
   * Compile a complete XML signature verification result object from the list of individual signature results
   *
   * @param sigVerifyResultList list of individual signature validation results. Each result must be of type {@link ExtendedJOSESigvalResult}
   * @return Signature validation result objects
   */
  public static SignedDocumentValidationResult<ExtendedJOSESigvalResult> getConcludingSigVerifyResult(
    List<SignatureValidationResult> sigVerifyResultList) {
    SignedDocumentValidationResult<ExtendedJOSESigvalResult> sigVerifyResult = new SignedDocumentValidationResult<>();
    List<ExtendedJOSESigvalResult> extendedJoseSigvalResults = new ArrayList<>();
    try {
      extendedJoseSigvalResults = sigVerifyResultList.stream()
        .map(signatureValidationResult -> (ExtendedJOSESigvalResult) signatureValidationResult)
        .collect(Collectors.toList());
      sigVerifyResult.setSignatureValidationResults(extendedJoseSigvalResults);
    }
    catch (Exception ex) {
      throw new IllegalArgumentException("Provided results are not instances of ExtendedJOSESigvalResult");
    }
    // Test if there are no signatures
    if (sigVerifyResultList.isEmpty()) {
      sigVerifyResult.setSignatureCount(0);
      sigVerifyResult.setStatusMessage("No signatures");
      sigVerifyResult.setValidSignatureCount(0);
      sigVerifyResult.setCompleteSuccess(false);
      sigVerifyResult.setSigned(false);
      return sigVerifyResult;
    }

    //Get valid signatures
    sigVerifyResult.setSigned(true);
    sigVerifyResult.setSignatureCount(sigVerifyResultList.size());
    List<ExtendedJOSESigvalResult> validSignatureResultList = extendedJoseSigvalResults.stream()
      .filter(DefaultSignatureValidationResult::isSuccess)
      .collect(Collectors.toList());

    sigVerifyResult.setValidSignatureCount(validSignatureResultList.size());
    if (validSignatureResultList.isEmpty()) {
      //No valid signatures
      sigVerifyResult.setCompleteSuccess(false);
      sigVerifyResult.setStatusMessage("No valid signatures");
      return sigVerifyResult;
    }

    //Reaching this point means that there are valid signatures.
    if (sigVerifyResult.getSignatureCount() == validSignatureResultList.size()) {
      sigVerifyResult.setStatusMessage("OK");
      sigVerifyResult.setCompleteSuccess(true);
    }
    else {
      sigVerifyResult.setStatusMessage("Some signatures are valid and some are invalid");
      sigVerifyResult.setCompleteSuccess(false);
    }

    //Check if any valid signature signs the whole document
    boolean validSigSignsWholeDoc = validSignatureResultList.stream()
      .anyMatch(ExtendedSigValResult::isCoversDocument);

    sigVerifyResult.setValidSignatureSignsWholeDocument(validSigSignsWholeDoc);

    return sigVerifyResult;
  }

}
