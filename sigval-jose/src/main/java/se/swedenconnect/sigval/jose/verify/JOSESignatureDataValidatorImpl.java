/*
 * Copyright (c) 2020-2022. Sweden Connect
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

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.X509Certificate;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.TimeZone;
import java.util.stream.Collectors;

import org.bouncycastle.util.encoders.Base64;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.UnprotectedHeader;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import lombok.extern.slf4j.Slf4j;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.certificate.impl.DefaultCertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.swedenconnect.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.swedenconnect.sigval.commons.algorithms.JWSAlgorithmRegistry;
import se.swedenconnect.sigval.commons.data.PolicyValidationResult;
import se.swedenconnect.sigval.commons.data.PubKeyParams;
import se.swedenconnect.sigval.commons.data.SigValIdentifiers;
import se.swedenconnect.sigval.commons.data.TimeValidationResult;
import se.swedenconnect.sigval.commons.timestamp.TimeStamp;
import se.swedenconnect.sigval.commons.timestamp.TimeStampPolicyVerifier;
import se.swedenconnect.sigval.commons.utils.GeneralCMSUtils;
import se.swedenconnect.sigval.commons.utils.SVAUtils;
import se.swedenconnect.sigval.jose.data.ExtendedJOSESigvalResult;
import se.swedenconnect.sigval.jose.data.JOSESignatureData;
import se.swedenconnect.sigval.jose.jades.EtsiUComponent;
import se.swedenconnect.sigval.jose.policy.JOSESignaturePolicyValidator;
import se.swedenconnect.sigval.jose.svt.JOSESVTValInput;
import se.swedenconnect.sigval.jose.svt.JOSESVTValidator;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;
import se.swedenconnect.sigval.svt.claims.SignatureClaims;
import se.swedenconnect.sigval.svt.claims.TimeValidationClaims;
import se.swedenconnect.sigval.svt.claims.ValidationConclusion;
import se.swedenconnect.sigval.svt.validation.SignatureSVTValidationResult;

/**
 * Validator for validating single signature elements within an JSON document.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class JOSESignatureDataValidatorImpl implements JOSESignatureDataValidator {

  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  private static final SimpleDateFormat RFC3339_DATE_FORMAT = new SimpleDateFormat("yyy-MM-dd'T'HH:mm:ss'Z'");

  /** Optional certificate validator. */
  private final CertificateValidator certificateValidator;

  /** A verifier used to verify signature timestamps */
  private final TimeStampPolicyVerifier timeStampPolicyVerifier;

  /** Signature policy validator determine the final validity of the signature based on validation policy */
  private final JOSESignaturePolicyValidator signaturePolicyValidator;

  /** An optional validator capable of validating signatures based on provided SVT tokens */
  private final JOSESVTValidator svtValidator;

  static {
    RFC3339_DATE_FORMAT.setTimeZone(TimeZone.getTimeZone("UTC"));
  }

  /**
   * Constructor setting up the validator.
   *
   * @param certificateValidator     certificate validator
   * @param signaturePolicyValidator signature policy validator
   * @param timeStampPolicyVerifier  timestamp policy validator
   */
  public JOSESignatureDataValidatorImpl(final CertificateValidator certificateValidator,
    final JOSESignaturePolicyValidator signaturePolicyValidator, final TimeStampPolicyVerifier timeStampPolicyVerifier) {
    this.certificateValidator = certificateValidator;
    this.signaturePolicyValidator = signaturePolicyValidator;
    this.timeStampPolicyVerifier = timeStampPolicyVerifier;
    this.svtValidator = null;
  }

  /**
   * Constructor setting up the validator.
   *
   * @param certificateValidator     certificate validator
   * @param signaturePolicyValidator signature policy validator
   * @param timeStampPolicyVerifier  timestamp policy validator
   * @param svtValidator             xml SVT validator
   */
  public JOSESignatureDataValidatorImpl(final CertificateValidator certificateValidator,
    final JOSESignaturePolicyValidator signaturePolicyValidator,
    final TimeStampPolicyVerifier timeStampPolicyVerifier,
    final JOSESVTValidator svtValidator) {
    this.certificateValidator = certificateValidator;
    this.signaturePolicyValidator = signaturePolicyValidator;
    this.timeStampPolicyVerifier = timeStampPolicyVerifier;
    this.svtValidator = svtValidator;
  }

  /**
   * Checks that the signature has been validated and that the signer certificate is trusted.
   *
   * @param signatureData information about the signature to validate
   * @return a validation result
   */
  @Override
  public ExtendedJOSESigvalResult validateSignature(final JOSESignatureData signatureData) {

    ExtendedJOSESigvalResult result = new ExtendedJOSESigvalResult();

    try {
      // Attempt SVT validation first
      final JOSESVTValInput svtValInput = JOSESVTValInput.builder()
        .signatureData(signatureData)
        .build();
      // If an SVT validator is present. Attempt to validate any present SVT data
      final List<SignatureSVTValidationResult> svtValidationResultList =
        this.svtValidator == null
          ? null
          : this.svtValidator.validate(svtValInput);
      // Pick the first valid SVT validation result if present
      final SignatureSVTValidationResult validSvtValidationResult =
        svtValidationResultList == null
          ? null
          : svtValidationResultList.stream()
          .filter(SignatureSVTValidationResult::isSvtValidationSuccess)
          .findFirst()
          .orElse(null);

      if (validSvtValidationResult != null) {
        // There is a valid SVT validation result. Then use that
        return this.compileJOSESigValResultsFromSvtValidation(validSvtValidationResult, signatureData);
      }

      // If not SVT validation, then perform normal validation
      result = this.validateSignatureData(signatureData);

      // If we have a cert path validator installed, perform path validation...
      //
      if (result.isSuccess() && this.certificateValidator != null) {
        try {
          final CertificateValidationResult validatorResult = this.certificateValidator.validate(result.getSignerCertificate(),
            result.getSignatureCertificateChain(), null);
          result.setCertificateValidationResult(validatorResult);
        }
        catch (final Exception ex) {
          // We only set errors if path building failed (no path available to trust anchor).
          // All other status indications are evaluated by the signature policy evaluator.
          if (ex instanceof ExtendedCertPathValidatorException) {
            final ExtendedCertPathValidatorException extEx = (ExtendedCertPathValidatorException) ex;
            result.setCertificateValidationResult(extEx.getPathValidationResult());
            final List<X509Certificate> validatedCertificatePath = extEx.getPathValidationResult().getValidatedCertificatePath();
            if (validatedCertificatePath == null || validatedCertificatePath.isEmpty()) {
              log.debug("Failed to build certificates to a trusted path");
              result.setError(SignatureValidationResult.Status.ERROR_NOT_TRUSTED, extEx.getMessage(), ex);
            }
            // We don't set an error if we have path validation result.
          }
          else {
            // This option means that we don't have access to path validation result. Set error always:
            if (ex instanceof CertPathBuilderException) {
              final String msg = String.format("Failed to build a path to a trusted root for signer certificate - %s", ex.getMessage());
              log.error("{}", ex.getMessage());
              result.setError(SignatureValidationResult.Status.ERROR_NOT_TRUSTED, msg, ex);
            }
            else {
              final String msg = String.format("Certificate path validation failure for signer certificate - %s", ex.getMessage());
              log.error("{}", ex.getMessage(), ex);
              result.setError(SignatureValidationResult.Status.ERROR_SIGNER_INVALID, msg, ex);
            }
          }
        }
      }

      // A JOSE signature always covers the whole document
      result.setCoversDocument(true);
      // We regard this as an Etsi Ades if the unprotected header is present with an etsiU component.
      boolean etsiAdes = false;
      final UnprotectedHeader unprotectedHeader = signatureData.getUnprotectedHeader();
      if (unprotectedHeader != null) {
        etsiAdes = unprotectedHeader.getParam("etsiU") != null;
      }
      result.setEtsiAdes(etsiAdes);
      // Check claimed signing time
      result.setClaimedSigningTime(getClaimedSigningTime(signatureData.getHeader()));

      // Timestamp validation
      List<TimeStamp> timeStampList = new ArrayList<>();
      final List<byte[]> signatureTimeStampDataList = getSignatureTimestampList(signatureData);
      if (signatureTimeStampDataList != null && !signatureTimeStampDataList.isEmpty()) {

        // In JAdES, the timestamped bytes are the bytes of the string that is the base64URLEncoded bytes of the signature data!!!
        // MORONS
        byte[] timestampedBytes = Base64URL.encode(signatureData.getSignatureBytes()).toString().getBytes(StandardCharsets.UTF_8);
        timeStampList = signatureTimeStampDataList.stream()
          .map(tsData -> {
            try {
              return new TimeStamp(
                tsData,
                timestampedBytes,
                this.timeStampPolicyVerifier);
            }
            catch (final Exception ex) {
              return null;
            }
          })
          .filter(timeStamp -> timeStamp != null)
          .filter(timeStamp -> timeStamp.getTstInfo() != null)
          .collect(Collectors.toList());
      }

      final List<TimeValidationResult> timeValidationResultList = timeStampList.stream()
        .map(timeStamp -> this.getTimeValidationResult(timeStamp))
        .filter(timeValidationResult -> timeValidationResult != null)
        .collect(Collectors.toList());
      result.setTimeValidationResults(timeValidationResultList);

      // Let the signature policy verifier determine the final result path validation
      // The signature policy verifier may accept a revoked cert if signature is timestamped
      final PolicyValidationResult policyValidationResult = this.signaturePolicyValidator.validatePolicy(result);
      final PolicyValidationClaims policyValidationClaims = policyValidationResult.getPolicyValidationClaims();
      if (!policyValidationClaims.getRes().equals(ValidationConclusion.PASSED)) {
        result.setStatus(policyValidationResult.getStatus());
        result.setStatusMessage(policyValidationClaims.getMsg());
        result.setException(new SignatureException(policyValidationClaims.getMsg()));
      }
      result.setValidationPolicyResultList(Arrays.asList(policyValidationClaims));

    }
    catch (final Exception ex) {
      log.error("Failed to parse signature {}", ex.getMessage());
      result.setError(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE, "Failed to parse signature data", ex);
    }
    return result;
  }

  private Date getClaimedSigningTime(JWSHeader header) {
    if (header == null) {
      return null;
    }
    final Map<String, Object> customParams = header.getCustomParams();
    if (!customParams.containsKey("sigT")) {
      return null;
    }
    final Object sigTObject = customParams.get("sigT");
    if (!(sigTObject instanceof String)) {
      log.debug("Illegal claimed signing time data type");
      return null;
    }
    try {
      return RFC3339_DATE_FORMAT.parse((String) sigTObject);
    }
    catch (ParseException e) {
      log.debug("Unable to parse provided claimed signing time data");
      return null;
    }
  }

  private List<byte[]> getSignatureTimestampList(JOSESignatureData signatureData) {

    final UnprotectedHeader unprotectedHeader = signatureData.getUnprotectedHeader();
    if (unprotectedHeader == null) {
      return new ArrayList<>();
    }
    final Object etsiUObject = unprotectedHeader.getParam("etsiU");
    if (etsiUObject == null || !(etsiUObject instanceof List)) {
      return new ArrayList<>();
    }

    List etsiList = (List) etsiUObject;
    List<EtsiUComponent> etsiUComponentList = new ArrayList<>();
    boolean base64URLEncoded = false;
    boolean plainJson = false;
    for (Object etsiUItemObject : etsiList) {
      if (!(etsiUItemObject instanceof String)) {
        continue;
      }
      String etsiUItem = (String) etsiUItemObject;
      // Attempt raw parsing
      try {
        EtsiUComponent etsiUComponent = OBJECT_MAPPER.readValue(etsiUItem, EtsiUComponent.class);
        etsiUComponentList.add(etsiUComponent);
        plainJson = true;
      }
      catch (Exception ex) {
        // Try to base64UrlDecode first
        try {
          EtsiUComponent etsiUComponent = OBJECT_MAPPER.readValue(Base64URL.from(etsiUItem).decode(), EtsiUComponent.class);
          etsiUComponentList.add(etsiUComponent);
          base64URLEncoded = true;
        }
        catch (Exception ex2) {
          log.debug("And etsiU unsigned header parameter was present, but decoding this parameter failed");
          return new ArrayList<>();
        }
      }
    }
    if (base64URLEncoded && plainJson) {
      log.debug(
        "A mix of JSON encoded and Base64URLencoded data was present. This is illegal, but we allow it by applying the Postel principle");
    }

    // Try to decode the data
    List<byte[]> timestampDataList = new ArrayList<>();
    for (EtsiUComponent etsiUComponent : etsiUComponentList) {
      final EtsiUComponent.TimeStampData sigTst = etsiUComponent.getSigTst();
      if (sigTst != null) {
        final List<EtsiUComponent.TimeStampToken> tstTokens = sigTst.getTstTokens();
        if (tstTokens != null) {
          for (EtsiUComponent.TimeStampToken tstToken : tstTokens) {
            try {
              timestampDataList.add(Base64.decode(tstToken.getVal()));
            }
            catch (Exception ex) {
              log.debug("Failed to decode time stamp token in etsiU time stamp unprotected header");
            }
          }
        }
      }
    }
    return timestampDataList;
  }

  /**
   * Obtains the bytes that should be time stamped by a signature timestamp for a specific signature.
   *
   * <p>
   * According to XAdES, the signature timestamp is calculated over the canonicalized SignatureValue element
   * </p>
   * <p>
   * This means that the element itself with element tags and attributes as well as the Base64 encoded signature value
   * is timestamped, not only the signature bytes. The Canonicalization algorithm used to canonicalize the element value
   * is specified by the ds:CanonicalizationMethod element inside the xades:SignatureTimestamp element
   * </p>
   *
   * @param signatureData signature element
   * @return canonical signature value element bytes
   */
  @SuppressWarnings("unused")
  private byte[] getTimestampedBytes(final JOSESignatureData signatureData) {

    //TODO implement JSON version of this
    return null;

/*
    try {
      final Node sigValElement = signatureElement.getElementsByTagNameNS(XMLDSIG_NS, "SignatureValue").item(0);
      final Transformer transformer = TransformerFactory.newInstance().newTransformer();
      final ByteArrayOutputStream os = new ByteArrayOutputStream();
      transformer.transform(new DOMSource(sigValElement), new StreamResult(os));
      final byte[] sigValElementBytes = os.toByteArray();
      final Canonicalizer canonicalizer = Canonicalizer.getInstance(canonicalizationMethod);
      try (final ByteArrayOutputStream bos = new ByteArrayOutputStream()) {
        canonicalizer.canonicalize(sigValElementBytes, bos, false);
        return bos.toByteArray();
      }
    }
    catch (final Exception ex) {
      log.debug("Failed to parse signature value element using time stamp canonicalization algorithm", ex);
      return null;
    }
*/
  }

  @Override
  public CertificateValidator getCertificateValidator() {
    return this.certificateValidator;
  }

  /**
   * Validates the signature value and checks that the signer certificate is accepted.
   *
   * @param signatureData signature data collected for this signature element
   * @return a validation result
   */
  public ExtendedJOSESigvalResult validateSignatureData(final JOSESignatureData signatureData) {

    final ExtendedJOSESigvalResult result = new ExtendedJOSESigvalResult();

    try {
      // Store the JSON signature specific data
      result.setSignatureValue(signatureData.getSignatureBytes());
      result.setHeader(signatureData.getHeader());
      result.setUnprotectedHeader(signatureData.getUnprotectedHeader());
      result.setPayload(signatureData.getPayload());
      result.setSignedDocument(signatureData.getPayload().toBytes());

      // Locate the certificate that was used to sign ...
      //
      PublicKey validationKey = null;
      final X509Certificate validationCertificate = signatureData.getSignerCertificate();
      if (validationCertificate == null) {
        log.warn("No signing certificate found in signature");
      }
      else {
        result.setSignerCertificate(validationCertificate);
        result.setSignatureCertificateChain(signatureData.getSignatureCertChain());
        validationKey = validationCertificate.getPublicKey();
      }

      // Check signature ...
      //
      if (validationKey == null) {
        // We did not find a validation key (or cert) in the key info
        final String msg = "No certificate or public key found in signature's KeyInfo";
        log.info(msg);
        result.setError(SignatureValidationResult.Status.ERROR_BAD_FORMAT, msg);
        return result;
      }

      // The KeyInfo contained cert/key. First verify signature bytes...
      //
      try {
        // Set pk parameters
        result.setPubKeyParams(GeneralCMSUtils.getPkParams(validationKey));
        // Set algorithm
        result.setSignatureAlgorithm(signatureData.getSignatureAlgorithm());
        // Check signature
        if (!signatureData.isVerified()) {
          final String msg = "Signature is invalid - signature value did not validate correctly or reference digest comparison failed";
          log.info("{}", msg);
          result.setError(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE, msg);
          return result;
        }
      }
      catch (Exception e) {
        final String msg = "Signature is invalid - " + e.getMessage();
        log.info("{}", msg, e);
        result.setError(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE, msg, e);
        return result;
      }
      log.debug("Signature value was successfully validated");

      // Next, make sure that the signer is one of the required ...
      //
      if (result.getSignerCertificate() == null) {
        // If the KeyInfo did not contain a signer certificate, we fail. This validator does not support signatures with
        // absent certificate
        final String msg = "No signer certificate provided with signature";
        log.info("Signature validation failed - {}", msg);
        result.setError(SignatureValidationResult.Status.ERROR_SIGNER_NOT_ACCEPTED, msg);
        return result;
      }
      // The KeyInfo contained a certificate
      result.setStatus(SignatureValidationResult.Status.SUCCESS);
      return result;
    }
    catch (final Exception e) {
      result.setError(SignatureValidationResult.Status.ERROR_BAD_FORMAT, e.getMessage(), e);
      return result;
    }
  }

  /**
   * Add verified timestamps to the signature validation results
   *
   * @param timeStamp the verification results including result data from time stamps embedded in the signature
   */
  private TimeValidationResult getTimeValidationResult(final TimeStamp timeStamp) {

    // Loop through direct validation results and add signature timestamp results
    final TimeValidationClaims timeValidationClaims = this.getVerifiedTimeFromTimeStamp(timeStamp,
      SigValIdentifiers.TIME_VERIFICATION_TYPE_SIG_TIMESTAMP);
    if (timeValidationClaims != null) {
      return new TimeValidationResult(timeValidationClaims, timeStamp.getCertificateValidationResult(), timeStamp);
    }
    return null;
  }

  private TimeValidationClaims getVerifiedTimeFromTimeStamp(final TimeStamp timeStamp, final String type) {
    try {
      final TimeValidationClaims timeValidationClaims = TimeValidationClaims.builder()
        .id(timeStamp.getTstInfo().getSerialNumber().getValue().toString(16))
        .iss(timeStamp.getSigCert().getSubjectX500Principal().toString())
        .time(timeStamp.getTstInfo().getGenTime().getDate().getTime() / 1000)
        .type(type)
        .val(timeStamp.getPolicyValidationClaimsList())
        .build();
      return timeValidationClaims;
    }
    catch (final Exception ex) {
      log.error("Error collecting time validation claims data: {}", ex.getMessage());
      return null;
    }
  }

  /**
   * Use the results obtained from SVT validation to produce general signature validation result as if the signature was
   * validated using complete validation.
   *
   * @param svtValResult  results from SVT validation
   * @param signatureData data collected about this signature
   * @return {@link ExtendedJOSESigvalResult} signature validation results
   */
  private ExtendedJOSESigvalResult compileJOSESigValResultsFromSvtValidation(final SignatureSVTValidationResult svtValResult,
    final JOSESignatureData signatureData) {

    final ExtendedJOSESigvalResult joseSvResult = new ExtendedJOSESigvalResult();

    try {
      // JWS data
      boolean etsiAdes = false;
      final UnprotectedHeader unprotectedHeader = signatureData.getUnprotectedHeader();
      if (unprotectedHeader != null) {
        etsiAdes = unprotectedHeader.getParam("etsiU") != null;
      }

      // Set basic signature data
      joseSvResult.setSignatureValue(signatureData.getSignatureBytes());
      joseSvResult.setHeader(signatureData.getHeader());
      joseSvResult.setUnprotectedHeader(signatureData.getUnprotectedHeader());

      joseSvResult.setSignedDocument(signatureData.getPayload().toBytes());
      joseSvResult.setCoversDocument(true);
      joseSvResult.setEtsiAdes(etsiAdes);
      joseSvResult.setInvalidSignCert(!signatureData.isVerified());
      joseSvResult.setClaimedSigningTime(getClaimedSigningTime(signatureData.getHeader()));

      // Get algorithms and public key type. Note that the source of these values is the SVA signature which is regarded
      // as the algorithm
      // That is effectively protecting the integrity of the signature, superseding the use of the original algorithms.
      final SignedJWT signedJWT = svtValResult.getSignedJWT();
      final JWSAlgorithm svtJwsAlgo = signedJWT.getHeader().getAlgorithm();

      final String algoUri = JWSAlgorithmRegistry.getUri(svtJwsAlgo);
      joseSvResult.setSignatureAlgorithm(algoUri);
      final PubKeyParams pkParams =
        GeneralCMSUtils.getPkParams(SVAUtils.getCertificate(svtValResult.getSignerCertificate()).getPublicKey());
      joseSvResult.setPubKeyParams(pkParams);

      // Set signed SVT JWT
      joseSvResult.setSvtJWT(signedJWT);

      /**
       * Set the signature certs as the result certs and set the validated certs as the validated path in cert
       * validation results The reason for this is that the SVT issuer must decide whether to just include a hash of the
       * certs in the signature or to include all explicit certs of the validated path. The certificates in the
       * CertificateValidationResult represents the validated path. If the validation was done by SVT, then the
       * certificates obtained from SVT validation represents the validated path
       */
      // Get the signature certificates
      joseSvResult.setSignerCertificate(signatureData.getSignerCertificate());
      joseSvResult.setSignatureCertificateChain(signatureData.getSignatureCertChain());
      // Store the svt validated certificates as path of certificate validation results
      final CertificateValidationResult cvr = new DefaultCertificateValidationResult(
        SVAUtils.getOrderedCertList(svtValResult.getSignerCertificate(), svtValResult.getCertificateChain()));
      joseSvResult.setCertificateValidationResult(cvr);

      // Finalize
      final SignatureClaims signatureClaims = svtValResult.getSignatureClaims();
      if (svtValResult.isSvtValidationSuccess()) {
        joseSvResult.setStatus(getStatusFromPolicyValidationClaims(signatureClaims.getSig_val()));
      }
      else {
        joseSvResult.setStatus(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE);
        joseSvResult.setStatusMessage("Unable to verify SVT signature");
      }
      joseSvResult.setSignatureClaims(signatureClaims);
      joseSvResult.setValidationPolicyResultList(signatureClaims.getSig_val());

      // Add SVT timestamp that was used to perform this SVT validation to verified times
      // This ensures that this time stamp gets added when SVT issuance is based on a previous SVT.
      final JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
      final List<TimeValidationClaims> timeValidationClaimsList = signatureClaims.getTime_val();
      timeValidationClaimsList.add(TimeValidationClaims.builder()
        .iss(jwtClaimsSet.getIssuer())
        .time(jwtClaimsSet.getIssueTime().getTime() / 1000)
        .type(SigValIdentifiers.TIME_VERIFICATION_TYPE_SVT)
        .id(jwtClaimsSet.getJWTID())
        .val(Arrays.asList(PolicyValidationClaims.builder()
          .pol(SigValIdentifiers.SIG_VALIDATION_POLICY_PKIX_VALIDATION)
          .res(ValidationConclusion.PASSED)
          .build()))
        .build());
      joseSvResult.setTimeValidationResults(timeValidationClaimsList.stream()
        .map(timeValidationClaims -> new TimeValidationResult(
          timeValidationClaims, null, null))
        .collect(Collectors.toList()));

    }
    catch (final Exception ex) {
      joseSvResult.setStatus(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE);
      joseSvResult.setStatusMessage("Unable to process SVA token or signature data");
      return joseSvResult;
    }
    return joseSvResult;
  }

  private SignatureValidationResult.Status getStatusFromPolicyValidationClaims(List<PolicyValidationClaims> policyValidationClaims) {
    if (policyValidationClaims == null) {
      return SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE;
    }
    if (policyValidationClaims.isEmpty()) {
      return SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE;
    }
    if (policyValidationClaims.stream().anyMatch(pvc -> pvc.getRes().equals(ValidationConclusion.PASSED))) {
      return SignatureValidationResult.Status.SUCCESS;
    }
    if (policyValidationClaims.stream().anyMatch(pvc -> pvc.getRes().equals(ValidationConclusion.FAILED))) {
      return SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE;
    }
    if (policyValidationClaims.stream().anyMatch(pvc -> pvc.getRes().equals(ValidationConclusion.INDETERMINATE))) {
      return SignatureValidationResult.Status.INTERDETERMINE;
    }
    return SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE;
  }

}
