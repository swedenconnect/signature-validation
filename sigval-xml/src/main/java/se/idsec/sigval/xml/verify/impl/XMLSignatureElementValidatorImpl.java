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

package se.idsec.sigval.xml.verify.impl;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.c14n.Canonicalizer;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.certificate.impl.DefaultCertificateValidationResult;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.idsec.sigval.commons.algorithms.JWSAlgorithmRegistry;
import se.idsec.sigval.commons.data.PolicyValidationResult;
import se.idsec.sigval.commons.data.PubKeyParams;
import se.idsec.sigval.commons.data.SigValIdentifiers;
import se.idsec.sigval.commons.data.TimeValidationResult;
import se.idsec.sigval.commons.timestamp.TimeStamp;
import se.idsec.sigval.commons.timestamp.TimeStampPolicyVerifier;
import se.idsec.sigval.commons.utils.GeneralCMSUtils;
import se.idsec.sigval.commons.utils.SVAUtils;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;
import se.idsec.sigval.svt.claims.SignatureClaims;
import se.idsec.sigval.svt.claims.TimeValidationClaims;
import se.idsec.sigval.svt.claims.ValidationConclusion;
import se.idsec.sigval.svt.validation.SignatureSVTValidationResult;
import se.idsec.sigval.xml.data.ExtendedXmlSigvalResult;
import se.idsec.sigval.xml.policy.XMLSignaturePolicyValidator;
import se.idsec.sigval.xml.svt.XMLSVTValidator;
import se.idsec.sigval.xml.svt.XMLSigValInput;
import se.idsec.sigval.xml.verify.XMLSignatureElementValidator;
import se.idsec.sigval.xml.xmlstruct.SignatureData;
import se.idsec.sigval.xml.xmlstruct.XAdESObjectParser;
import se.idsec.sigval.xml.xmlstruct.XMLSigConstants;
import se.idsec.sigval.xml.xmlstruct.XadesSignatureTimestampData;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Validator for validating single signature elements within an XML document
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XMLSignatureElementValidatorImpl implements XMLSignatureElementValidator, XMLSigConstants {

  /** Optional certificate validator. */
  private final CertificateValidator certificateValidator;

  /** A verifier used to verify signature timestamps */
  private final TimeStampPolicyVerifier timeStampPolicyVerifier;

  /** Signature policy validator determine the final validity of the signature based on validation policy */
  private final XMLSignaturePolicyValidator signaturePolicyValidator;

  /** An optional validator capable of validating signatures based on provided SVT tokens */
  private final XMLSVTValidator xmlsvtValidator;

  /**
   * Constructor setting up the validator.
   */
  public XMLSignatureElementValidatorImpl(
    CertificateValidator certificateValidator, XMLSignaturePolicyValidator signaturePolicyValidator,
    TimeStampPolicyVerifier timeStampPolicyVerifier) {
    this.certificateValidator = certificateValidator;
    this.signaturePolicyValidator = signaturePolicyValidator;
    this.timeStampPolicyVerifier = timeStampPolicyVerifier;
    this.xmlsvtValidator = null;
  }
  /**
   * Constructor setting up the validator.
   */
  public XMLSignatureElementValidatorImpl(
    CertificateValidator certificateValidator, XMLSignaturePolicyValidator signaturePolicyValidator,
    TimeStampPolicyVerifier timeStampPolicyVerifier, XMLSVTValidator xmlsvtValidator) {
    this.certificateValidator = certificateValidator;
    this.signaturePolicyValidator = signaturePolicyValidator;
    this.timeStampPolicyVerifier = timeStampPolicyVerifier;
    this.xmlsvtValidator = xmlsvtValidator;
  }

  /**
   * Validates the signature value and checks that the signer certificate is accepted.
   *
   * @param signature the signature element
   * @return a validation result
   */
  @Override
  public ExtendedXmlSigvalResult validateSignature(final Element signature, final SignatureData signatureData) {

    ExtendedXmlSigvalResult result = new ExtendedXmlSigvalResult();

    try {
      // Attempt SVT validation first
      XMLSigValInput sigValInput = XMLSigValInput.builder()
        .signatureElement(signature)
        .signatureData(signatureData)
        .build();
      List<SignatureSVTValidationResult> svtValidationResultList = xmlsvtValidator == null ? null : xmlsvtValidator.validate(sigValInput);
      SignatureSVTValidationResult svtValResult = svtValidationResultList == null || svtValidationResultList.isEmpty() ? null : svtValidationResultList.get(0);

      if (svtValResult != null) {
        return compileXMLSigValResultsFromSvtValidation(svtValResult, signature, signatureData);
      }

      // If not SVT validation, then perform normal validation
      result = validateSignatureElement(signature, signatureData);

      // If we have a cert path validator installed, perform path validation...
      //
      if (result.isSuccess() && this.certificateValidator != null) {
        try {
          CertificateValidationResult validatorResult = this.certificateValidator.validate(result.getSignerCertificate(),
            result.getSignatureCertificateChain(), null);
          result.setCertificateValidationResult(validatorResult);
        }
        catch (Exception ex) {
          // We only set errors if path building failed (no path available to trust anchor).
          // All other status indications are evaluated by the signature policy evaluator.
          if (ex instanceof ExtendedCertPathValidatorException) {
            ExtendedCertPathValidatorException extEx = (ExtendedCertPathValidatorException) ex;
            result.setCertificateValidationResult(extEx.getPathValidationResult());
            List<X509Certificate> validatedCertificatePath = extEx.getPathValidationResult().getValidatedCertificatePath();
            if (validatedCertificatePath == null || validatedCertificatePath.isEmpty()){
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

      XAdESObjectParser xAdESObjectParser = new XAdESObjectParser(signature, signatureData);
      result.setSignedDocument(signatureData.getSignedDocument());
      result.setCoversDocument(signatureData.isCoversWholeDoc());
      result.setEtsiAdes(xAdESObjectParser.getQualifyingProperties() != null);
      result.setInvalidSignCert(!xAdESObjectParser.isXadesVerified(result.getSignerCertificate()));
      result.setClaimedSigningTime(xAdESObjectParser.getClaimedSigningTime());

      if (result.isEtsiAdes() && result.isInvalidSignCert()) {
        final String msg = "Signature is XAdES signature, but signature certificate does not match signed certificate digest";
        log.debug(msg);
        result.setError(SignatureValidationResult.Status.ERROR_SIGNER_INVALID, msg, new CertPathBuilderException(msg));
      }

      // Timestamp validation
      List<TimeStamp> timeStampList = new ArrayList<>();
      List<XadesSignatureTimestampData> signatureTimeStampDataList = xAdESObjectParser.getSignatureTimeStampDataList();
      if (signatureTimeStampDataList != null && !signatureTimeStampDataList.isEmpty()) {

        timeStampList = signatureTimeStampDataList.stream()
          .map(tsData -> {
            try {
              return new TimeStamp(
                tsData.getTimeStampSignatureBytes(),
                getTimestampedBytes(signature, tsData.getCanonicalizationMethod()),
                timeStampPolicyVerifier);
            }
            catch (Exception ex) {
              return null;
            }
          })
          .filter(timeStamp -> timeStamp != null)
          .filter(timeStamp -> timeStamp.getTstInfo() != null)
          .collect(Collectors.toList());
      }

      List<TimeValidationResult> timeValidationResultList = timeStampList.stream()
        .map(timeStamp -> getTimeValidationResult(timeStamp))
        .filter(timeValidationResult -> timeValidationResult != null)
        .collect(Collectors.toList());
      result.setTimeValidationResults(timeValidationResultList);

      // Let the signature policy verifier determine the final result path validation
      // The signature policy verifier may accept a revoked cert if signature is timestamped
      PolicyValidationResult policyValidationResult = signaturePolicyValidator.validatePolicy(result);
      PolicyValidationClaims policyValidationClaims = policyValidationResult.getPolicyValidationClaims();
      if (!policyValidationClaims.getRes().equals(ValidationConclusion.PASSED)) {
        result.setStatus(policyValidationResult.getStatus());
        result.setStatusMessage(policyValidationClaims.getMsg());
        result.setException(new SignatureException(policyValidationClaims.getMsg()));
      }
      result.setValidationPolicyResultList(Arrays.asList(policyValidationClaims));

    }
    catch (Exception ex) {
      log.error("Failed to parse signature {}", ex.getMessage());
      result.setError(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE, "Failed to parse signature data", ex);
    }
    return result;
  }

  /**
   * Obtains the bytes that should be time stamped by a signature timestamp for a specific signature.
   *
   * <p>According to XAdES, the signature timestamp is calculated over the canonicalized SignatureValue element</p>
   * <p>This means that the element itself with element tags and attributes as well as the Base64 encoded signature value
   * is timestamped, not only the signature bytes. The Canonicalization algorithm used to canonicalize the element value is
   * specified by the ds:CanonicalizationMethod element inside the xades:SignatureTimestamp element</p>
   *
   * @param signatureElement       signature element
   * @param canonicalizationMethod canonicalization algorithm uri
   * @return canonical signature value element bytes
   */
  private byte[] getTimestampedBytes(Element signatureElement, String canonicalizationMethod) {
    try {
      Node sigValElement = signatureElement.getElementsByTagNameNS(XMLDSIG_NS, "SignatureValue").item(0);
      Transformer transformer = TransformerFactory.newInstance().newTransformer();
      ByteArrayOutputStream os = new ByteArrayOutputStream();
      transformer.transform(new DOMSource(sigValElement), new StreamResult(os));
      byte[] sigValElementBytes = os.toByteArray();
      Canonicalizer canonicalizer = Canonicalizer.getInstance(canonicalizationMethod);
      byte[] canonicalizedSigElement = canonicalizer.canonicalize(sigValElementBytes);
      return canonicalizedSigElement;
    }
    catch (Exception ex) {
      log.debug("Failed to parse signature value element using time stamp canonicalization algorithm", ex);
      return null;
    }
  }

  @Override public CertificateValidator getCertificateValidator() {
    return certificateValidator;
  }

  /**
   * Validates the signature value and checks that the signer certificate is accepted.
   *
   * @param signature the signature element
   * @return a validation result
   */
  public ExtendedXmlSigvalResult validateSignatureElement(final Element signature, SignatureData signatureData) {

    ExtendedXmlSigvalResult result = new ExtendedXmlSigvalResult();
    result.setSignatureElement(signature);

    try {
      // Parse the signature element.
      XMLSignature xmlSignature = new XMLSignature(signature, "");

      // Locate the certificate that was used to sign ...
      //
      PublicKey validationKey = null;
      X509Certificate validationCertificate = signatureData.getSignerCertificate();
      if (validationCertificate == null){
        log.warn("No signing certificate found in signature");
        validationKey = xmlSignature.getKeyInfo().getPublicKey();
      } else {
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
        result.setSignatureAlgorithm(xmlSignature.getSignedInfo().getSignatureMethodURI());
        // Check signature
        if (!xmlSignature.checkSignatureValue(validationKey)) {
          final String msg = "Signature is invalid - signature value did not validate correctly or reference digest comparison failed";
          log.info("{}", msg);
          result.setError(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE, msg);
          return result;
        }
      }
      catch (XMLSignatureException | IOException e) {
        final String msg = "Signature is invalid - " + e.getMessage();
        log.info("{}", msg, e);
        result.setError(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE, msg, e);
        return result;
      }
      log.debug("Signature value was successfully validated");

      // Next, make sure that the signer is one of the required ...
      //
      if (result.getSignerCertificate() == null) {
        // If the KeyInfo did not contain a signer certificate, we fail. This validator does not support signatures with absent certificate
        final String msg = "No signer certificate provided with signature";
        log.info("Signature validation failed - {}", msg);
        result.setError(SignatureValidationResult.Status.ERROR_SIGNER_NOT_ACCEPTED, msg);
        return result;
      }
      // The KeyInfo contained a certificate
      result.setStatus(SignatureValidationResult.Status.SUCCESS);
      return result;
    }
    catch (Exception e) {
      result.setError(SignatureValidationResult.Status.ERROR_BAD_FORMAT, e.getMessage(), e);
      return result;
    }
  }

  /**
   * Add verified timestamps to the signature validation results
   *
   * @param timeStamp the verification results including result data from time stamps embedded in the signature
   */
  private TimeValidationResult getTimeValidationResult(TimeStamp timeStamp) {

    // Loop through direct validation results and add signature timestamp results
    TimeValidationClaims timeValidationClaims = getVerifiedTimeFromTimeStamp(timeStamp,
      SigValIdentifiers.TIME_VERIFICATION_TYPE_SIG_TIMESTAMP);
    if (timeValidationClaims != null) {
      return new TimeValidationResult(timeValidationClaims, timeStamp.getCertificateValidationResult(), timeStamp);
    }
    return null;
  }

  private TimeValidationClaims getVerifiedTimeFromTimeStamp(final TimeStamp timeStamp, final String type) {
    try {
      TimeValidationClaims timeValidationClaims = TimeValidationClaims.builder()
        .id(timeStamp.getTstInfo().getSerialNumber().getValue().toString(16))
        .iss(timeStamp.getSigCert().getSubjectX500Principal().toString())
        .time(timeStamp.getTstInfo().getGenTime().getDate().getTime() / 1000)
        .type(type)
        .val(timeStamp.getPolicyValidationClaimsList())
        .build();
      return timeValidationClaims;
    }
    catch (Exception ex) {
      log.error("Error collecting time validation claims data: {}", ex.getMessage());
      return null;
    }
  }

  /**
   * Use the results obtained from SVT validation to produce general signature validation result as if the signature was validated using
   * complete validation.
   *
   * @param svtValResult  results from SVT validation
   * @param signature     the signature being validated
   * @param signatureData data collected about this signature
   * @return {@link ExtendedXmlSigvalResult} signature validation results
   */
  private ExtendedXmlSigvalResult compileXMLSigValResultsFromSvtValidation(SignatureSVTValidationResult svtValResult, Element signature,
    SignatureData signatureData) {

    ExtendedXmlSigvalResult xmlSvResult = new ExtendedXmlSigvalResult();
    xmlSvResult.setSignatureElement(signature);

    try {
      //XAdES data
      XAdESObjectParser xAdESObjectParser = new XAdESObjectParser(signature, signatureData);
      xmlSvResult.setSignedDocument(signatureData.getSignedDocument());
      xmlSvResult.setCoversDocument(signatureData.isCoversWholeDoc());
      xmlSvResult.setEtsiAdes(xAdESObjectParser.getQualifyingProperties() != null);
      xmlSvResult.setInvalidSignCert(!xAdESObjectParser.isXadesVerified(xmlSvResult.getSignerCertificate()));
      xmlSvResult.setClaimedSigningTime(xAdESObjectParser.getClaimedSigningTime());
      xmlSvResult.setSignedDocument(signatureData.getSignedDocument());

      //Get algorithms and public key type. Note that the source of these values is the SVA signature which is regarded as the algorithm
      //That is effectively protecting the integrity of the signature, superseding the use of the original algorithms.
      SignedJWT signedJWT = svtValResult.getSignedJWT();
      JWSAlgorithm svtJwsAlgo = signedJWT.getHeader().getAlgorithm();

      String algoUri = JWSAlgorithmRegistry.getUri(svtJwsAlgo);
      xmlSvResult.setSignatureAlgorithm(algoUri);
      PubKeyParams pkParams = GeneralCMSUtils.getPkParams(SVAUtils.getCertificate(svtValResult.getSignerCertificate()).getPublicKey());
      xmlSvResult.setPubKeyParams(pkParams);

      //Set signed SVT JWT
      xmlSvResult.setSvtJWT(signedJWT);

      /**
       * Set the signature certs as the result certs and set the validated certs as the validated path in cert validation results
       * The reason for this is that the SVT issuer must decide whether to just include a hash of the certs in the signature
       * or to include all explicit certs of the validated path. The certificates in the CertificateValidationResult represents the
       * validated path. If the validation was done by SVT, then the certificates obtained from SVT validation represents the validated path
       */
      // Get the signature certificates
      xmlSvResult.setSignerCertificate(signatureData.getSignerCertificate());
      xmlSvResult.setSignatureCertificateChain(signatureData.getSignatureCertChain());
      // Store the svt validated certificates as path of certificate validation results
      CertificateValidationResult cvr = new DefaultCertificateValidationResult(SVAUtils.getOrderedCertList(svtValResult.getSignerCertificate(), svtValResult.getCertificateChain()));
      xmlSvResult.setCertificateValidationResult(cvr);

      // Finalize
      SignatureClaims signatureClaims = svtValResult.getSignatureClaims();
      if (svtValResult.isSvtValidationSuccess()) {
        xmlSvResult.setStatus(SignatureValidationResult.Status.SUCCESS);
      }
      else {
        xmlSvResult.setStatus(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE);
        xmlSvResult.setStatusMessage("Unable to verify SVT signature");
      }
      xmlSvResult.setSignatureClaims(signatureClaims);
      xmlSvResult.setValidationPolicyResultList(signatureClaims.getSig_val());

      //Add SVT timestamp that was used to perform this SVT validation to verified times
      //This ensures that this time stamp gets added when SVT issuance is based on a previous SVT.
      JWTClaimsSet jwtClaimsSet = signedJWT.getJWTClaimsSet();
      List<TimeValidationClaims> timeValidationClaimsList = signatureClaims.getTime_val();
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
      xmlSvResult.setTimeValidationResults(timeValidationClaimsList.stream()
        .map(timeValidationClaims -> new TimeValidationResult(
          timeValidationClaims, null, null))
        .collect(Collectors.toList())
      );

    } catch (Exception ex) {
      xmlSvResult.setStatus(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE);
      xmlSvResult.setStatusMessage("Unable to process SVA token or signature data");
      return xmlSvResult;
    }
    return xmlSvResult;
  }

}
