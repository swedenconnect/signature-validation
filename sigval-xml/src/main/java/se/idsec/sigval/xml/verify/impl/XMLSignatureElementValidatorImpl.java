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

import lombok.extern.slf4j.Slf4j;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.idsec.signservice.security.certificate.CertificateValidationResult;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.idsec.sigval.commons.data.PolicyValidationResult;
import se.idsec.sigval.commons.timestamp.TimeStampPolicyVerifier;
import se.idsec.sigval.svt.claims.PolicyValidationClaims;
import se.idsec.sigval.svt.claims.ValidationConclusion;
import se.idsec.sigval.xml.data.ExtendedXmlSigvalResult;
import se.idsec.sigval.xml.policy.XMLSignaturePolicyValidator;
import se.idsec.sigval.xml.verify.XMLSignatureElementValidator;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

@Slf4j
public class XMLSignatureElementValidatorImpl implements XMLSignatureElementValidator {

  /** Optional certificate validator. */
  private final CertificateValidator certificateValidator;

  private final TimeStampPolicyVerifier timeStampPolicyVerifier;

  private final XMLSignaturePolicyValidator signaturePolicyValidator;

  /** Flag that tells if the validator should handle XAdES signatures. */
  protected boolean xadesProcessing = true;

  /**
   * Constructor setting up the validator.
   */
  public XMLSignatureElementValidatorImpl(
    CertificateValidator certificateValidator, XMLSignaturePolicyValidator signaturePolicyValidator,
    TimeStampPolicyVerifier timeStampPolicyVerifier) {
    this.certificateValidator = certificateValidator;
    this.signaturePolicyValidator = signaturePolicyValidator;
    this.timeStampPolicyVerifier = timeStampPolicyVerifier;
  }


  /**
   * Validates the signature value and checks that the signer certificate is accepted.
   *
   * @param signature             the signature element
   * @param signatureUriReference the signature URI reference
   * @return a validation result
   */
  @Override
  public ExtendedXmlSigvalResult validateSignature(final Element signature, final String signatureUriReference) {
    ExtendedXmlSigvalResult result = validateSignatureElement(signature, signatureUriReference);

    // If we have a cert path validator installed, perform path validation...
    //
    if (result.isSuccess() && this.certificateValidator != null) {
      try {
        CertificateValidationResult validatorResult = this.certificateValidator.validate(result.getSignerCertificate(),
          result.getSignatureCertificateChain(), null);
        result.setCertificateValidationResult(validatorResult);
      }
      catch (Exception ex) {
        if (ex instanceof ExtendedCertPathValidatorException) {
          ExtendedCertPathValidatorException extEx = (ExtendedCertPathValidatorException) ex;
          result.setCertificateValidationResult(extEx.getPathValidationResult());
          result.setError(SignatureValidationResult.Status.ERROR_SIGNER_INVALID, extEx.getMessage(), ex);
        } else {
          if (ex instanceof CertPathBuilderException){
            final String msg = String.format("Failed to build a path to a trusted root for signer certificate - %s", ex.getMessage());
            log.error("{}", ex.getMessage());
            result.setError(SignatureValidationResult.Status.ERROR_NOT_TRUSTED, msg, ex);
          }
          if (ex instanceof GeneralSecurityException) {
            final String msg = String.format("Certificate path validation failure for signer certificate - %s", ex.getMessage());
            log.error("{}", ex.getMessage(), ex);
            result.setError(SignatureValidationResult.Status.ERROR_SIGNER_INVALID, msg, ex);
          }
        }
      }
    }

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

    return result;
  }

  @Override public CertificateValidator getCertificateValidator() {
    return certificateValidator;
  }

  /**
   * Validates the signature value and checks that the signer certificate is accepted.
   *
   * @param signature             the signature element
   * @param signatureUriReference the signature URI reference
   * @return a validation result
   */
  public ExtendedXmlSigvalResult validateSignatureElement(final Element signature, final String signatureUriReference) {

    ExtendedXmlSigvalResult result = new ExtendedXmlSigvalResult();
    result.setSignatureElement(signature);

    try {
      // Parse the signature element.
      XMLSignature xmlSignature = new XMLSignature(signature, "");

      // Make sure the signature covers the entire document.
      //
      final List<String> uris = this.getSignedInfoReferenceURIs(xmlSignature.getSignedInfo().getElement());
      if (!uris.contains(signatureUriReference)) {
        final String msg = String.format("The Signature contained the reference(s) %s - none of these covers the entire document", uris);
        log.error(msg);
        result.setError(SignatureValidationResult.Status.ERROR_BAD_FORMAT, msg);
        return result;
      }

      // Locate the certificate that was used to sign ...
      //
      PublicKey validationKey = null;

      if (xmlSignature.getKeyInfo() != null) {
        final X509Certificate validationCertificate = xmlSignature.getKeyInfo().getX509Certificate();
        if (validationCertificate != null) {
          result.setSignerCertificate(validationCertificate);

          // Get hold of any other certs (intermediate and roots)
          result.setSignatureCertificateChain(this.getAllSignatureCertifictes(xmlSignature.getKeyInfo()));

          validationKey = validationCertificate.getPublicKey();
        }
        else {
          log.info("No certificate found in signature's KeyInfo ...");
          validationKey = xmlSignature.getKeyInfo().getPublicKey();
        }
      }
      else {
        log.warn("No KeyInfo element found in Signature ...");
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
        if (!xmlSignature.checkSignatureValue(validationKey)) {
          final String msg = "Signature is invalid - signature value did not validate correctly or reference digest comparison failed";
          log.info("{}", msg);
          result.setError(SignatureValidationResult.Status.ERROR_INVALID_SIGNATURE, msg);
          return result;
        }
      }
      catch (XMLSignatureException e) {
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
    catch (XMLSecurityException | SignatureException e) {
      result.setError(SignatureValidationResult.Status.ERROR_BAD_FORMAT, e.getMessage(), e);
      return result;
    }
  }

  /**
   * Extracts all certificates from the supplied KeyInfo.
   *
   * @param keyInfo           the KeyInfo
   * @return a list of certificates
   */
  protected List<X509Certificate> getAllSignatureCertifictes(final KeyInfo keyInfo) {
    List<X509Certificate> additional = new ArrayList<>();
    for (int i = 0; i < keyInfo.lengthX509Data(); i++) {
      try {
        final X509Data x509data = keyInfo.itemX509Data(i);
        if (x509data == null) {
          continue;
        }
        for (int j = 0; j < x509data.lengthCertificate(); j++) {
          final XMLX509Certificate xmlCert = x509data.itemCertificate(j);
          if (xmlCert != null) {
            final X509Certificate cert = CertificateUtils.decodeCertificate(xmlCert.getCertificateBytes());
            additional.add(cert);
          }
        }
      }
      catch (XMLSecurityException | CertificateException e) {
        log.error("Failed to extract X509Certificate from KeyInfo", e);
        continue;
      }
    }
    return additional;
  }


  /**
   * Utility method for getting hold of the reference URI:s of a {@code SignedInfo} element.
   *
   * @param signedInfo the signed info element
   * @return a list of one or more reference URI:s
   * @throws SignatureException for unmarshalling errors
   */
  private List<String> getSignedInfoReferenceURIs(final Element signedInfo) throws SignatureException {
    final NodeList references = signedInfo.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Reference");
    if (references.getLength() == 0) {
      throw new SignatureException("No Reference element found in SignedInfo of signature");
    }
    List<String> uris = new ArrayList<>();
    for (int i = 0; i < references.getLength(); i++) {
      final Element reference = (Element) references.item(i);
      uris.add(reference.getAttribute("URI"));
    }
    return uris;
  }
}
