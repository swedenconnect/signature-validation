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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.idsec.signservice.security.sign.SignatureValidationResult;
import se.idsec.signservice.security.sign.xml.XMLSignatureLocation;
import se.idsec.signservice.security.sign.xml.impl.DefaultXMLSigner;
import se.idsec.sigval.commons.data.SignedDocumentValidationResult;
import se.idsec.sigval.svt.validation.SignatureSVTValidationResult;
import se.idsec.sigval.xml.data.ExtendedXmlSigvalResult;
import se.idsec.sigval.xml.svt.XMLSVTValidator;
import se.idsec.sigval.xml.utils.XMLDocumentBuilder;
import se.idsec.sigval.xml.utils.XMLSVAUtils;
import se.idsec.sigval.xml.verify.ExtendedXMLSignedDocumentValidator;
import se.idsec.sigval.xml.verify.XMLSignatureElementValidator;

import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Slf4j
public class XMLSignedDocumentValidator implements ExtendedXMLSignedDocumentValidator {

  /** XAdES namespace URI. */
  private static final String XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

  /** Validator for individual signatures */
  private final XMLSignatureElementValidator signatureElementValidator;

  private final XMLSVTValidator xmlsvtValidator;

  /** Flag that tells if the validator should handle XAdES signatures. */
  protected boolean xadesProcessing = true;

  /**
   * Constructor setting up the validator.
   */
  public XMLSignedDocumentValidator(XMLSignatureElementValidator signatureElementValidator,
    XMLSVTValidator xmlsvtValidator) {
    this.signatureElementValidator = signatureElementValidator;
    this.xmlsvtValidator = xmlsvtValidator;
  }

  /**
   * Constructor setting up the validator without SVT validation.
   */
  public XMLSignedDocumentValidator(XMLSignatureElementValidator signatureElementValidator) {
    this.signatureElementValidator = signatureElementValidator;
    this.xmlsvtValidator = null;
  }

  @Override public SignedDocumentValidationResult<ExtendedXmlSigvalResult> extendedResultValidation(byte[] documentBytes)
    throws SignatureException {
    // TODO
    return null;
  }

  @Override public List<SignatureValidationResult> validate(Document document) throws SignatureException {
    // First locate all signature elements ...
    //
    NodeList signatureElements = document.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
    if (signatureElements.getLength() == 0) {
      log.debug("No signatures found");
      // We return an empty list of signature results as it is not considered an exception to validate an unsigned document
      return new ArrayList<>();
    }
    List<Element> signatures = new ArrayList<>();
    for (int i = 0; i < signatureElements.getLength(); i++) {
      signatures.add((Element) signatureElements.item(i));
    }
    try {
      return this.validate(document, signatures);
    }
    catch (Exception e) {
      log.error("Error validating XML signatures: {}", e.getMessage());
      throw new SignatureException(e.getMessage(), e);
    }
  }

  @Override public List<SignatureValidationResult> validate(Document document, XMLSignatureLocation signatureLocation)
    throws SignatureException {
    if (signatureLocation == null) {
      return this.validate(document);
    }
    try {
      final Element signature = signatureLocation.getSignature(document);
      if (signature == null) {
        // We return exception in this case since a specific signature location was requested, but not found.
        throw new SignatureException("Could not find Signature element");
      }
      return this.validate(document, Collections.singletonList(signature));
    }
    catch (Exception e) {
      log.error("Error validating XML signatures: {}", e.getMessage());
      throw new SignatureException(e.getMessage(), e);
    }
  }

  /**
   * Validates the supplied signatures.
   *
   * @param document   the document containing the signatures
   * @param signatures the signatures
   * @return a list of result objects
   */
  protected List<SignatureValidationResult> validate(final Document document, final List<Element> signatures) throws Exception{

    try {
      byte[] docBytes = XMLDocumentBuilder.getCanonicalDocBytes(document);
      // Get the document ID attribute (and register the ID attributes).
      //
      final String signatureUriReference = DefaultXMLSigner.registerIdAttributes(document);

      // Register ID nodes for XAdES ...
      //
      if (this.xadesProcessing) {
        this.registerXadesIdNodes(document);
      }

      // Attempt SVT validation first
      List<SignatureSVTValidationResult> svtValidationResultList = xmlsvtValidator == null ? null : xmlsvtValidator.validate(docBytes);
      // Verify all signatures ...
      //
      List<SignatureValidationResult> results = new ArrayList<>();
      for (Element signature : signatures) {
        SignatureSVTValidationResult svtValResult = XMLSVAUtils.getMatchingSvtValidation(signature, docBytes, svtValidationResultList);
        if (svtValResult == null) {
          results.add(signatureElementValidator.validateSignature(signature, signatureUriReference));
        } else {
          results.add(compileXMLSigValResultsFromSvtValidation(svtValResult, signature, docBytes));
        }
      }

      return results;
    }
    catch (Exception e) {
      throw e;
    }
  }

  /** {@inheritDoc} */
  @Override
  public boolean isSigned(final Document document) throws IllegalArgumentException {
    try {
      NodeList signatureElements = document.getElementsByTagNameNS(javax.xml.crypto.dsig.XMLSignature.XMLNS, "Signature");
      return signatureElements.getLength() > 0;
    }
    catch (Exception e) {
      throw new IllegalArgumentException("Invalid document", e);
    }
  }

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getRequiredSignerCertificates() {
    return new ArrayList<>();
  }

  /** {@inheritDoc} */
  @Override
  public CertificateValidator getCertificateValidator() {
    return this.signatureElementValidator.getCertificateValidator();
  }

  /**
   * Sets flag that tells whether this validator should handle XAdES processing. The default is {@code true}
   *
   * @param xadesProcessing whether to process XAdES
   */
  public void setXadesProcessing(boolean xadesProcessing) {
    this.xadesProcessing = xadesProcessing;
  }

  /**
   * Looks for any {@code xades:SignedProperties} elements and registers an Id attribute for the elements that are
   * found.
   *
   * @param document the document to manipulate
   */
  protected void registerXadesIdNodes(Document document) {
    final NodeList xadesSignedProperties = document.getElementsByTagNameNS(XADES_NAMESPACE, "SignedProperties");
    for (int i = 0; i < xadesSignedProperties.getLength(); i++) {
      final Element sp = (Element) xadesSignedProperties.item(i);
      sp.setIdAttribute("Id", true);
    }
  }

  private SignatureValidationResult compileXMLSigValResultsFromSvtValidation(SignatureSVTValidationResult svtValResult, Element signature, byte[] docBytes) {
    //TODO
    return null;
  }

}
