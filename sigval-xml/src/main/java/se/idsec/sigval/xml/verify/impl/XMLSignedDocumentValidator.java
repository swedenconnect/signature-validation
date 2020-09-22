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

import lombok.Setter;
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
import se.idsec.sigval.xml.svt.XMLSigValInput;
import se.idsec.sigval.xml.utils.XMLDocumentBuilder;
import se.idsec.sigval.xml.utils.XMLSVAUtils;
import se.idsec.sigval.xml.utils.XMLSigUtils;
import se.idsec.sigval.xml.verify.ExtendedXMLSignedDocumentValidator;
import se.idsec.sigval.xml.verify.XMLSignatureElementValidator;
import se.idsec.sigval.xml.xmlstruct.SignatureData;
import se.idsec.sigval.xml.xmlstruct.XAdESObjectParser;
import se.idsec.sigval.xml.xmlstruct.XMLSignatureContext;
import se.idsec.sigval.xml.xmlstruct.XMLSignatureContextFactory;
import se.idsec.sigval.xml.xmlstruct.impl.DefaultXMLSignatureContextFactory;

import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class XMLSignedDocumentValidator implements ExtendedXMLSignedDocumentValidator {

  /** XAdES namespace URI. */
  private static final String XADES_NAMESPACE = "http://uri.etsi.org/01903/v1.3.2#";

  /** Validator for individual signatures */
  private final XMLSignatureElementValidator signatureElementValidator;

  /** An optional validator capable of validating signatures based on provided SVT tokens */
  private final XMLSVTValidator xmlsvtValidator;

  /**
   * Factory for getting an implementation of the signature context provider providing info about the signed document
   *
   * @param signatureContextFactory signature context factory
   */
  @Setter private XMLSignatureContextFactory signatureContextFactory;

  /**
   * Constructor setting up the validator.
   */
  public XMLSignedDocumentValidator(XMLSignatureElementValidator signatureElementValidator,
    XMLSVTValidator xmlsvtValidator) {
    this.signatureElementValidator = signatureElementValidator;
    this.xmlsvtValidator = xmlsvtValidator;
    this.signatureContextFactory = new DefaultXMLSignatureContextFactory();
  }

  /**
   * Constructor setting up the validator without SVT validation.
   */
  public XMLSignedDocumentValidator(XMLSignatureElementValidator signatureElementValidator) {
    this.signatureElementValidator = signatureElementValidator;
    this.xmlsvtValidator = null;
    this.signatureContextFactory = new DefaultXMLSignatureContextFactory();
  }

  @Override public SignedDocumentValidationResult<ExtendedXmlSigvalResult> extendedResultValidation(Document document)
    throws SignatureException {
    return getConcludingSigVerifyResult(validate(document));
  }

  @Override public List<SignatureValidationResult> validate(Document document) throws SignatureException {
    // First locate all signature elements ...
    //
    List<Element> signatures = XMLSigUtils.getSignatures(document);
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
  protected List<SignatureValidationResult> validate(final Document document, final List<Element> signatures) throws Exception {

    try {
      XMLSignatureContext signatureContext = signatureContextFactory.getSignatureContext(document);

      // Verify all signatures ...
      List<SignatureValidationResult> results = new ArrayList<>();
      for (Element signature : signatures) {
        SignatureData signatureData = signatureContext.getSignatureData(signature);

        // Attempt SVT validation first
        XMLSigValInput sigValInput = XMLSigValInput.builder()
          .signatureElement(signature)
          .signatureData(signatureData)
          .build();
        List<SignatureSVTValidationResult> svtValidationResultList = xmlsvtValidator == null ? null : xmlsvtValidator.validate(sigValInput);
        SignatureSVTValidationResult svtValResult = svtValidationResultList == null || svtValidationResultList.isEmpty() ? null : svtValidationResultList.get(0);

        if (svtValResult == null) {
          // We have no successful SVT validation. Perform standard validation
          results.add(signatureElementValidator.validateSignature(signature, signatureData));
        }
        else {
          // We have successful SVT validation. Get the SVT results
          results.add(compileXMLSigValResultsFromSvtValidation(svtValResult, signature, signatureData));
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

  private SignatureValidationResult compileXMLSigValResultsFromSvtValidation(SignatureSVTValidationResult svtValResult, Element signature,
    SignatureData signatureData) {
    //TODO
    return null;
  }

  /**
   * Compile a complete XML signature verification result object from the list of individual signature results
   *
   * @param sigVerifyResultList list of individual signature validation results. Each result must be of type {@link ExtendedXmlSigvalResult}
   * @return PDF signature validation result objects
   */
  public static SignedDocumentValidationResult<ExtendedXmlSigvalResult> getConcludingSigVerifyResult(
    List<SignatureValidationResult> sigVerifyResultList) {
    SignedDocumentValidationResult<ExtendedXmlSigvalResult> sigVerifyResult = new SignedDocumentValidationResult<>();
    List<ExtendedXmlSigvalResult> extendedPdfSigValResults = new ArrayList<>();
    try {
      extendedPdfSigValResults = sigVerifyResultList.stream()
        .map(signatureValidationResult -> (ExtendedXmlSigvalResult) signatureValidationResult)
        .collect(Collectors.toList());
      sigVerifyResult.setSignatureValidationResults(extendedPdfSigValResults);
    }
    catch (Exception ex) {
      throw new IllegalArgumentException("Provided results are not instances of ExtendedXmlSigvalResult");
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
    List<ExtendedXmlSigvalResult> validSignatureResultList = extendedPdfSigValResults.stream()
      .filter(cmsSigVerifyResult -> cmsSigVerifyResult.isSuccess())
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
      .filter(signatureValidationResult -> signatureValidationResult.isCoversDocument())
      .findFirst().isPresent();

    sigVerifyResult.setValidSignatureSignsWholeDocument(validSigSignsWholeDoc);

    return sigVerifyResult;
  }

}
