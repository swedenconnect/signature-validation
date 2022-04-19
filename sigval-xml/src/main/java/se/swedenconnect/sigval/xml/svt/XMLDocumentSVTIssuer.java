/*
 * Copyright (c) 2020. Sweden Connect
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

package se.swedenconnect.sigval.xml.svt;

import com.nimbusds.jwt.SignedJWT;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import se.swedenconnect.sigval.commons.svt.SVTExtendpolicy;
import se.swedenconnect.sigval.svt.issuer.SVTModel;
import se.swedenconnect.sigval.xml.utils.XMLDocumentBuilder;
import se.swedenconnect.sigval.xml.utils.XMLSigUtils;
import se.swedenconnect.sigval.xml.xmlstruct.SignatureData;
import se.swedenconnect.sigval.xml.xmlstruct.XMLSigConstants;
import se.swedenconnect.sigval.xml.xmlstruct.XMLSignatureContext;
import se.swedenconnect.sigval.xml.xmlstruct.XMLSignatureContextFactory;
import se.swedenconnect.sigval.xml.xmlstruct.impl.DefaultXMLSignatureContextFactory;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Implements functions to issue SVT for signed XML documents and to extend the signatures of the XML document with SVT tokens
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XMLDocumentSVTIssuer implements XMLSigConstants {

  private final XMLSVTSigValClaimsIssuer svtClaimsIssuer;
  @Setter private XMLSignatureContextFactory signatureContextFactory;

  public XMLDocumentSVTIssuer(XMLSVTSigValClaimsIssuer svtClaimsIssuer) {
    this.svtClaimsIssuer = svtClaimsIssuer;
    this.signatureContextFactory = new DefaultXMLSignatureContextFactory();
  }

  /**
   * Issues Signature Validation Tokens to signatures of an XML document and extends the document signatures with the SVT tokens.
   * @param document The signed document to extend
   * @param svtModel model providing basic SVT parameters
   * @param svtMethod specifying the extension strategy as defined by options declared in {@link SVTExtendpolicy}
   * @return bytes of signed XML document extended with SVT
   * @throws Exception on critical errors that prevents the document from being extended as requested
   */
  public byte[] issueSvt(Document document, SVTModel svtModel, SVTExtendpolicy svtMethod) throws Exception {

    List<Element> signatures = XMLSigUtils.getSignatures(document);

    XMLSignatureContext signatureContext = signatureContextFactory.getSignatureContext(document);

    // Verify all signatures ...
    //
    List<SVTExtensionData> svtExtensionDataList = new ArrayList<>();
    for (Element signature : signatures) {
      SignedJWT signedSvtJWT = null;
      SignatureData signatureData = signatureContext.getSignatureData(signature);
      try {
        signedSvtJWT = svtClaimsIssuer.getSignedSvtJWT(
          XMLSigValInput.builder()
            .signatureData(signatureData)
            .signatureElement(signature)
            .svtMethod(svtMethod)
            .build(), svtModel
        );
        if (signedSvtJWT != null)
          svtExtensionDataList.add(new SVTExtensionData(signature, signedSvtJWT, signatureData, svtMethod));
      }
      catch (Exception ex) {
        log.error("Signature validation claims collection caused error: {}", ex.getMessage(), ex);
      }
    }
    return extendDocumentSignature(document, svtExtensionDataList);
  }

  /**
   * Extends the document signature with SVT token
   * @param document the XML document owning the signatures to extend
   * @param svtExtensionDataList
   * @return
   * @throws Exception
   */
  private byte[] extendDocumentSignature(Document document, List<SVTExtensionData> svtExtensionDataList) throws Exception{

    for (SVTExtensionData svtExtensionData:svtExtensionDataList){
      SignedJWT signedJWT = svtExtensionData.getSignedJWT();
      // Abort if we didn't get a new SVT
      if (signedJWT == null) continue;

      Element sigElement = svtExtensionData.getElement();
      SVTExtendpolicy svtMethod = svtExtensionData.getSvtMethod();
      List<Element> svtSignaturePropertyElements = getSvtSignaturePropertyElements(sigElement, new ArrayList<>());
      // Remove old SVT objects if method is set to replace (if we have a new SVT) or replace all.
      if (svtMethod.equals(SVTExtendpolicy.REPLACE) && signedJWT != null){
        svtSignaturePropertyElements.stream().forEach(element -> removeElement(element));
      }

      Element targetSignaturePropertiesElement = getTargetSignaturePropertiesElement(document, sigElement);
      Element signatureProperty = document.createElementNS(XMLDSIG_NS, "SignatureProperty");
      setElementPrefix(signatureProperty, sigElement);
      targetSignaturePropertiesElement.appendChild(signatureProperty);

      // If the signature element does not have an Id attribute, then create one.
      String sigId = sigElement.getAttribute("Id");
      if (StringUtils.isEmpty(sigId)){
        sigId = "id_" + new BigInteger(128, new SecureRandom()).toString(16);
        sigElement.setAttribute("Id", sigId);
      }
      signatureProperty.setAttribute("Target", "#" + sigId);

      Element signatureValidationToken = document.createElementNS(XML_SVT_NS, "SignatureValidationToken");
      signatureValidationToken.setPrefix("svt");
      signatureProperty.appendChild(signatureValidationToken);
      signatureValidationToken.setTextContent(signedJWT.serialize());
    }

    // Return resulting document with updated signature elements
    return XMLDocumentBuilder.getCanonicalDocBytes(document);
  }

  /**
   * Remove element and recursively removes any empty parent left after removal up until the signature element itself
   * @param elementToRemove element to remove
   */
  private void removeElement(Node elementToRemove) {
    Node parentNode = elementToRemove.getParentNode();
    parentNode.removeChild(elementToRemove);

    boolean emptyParentElement =
      parentNode instanceof Element
      && parentNode.getChildNodes().getLength() == 0
      && !parentNode.getLocalName().equalsIgnoreCase("Signature");

    if (emptyParentElement){
      removeElement(parentNode);
    }
  }

  private Element getTargetSignaturePropertiesElement(Document document, Element sigElement) {
    // Try to find an existing signature properties element
    List<Element> svtSigPropElementList = new ArrayList<>();
    List<Element> sigPropertiesNodeList = new ArrayList<>();
    NodeList signaturePropertiesNodes = sigElement.getElementsByTagNameNS(XMLDSIG_NS, "SignatureProperties");
    for (int i = 0; i<signaturePropertiesNodes.getLength() ; i++){
      if (signaturePropertiesNodes.item(i) instanceof Element){
        sigPropertiesNodeList.add((Element) signaturePropertiesNodes.item(i));
        getSvtSignaturePropertyElements((Element) signaturePropertiesNodes.item(i), svtSigPropElementList);
      }
    }
    if (!svtSigPropElementList.isEmpty()){
      Node parentNode = svtSigPropElementList.get(0).getParentNode();
      // If we have a SVT element, then use the sig properties parent node
      if (parentNode.getLocalName().equalsIgnoreCase("SignatureProperties")) return (Element) parentNode;
    }
    if (!sigPropertiesNodeList.isEmpty()){
      // There was no SVT node, but we have a sig properties node. Use that
      return sigPropertiesNodeList.get(0);
    }

    // There was no existing node. Create the new SVT XML SignatureProperties node
    Element svtObject = document.createElementNS(XMLDSIG_NS, "Object");
    setElementPrefix(svtObject, sigElement);
    sigElement.appendChild(svtObject);
    Element signatureProperties = document.createElementNS(XMLDSIG_NS, "SignatureProperties");
    setElementPrefix(signatureProperties, sigElement);
    svtObject.appendChild(signatureProperties);
    return signatureProperties;
  }

  private List<Element> getSvtSignaturePropertyElements(Element contextRoot, List<Element> svtSigPropElementList) {
    NodeList signaturePropertyNodes = contextRoot.getElementsByTagNameNS(XMLDSIG_NS, "SignatureProperty");
    for (int i = 0; i<signaturePropertyNodes.getLength() ; i++){
      if (signaturePropertyNodes.item(i) instanceof Element){
        Element sigPropElement = (Element) signaturePropertyNodes.item(i);
        int svtCount = sigPropElement.getElementsByTagNameNS(XML_SVT_NS, "SignatureValidationToken").getLength();
        if (svtCount > 0) svtSigPropElementList.add(sigPropElement);
      }
    }
    return svtSigPropElementList;
  }

  private void setElementPrefix(Element target, Element sigElement) {
    if (StringUtils.isEmpty(sigElement.getPrefix())) return;
    target.setPrefix(sigElement.getPrefix());
  }

  @Data
  @AllArgsConstructor
  private class SVTExtensionData {

    private Element element;
    private SignedJWT signedJWT;
    private SignatureData signatureData;
    private SVTExtendpolicy svtMethod;

  }

}
