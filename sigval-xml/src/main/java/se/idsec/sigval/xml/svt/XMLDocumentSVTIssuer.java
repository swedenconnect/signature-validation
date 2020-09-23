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

package se.idsec.sigval.xml.svt;

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
import se.idsec.sigval.svt.issuer.SVTModel;
import se.idsec.sigval.xml.utils.XMLDocumentBuilder;
import se.idsec.sigval.xml.utils.XMLSigUtils;
import se.idsec.sigval.xml.xmlstruct.SignatureData;
import se.idsec.sigval.xml.xmlstruct.XMLSigConstants;
import se.idsec.sigval.xml.xmlstruct.XMLSignatureContext;
import se.idsec.sigval.xml.xmlstruct.XMLSignatureContextFactory;
import se.idsec.sigval.xml.xmlstruct.impl.DefaultXMLSignatureContextFactory;

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
   * @param svtMethod specifying the extension strategy as defined by options declared in {@link XMLDocumentSVTMethod}
   * @return bytes of signed XML document extended with SVT
   * @throws Exception on critical errors that prevents the document from being extended as requested
   */
  public byte[] issueSvt(Document document, SVTModel svtModel, XMLDocumentSVTMethod svtMethod) throws Exception {

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
      Element sigElement = svtExtensionData.getElement();
      XMLDocumentSVTMethod svtMethod = svtExtensionData.getSvtMethod();


      NodeList objectNodes = sigElement.getElementsByTagNameNS(XMLDSIG_NS, "Object");
      List<Element> svtObjects = getSvtObjects(objectNodes);
      // Remove old SVT objects if method is set to replace (if we have a new SVT) or replace all.
      if (svtMethod.equals(XMLDocumentSVTMethod.REPLACE) && signedJWT != null){
        svtObjects.stream().forEach(element -> sigElement.removeChild(element));
      }
      // No need to continue if we didn't get a new SVT
      if (signedJWT == null) continue;

      // Create the new SVT XML Signature Object
      Element svtObject = document.createElementNS(XMLDSIG_NS, "Object");
      setElementPrefix(svtObject, sigElement);
      sigElement.appendChild(svtObject);
      Element signatureProperties = document.createElementNS(XMLDSIG_NS, "SignatureProperties");
      setElementPrefix(signatureProperties, sigElement);
      svtObject.appendChild(signatureProperties);
      Element signatureProperty = document.createElementNS(XMLDSIG_NS, "SignatureProperty");
      setElementPrefix(signatureProperty, sigElement);
      signatureProperties.appendChild(signatureProperty);

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

  private void setElementPrefix(Element target, Element sigElement) {
    if (StringUtils.isEmpty(sigElement.getPrefix())) return;
    target.setPrefix(sigElement.getPrefix());
  }

  private List<Element> getSvtObjects(NodeList objectNodes) {
    List<Element> elementList = new ArrayList<>();
    if (objectNodes == null) return elementList;
    for (int i = 0 ; i< objectNodes.getLength(); i++){
      Node node = objectNodes.item(i);
      if (node instanceof Element){
        Element objElement = (Element) node;
        NodeList svtNodes = objElement.getElementsByTagNameNS(XML_SVT_NS, "SignatureValidationToken");
        if (svtNodes != null && svtNodes.getLength() > 0){
          elementList.add(objElement);
        }
      }
    }
    return elementList;
  }

  @Data
  @AllArgsConstructor
  private class SVTExtensionData {

    private Element element;
    private SignedJWT signedJWT;
    private SignatureData signatureData;
    private XMLDocumentSVTMethod svtMethod;

  }

}
