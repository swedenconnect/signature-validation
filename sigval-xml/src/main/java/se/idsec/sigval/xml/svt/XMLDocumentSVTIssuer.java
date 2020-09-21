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
import org.apache.xml.security.signature.XMLSignature;
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

@Slf4j
public class XMLDocumentSVTIssuer implements XMLSigConstants {

  private final XMLSVTSigValClaimsIssuer svtClaimsIssuer;
  @Setter private XMLSignatureContextFactory signatureContextFactory;

  public XMLDocumentSVTIssuer(XMLSVTSigValClaimsIssuer svtClaimsIssuer) {
    this.svtClaimsIssuer = svtClaimsIssuer;
    this.signatureContextFactory = new DefaultXMLSignatureContextFactory();
  }

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

  private byte[] extendDocumentSignature(Document document, List<SVTExtensionData> svtExtensionDataList) throws Exception{

    for (SVTExtensionData svtExtensionData:svtExtensionDataList){
      SignedJWT signedJWT = svtExtensionData.getSignedJWT();
      if (signedJWT == null) continue;
      Element sigElement = svtExtensionData.getElement();
      XMLSignature signature = svtExtensionData.getSignatureData().getSignature();
      XMLDocumentSVTMethod svtMethod = svtExtensionData.getSvtMethod();

      NodeList objectNodes = sigElement.getElementsByTagNameNS(XMLDSIG_NS, "Object");
      List<Element> svtObjects = getSvtObjects(objectNodes);
      // Remove old SVT objects if method is set to replace
      if (svtMethod.equals(XMLDocumentSVTMethod.REPLACE) || svtMethod.equals(XMLDocumentSVTMethod.REPLACE_ALL)){
        svtObjects.stream().forEach(element -> sigElement.removeChild(element));
      }

      Element svtObject = document.createElementNS(XMLDSIG_NS, "Object");
      svtObject.setPrefix("ds");
      sigElement.appendChild(svtObject);
      Element signatureProperties = document.createElementNS(XMLDSIG_NS, "SignatureProperties");
      signatureProperties.setPrefix("ds");
      svtObject.appendChild(signatureProperties);
      Element signatureProperty = document.createElementNS(XMLDSIG_NS, "SignatureProperty");
      signatureProperty.setPrefix("ds");
      signatureProperties.appendChild(signatureProperty);

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

    return XMLDocumentBuilder.getCanonicalDocBytes(document);
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
