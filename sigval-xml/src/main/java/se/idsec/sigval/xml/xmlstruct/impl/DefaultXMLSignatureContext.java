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

package se.idsec.sigval.xml.xmlstruct.impl;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;
import se.idsec.sigval.xml.utils.XMLDocumentBuilder;
import se.idsec.sigval.xml.xmlstruct.SignatureData;
import se.idsec.sigval.xml.xmlstruct.XMLSigConstants;
import se.idsec.sigval.xml.xmlstruct.XMLSignatureContext;

import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.util.*;

@Slf4j
public class DefaultXMLSignatureContext implements XMLSignatureContext, XMLSigConstants {

  private final static String[] idNames = new String[]{"iD", "id", "Id", "ID"};

  private final Document document;
  private final byte[] documentBytes;

  private final String rootNamespaceURI;
  private final String rootElementName;
  private final String rootIdAttrVal;

  public DefaultXMLSignatureContext(Document document) throws IOException {
    try {
      this.document = document;
      this.documentBytes = XMLDocumentBuilder.getCanonicalDocBytes(document);

      Element documentElement = document.getDocumentElement();
      this.rootNamespaceURI = documentElement.getNamespaceURI();
      this.rootElementName = documentElement.getLocalName();
      this.rootIdAttrVal = getIdAttrVal(document.getDocumentElement());
    } catch (Exception ex){
      throw new IOException(ex);
    }
  }

  private String getIdAttrVal(Element element) {
    String idAttrValCandidate = null;
    for (String idName : idNames){
      idAttrValCandidate = getIdAttrVal(idName, element, idAttrValCandidate);
    }
    return idAttrValCandidate;
  }

  private String getIdAttrVal(String idAttrName, Element element, String defaultVal) {
    String attributeVal = element.getAttribute(idAttrName);
    return StringUtils.isNotEmpty(attributeVal)
      ? attributeVal
      : defaultVal;
  }


  @Override public byte[] getDocumentBytes() throws IOException {
    return documentBytes;
  }

  @Override public byte[] getSignedDocument(Element signature) {

    try {
      SignatureData signatureData = getSignatureData(signature, false);
      Map<String, byte[]> refDataMap = signatureData.getRefDataMap();

      Optional<Document> documentOptional = signatureData.getRefDataMap().keySet().stream()
        .map(s -> refDataMap.get(s))
        .map(bytes -> {
          try {
            return XMLDocumentBuilder.getDocument(bytes);
          }
          catch (Exception e) {
            return null;
          }
        })
        .filter(parsedFrag -> parsedFrag != null)
        .filter(signedDoc -> isMatch(signedDoc, signature))
        .findFirst();

      if (documentOptional.isPresent()) return XMLDocumentBuilder.getCanonicalDocBytes(documentOptional.get());
    }
    catch (Exception e) {
      log.debug("Failed to parse and retrieve a matching document: {}", e.getMessage());
    }
    return null;
  }

  private boolean isMatch(Document signedDoc, Element signature) {
    try {
      SignatureData signatureData = getSignatureData(signature, false);
      Element signedDocDocumentElement = signedDoc.getDocumentElement();
      String nameSpaceUri = signedDocDocumentElement.getNamespaceURI();
      String localName = signedDocDocumentElement.getLocalName();
      Map<String, byte[]> refDataMap = signatureData.getRefDataMap();

      boolean nsMatch = false;
      if (rootNamespaceURI == null) {
        nsMatch = nameSpaceUri == null;
      } else {
        nsMatch = rootNamespaceURI.equals(nameSpaceUri);
      }

      boolean elmNameMatch = rootElementName.equals(localName);

      boolean idMatch = false;
      if (rootIdAttrVal == null || rootIdAttrVal.isEmpty()){
        idMatch = refDataMap.containsKey("");
      } else {
        idMatch = refDataMap.containsKey("#" + rootIdAttrVal);
      }

      return nsMatch && elmNameMatch && idMatch;

    }
    catch (IOException e) {
      log.debug("Signature match check cause exception - {}", e.getMessage());
    }
    return false;
  }

  @Override public boolean isCoversWholeDocument(Element signature) {
    try {
      SignatureData signatureData = getSignatureData(signature, false);
      Map<String, byte[]> refDataMap = signatureData.getRefDataMap();
      if (refDataMap.containsKey("")) return true;
      return refDataMap.containsKey("#" + rootIdAttrVal);
    }
    catch (IOException e) {
      log.debug("Error parsing data to determine if signature covers document: {}", e.getMessage());
    }
    return false;
  }

  @Override public SignatureData getSignatureData(Element sigNode, boolean registerIdAttr) throws IOException {
    SignatureData.SignatureDataBuilder builder = SignatureData.builder();

    try {
      XMLSignature signature = new XMLSignature(sigNode, "");
      SignedInfo signedInfo = signature.getSignedInfo();

      NodeList signatureRefs = signedInfo.getElement().getElementsByTagNameNS(XMLDSIG_NS, "Reference");
      Map<String, byte[]> referencedDataMap = new HashMap<>();
      for (int i = 0; i < signatureRefs.getLength(); i++){
        Element refElement = (Element)signatureRefs.item(i);
        String transform = getTransformAlgorithm(refElement);
        if (XMLDSIG_V2_TRANSFORM.equalsIgnoreCase(transform)) {
          throw new IOException("XMLDsig versioin 2.0 signatures not supported");
        }
        String uri = refElement.getAttribute("URI");
        if (StringUtils.isNotEmpty(uri.trim()) && registerIdAttr) registerId(uri);
        byte[] signedData = null;
        try {
          XMLSignatureInput xmlSignatureInput = signedInfo.getReferencedContentAfterTransformsItem(i);
          signedData = xmlSignatureInput.getBytes();
          int sdf = 0;
        } catch (Exception ignored){
          int sdf=0;
          //Its perfectly legal if we don't find a document behind every reference, as long as 1 reference match our signed document
        }
        referencedDataMap.put(uri, signedData);
      }
      builder.refDataMap(referencedDataMap);


      builder.signature(signature);


      if (registerIdAttr){
        referencedDataMap.keySet().stream()
          .filter(referenceUri -> StringUtils.isNotEmpty(referenceUri))
          .filter(referenceUri -> referenceUri.startsWith("#"))
          .forEach(referenceUri -> registerId(referenceUri));
      }

    } catch (Exception ex) {
      log.error("Error parsing ref URI from signature");
      throw new IOException("Error parsing ref URI from signature", ex);
    }

    return builder.build();
  }

/*
  private Element getElementInDocument(String uri, byte[] signedData) {
    // If the URI is the empty root element URI reference
    if (StringUtils.isEmpty(uri.trim())) return document.getDocumentElement();

    // URI points to an ID outside of the document we stop here and return null.
    if (!uri.startsWith("#")) return null;

    try {
      Element signedDataDocElement = XMLDocumentBuilder.getDocument(signedData).getDocumentElement();
      String idAttrVal = getIdAttrVal(signedDataDocElement);
      if (StringUtils.isEmpty(idAttrVal)) return null;
      String namespaceURI = signedDataDocElement.getNamespaceURI();
      String localName = signedDataDocElement.getLocalName();
      NodeList matchelements = document.getDocumentElement().getElementsByTagNameNS(namespaceURI, localName);
      for (int i = 0; i< matchelements.getLength(); i++){
        Node matchNode = matchelements.item(i);
        if (matchNode instanceof Element){
          Element matchElm = (Element) matchNode;
          String matchIdVal = getIdAttrVal(matchElm);
          if (uri.equals("#" + matchIdVal)){
            //registerIdInElement(matchElm, uri);
            return matchElm;
          }
        }
      }
    }
    catch (IOException | SAXException | ParserConfigurationException e) {
      e.printStackTrace();
    }
    return null;
  }
*/

  private void registerId(String referenceUri) {
    NodeList nodes = document.getDocumentElement().getElementsByTagName("*");
    List<Element> matchingElements = new ArrayList<>();
    for (int i = 0 ; i<nodes.getLength() ; i++){
      Node node = nodes.item(i);
      if (node instanceof Element){
        Element element = (Element) node;
        String idAttrVal = getIdAttrVal(element);
        if (StringUtils.isNotEmpty(idAttrVal) && referenceUri.equals("#" + idAttrVal)){
          matchingElements.add(element);
        }
      }
    }
    if (matchingElements.size() == 1){
      registerIdInElement(matchingElements.get(0), referenceUri);
    }
  }

  private void registerIdInElement(Element element, String referenceUri) {
    for (String idName : idNames){
      String signatureUriReference = element.getAttribute(idName);
      if (StringUtils.isNotEmpty(signatureUriReference) && ("#" + signatureUriReference).equals(referenceUri)) {
        element.setIdAttribute(idName, true);
      }
    }
  }

  private String getTransformAlgorithm(Element refElement) {
    NodeList transformNodes = refElement.getElementsByTagNameNS(XMLDSIG_NS, "Transform");
    if (transformNodes == null || transformNodes.getLength() < 1) return null;

    try {
      Element transformElement = (Element) transformNodes.item(0);
      String algorithm = transformElement.getAttribute("Algorithm");
      return StringUtils.isNotEmpty(algorithm)
        ? algorithm
        : null;
    } catch (Exception ex) {
      log.debug("Failed to obtain transform algorithm: {}", ex.getMessage());
    }
    return null;
  }

}
