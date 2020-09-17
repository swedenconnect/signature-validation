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
import se.idsec.sigval.xml.utils.XMLDocumentBuilder;
import se.idsec.sigval.xml.xmlstruct.SignatureData;
import se.idsec.sigval.xml.xmlstruct.XMLSigConstants;
import se.idsec.sigval.xml.xmlstruct.XMLSignatureContext;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

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
      Optional<Document> documentOptional = signatureData.getSignedXmlFragments().stream()
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
      List<String> sigIdRefList = signatureData.getRefURIList();

      boolean nsMatch = false;
      if (rootNamespaceURI == null) {
        nsMatch = nameSpaceUri == null;
      } else {
        nsMatch = rootNamespaceURI.equals(nameSpaceUri);
      }

      boolean elmNameMatch = rootElementName.equals(localName);

      boolean idMatch = false;
      if (rootIdAttrVal == null || rootIdAttrVal.isEmpty()){
        idMatch = sigIdRefList.contains("");
      } else {
        idMatch = sigIdRefList.contains("#" + rootIdAttrVal);
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
      List<String> sigIdRefList = signatureData.getRefURIList();
      if (sigIdRefList.contains("")) return true;
      return sigIdRefList.contains("#" + rootIdAttrVal);
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

      int refCount = signedInfo.getSignedContentLength();
      List<byte[]> signedXmlList = new ArrayList<>();

      for (int refIdx = 0; refIdx < refCount; refIdx++) {
        try {
          XMLSignatureInput xmlSignatureInput = signedInfo.getReferencedContentAfterTransformsItem(refIdx);
          signedXmlList.add(xmlSignatureInput.getBytes());
        } catch (Exception ignored){
          //Its perfectly legal if we don't find a document behind every reference, as long as 1 reference match our signed document
        }
      }
      builder.signedXmlFragments(signedXmlList);
      builder.signature(signature);

      NodeList signatureRefs = signedInfo.getElement().getElementsByTagNameNS(XMLDSIG_NS, "Reference");
      List<String> refUriList = new ArrayList<>();
      for (int i = 0; i < signatureRefs.getLength(); i++){
        Element refElement = (Element)signatureRefs.item(i);
        String transform = getTransformAlgorithm(refElement);
        if (XMLDSIG_V2_TRANSFORM.equalsIgnoreCase(transform)) {
          throw new IOException("XMLDsig versioin 2.0 signatures not supported");
        }
        String uri = refElement.getAttribute("URI");
        refUriList.add(uri);
      }
      builder.refURIList(refUriList);

      if (registerIdAttr){
        refUriList.stream()
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
