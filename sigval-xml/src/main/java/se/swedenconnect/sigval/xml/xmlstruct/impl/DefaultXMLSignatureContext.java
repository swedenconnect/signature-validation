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

package se.swedenconnect.sigval.xml.xmlstruct.impl;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.signature.SignedInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import se.idsec.signservice.security.certificate.CertificateUtils;
import se.swedenconnect.sigval.xml.utils.XMLDocumentBuilder;
import se.swedenconnect.sigval.xml.xmlstruct.SignatureData;
import se.swedenconnect.sigval.xml.xmlstruct.XMLSigConstants;
import se.swedenconnect.sigval.xml.xmlstruct.XMLSignatureContext;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Provides signature context data related to XML document signatures.
 * This class is instantiated for a specific XML document and a new instance must be created for each processed XML document.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class DefaultXMLSignatureContext implements XMLSignatureContext, XMLSigConstants {

  private final static String[] idNames = new String[] { "iD", "id", "Id", "ID" };

  @Getter private final Document document;
  @Getter private final byte[] documentBytes;

  private final String rootNamespaceURI;
  private final String rootElementName;
  private final String rootIdAttrVal;

  /**
   * Constructor
   *
   * @param document the XML document from which signature context data is collected
   * @throws IOException on errors parsing data
   */
  public DefaultXMLSignatureContext(Document document) throws IOException {
    try {
      this.document = document;
      this.documentBytes = XMLDocumentBuilder.getCanonicalDocBytes(document);

      Element documentElement = document.getDocumentElement();
      this.rootNamespaceURI = documentElement.getNamespaceURI();
      this.rootElementName = documentElement.getLocalName();
      this.rootIdAttrVal = getIdAttrVal(document.getDocumentElement());
    }
    catch (Exception ex) {
      throw new IOException(ex);
    }
  }

  private String getIdAttrVal(Element element) {
    String idAttrValCandidate = null;
    for (String idName : idNames) {
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

  private byte[] getSignedDocument(Map<String, byte[]> refDataMap) {

    try {
      //SignatureData signatureData = getSignatureData(signature, false);

      Optional<Document> documentOptional = refDataMap.keySet().stream()
        .map(refDataMap::get)
        .map(bytes -> {
          try {
            return XMLDocumentBuilder.getDocument(bytes);
          }
          catch (Exception e) {
            return null;
          }
        })
        .filter(Objects::nonNull)
        .filter(parsedFrag -> isFragmentMatchingRootElement(parsedFrag, refDataMap))
        .findFirst();

      if (documentOptional.isPresent())
        return XMLDocumentBuilder.getCanonicalDocBytes(documentOptional.get());
    }
    catch (Exception e) {
      log.debug("Failed to parse and retrieve a matching document: {}", e.getMessage());
    }
    return null;
  }

  private boolean isFragmentMatchingRootElement(Document parsedFragment, Map<String, byte[]> refDataMap) {
    try {
      Element signedDocDocumentElement = parsedFragment.getDocumentElement();
      String nameSpaceUri = signedDocDocumentElement.getNamespaceURI();
      String localName = signedDocDocumentElement.getLocalName();

      boolean nsMatch;
      if (rootNamespaceURI == null) {
        nsMatch = nameSpaceUri == null;
      }
      else {
        nsMatch = rootNamespaceURI.equals(nameSpaceUri);
      }

      boolean elmNameMatch = rootElementName.equals(localName);

      boolean idMatch;
      if (rootIdAttrVal == null || rootIdAttrVal.isEmpty()) {
        idMatch = refDataMap.containsKey("");
      }
      else {
        idMatch = refDataMap.containsKey("#" + rootIdAttrVal);
      }

      // Finally conclude if this fragment match the document root
      return nsMatch && elmNameMatch && idMatch;

    }
    catch (Exception e) {
      log.debug("Signature match check cause exception - {}", e.getMessage());
    }
    return false;
  }

  private boolean isCoversWholeDocument(Map<String, byte[]> refDataMap) {
    if (refDataMap.containsKey(""))
      return true;
    return refDataMap.containsKey("#" + rootIdAttrVal);
  }

  /** {@inheritDoc} */
  @Override public SignatureData getSignatureData(Element sigNode) throws IOException {
    SignatureData.SignatureDataBuilder builder = SignatureData.builder();

    try {
      XMLSignature signature = new XMLSignature(sigNode, "");
      SignedInfo signedInfo = signature.getSignedInfo();

      NodeList signatureRefs = signedInfo.getElement().getElementsByTagNameNS(XMLDSIG_NS, "Reference");
      Map<String, byte[]> referencedDataMap = new HashMap<>();
      for (int i = 0; i < signatureRefs.getLength(); i++) {
        Element refElement = (Element) signatureRefs.item(i);
        String transform = getTransformAlgorithm(refElement);
        if (XMLDSIG_V2_TRANSFORM.equalsIgnoreCase(transform)) {
          throw new IOException("XMLDsig version 2.0 signatures not supported");
        }
        String uri = refElement.getAttribute("URI");
        // Make sure id attributes are registered
        if (StringUtils.isNotEmpty(uri.trim()))
          registerId(uri);
        byte[] signedData = null;
        try {
          XMLSignatureInput xmlSignatureInput = signedInfo.getReferencedContentAfterTransformsItem(i);
          signedData = xmlSignatureInput.getBytes();
        }
        catch (Exception ignored) {
          //Its perfectly legal if we don't find a document behind every reference, as long as 1 reference match our signed document
        }
        referencedDataMap.put(uri, signedData);
      }
      builder.refDataMap(referencedDataMap)
        .signature(signature)
        .coversWholeDoc(isCoversWholeDocument(referencedDataMap))
        .signedDocument(getSignedDocument(referencedDataMap))
        .signatureBytes(signature.getSignatureValue())
        .signedInfoBytes(signature.getSignedInfo().getCanonicalizedOctetStream());

      // Get certs
      KeyInfo keyInfo = signature.getKeyInfo();
      if (keyInfo != null){
        builder.signerCertificate(keyInfo.getX509Certificate())
          .signatureCertChain(getAllSignatureCertificates(keyInfo));
      }
    }
    catch (Exception ex) {
      log.error("Error parsing ref URI from signature");
      throw new IOException("Error parsing ref URI from signature", ex);
    }

    return builder.build();
  }

  private void registerId(String referenceUri) {
    NodeList nodes = document.getDocumentElement().getElementsByTagName("*");
    List<Element> matchingElements = new ArrayList<>();
    List<Element> candidateElements = new ArrayList<>();
    candidateElements.add(document.getDocumentElement());
    for (int i = 0; i < nodes.getLength(); i++) {
      Node node = nodes.item(i);
      if (node instanceof Element) {
        candidateElements.add((Element) node);
      }
    }
    for (Element element: candidateElements){
      String idAttrVal = getIdAttrVal(element);
      if (StringUtils.isNotEmpty(idAttrVal) && referenceUri.equals("#" + idAttrVal)) {
        matchingElements.add(element);
      }
    }
    if (matchingElements.size() == 1) {
      registerIdInElement(matchingElements.get(0), referenceUri);
    }
  }

  private void registerIdInElement(Element element, String referenceUri) {
    for (String idName : idNames) {
      String signatureUriReference = element.getAttribute(idName);
      if (StringUtils.isNotEmpty(signatureUriReference) && ("#" + signatureUriReference).equals(referenceUri)) {
        element.setIdAttribute(idName, true);
      }
    }
  }

  private String getTransformAlgorithm(Element refElement) {
    NodeList transformNodes = refElement.getElementsByTagNameNS(XMLDSIG_NS, "Transform");
    if (transformNodes == null || transformNodes.getLength() < 1)
      return null;

    try {
      Element transformElement = (Element) transformNodes.item(0);
      String algorithm = transformElement.getAttribute("Algorithm");
      return StringUtils.isNotEmpty(algorithm)
        ? algorithm
        : null;
    }
    catch (Exception ex) {
      log.debug("Failed to obtain transform algorithm: {}", ex.getMessage());
    }
    return null;
  }

  /**
   * Extracts all certificates from the supplied KeyInfo.
   *
   * @param keyInfo the KeyInfo
   * @return a list of certificates
   */
  protected List<X509Certificate> getAllSignatureCertificates(final KeyInfo keyInfo) {
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
      }
    }
    return additional;
  }

}
