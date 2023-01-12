/*
 * Copyright (c) 2023.  Sweden Connect
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

package se.swedenconnect.cert.extensions.utils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.cert.extensions.data.saci.AbstractDomData;
import se.swedenconnect.cert.extensions.data.saci.SAMLAttribute;

/**
 * XML DOM Utils
 */
@Slf4j
public class DOMUtils {

  public static final DateTimeFormatter XML_DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern(
    "yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ",
    Locale.ENGLISH).withZone(ZoneId.systemDefault());

  private static Transformer plainTransformer;
  @Getter private static Transformer transformer;
  @Getter private static DocumentBuilderFactory safeDocBuilderFactory;

  static {
    /**
     * This document builder factory is created in line with recommendations by OWASP
     * <p>https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#JAXP_DocumentBuilderFactory.2C_SAXParserFactory_and_DOM4J</p>
     * This Document builder disables the use of DTD and mitigates XEE attack threats
     */
    safeDocBuilderFactory = DocumentBuilderFactory.newInstance();
    safeDocBuilderFactory.setNamespaceAware(true);
    try {
      safeDocBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      safeDocBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
      safeDocBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      safeDocBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
      safeDocBuilderFactory.setXIncludeAware(false);
      safeDocBuilderFactory.setExpandEntityReferences(false);
    }
    catch (ParserConfigurationException e) {
      e.printStackTrace();
    }

    TransformerFactory tf = TransformerFactory.newInstance();
    try {
      plainTransformer = tf.newTransformer();
      transformer = tf.newTransformer();
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
      //transformer.setOutputProperty(OutputKeys.STANDALONE, "no");
      transformer.setOutputProperty(OutputKeys.METHOD, "xml");
      transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
      transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
      transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    }
    catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  public static Element getSingleElement(Element parent, String namespaceUri, String elementName) {
    List<Element> elementList = getElements(parent, namespaceUri, elementName);
    if (elementList.isEmpty()) {
      return null;
    }
    return elementList.get(0);
  }

  public static List<Element> getElements(Element parent, String namespaceUri, String elementName) {
    NodeList elements = parent.getElementsByTagNameNS(namespaceUri, elementName);
    List<Element> elementList = new ArrayList<>();
    for (int i = 0; i < elements.getLength(); i++) {
      Node node = elements.item(i);
      if (node instanceof Element) {
        elementList.add((Element) node);
      }
    }
    return elementList;
  }

  public static void setAttribute(Element element, String name, String value) {
    setAttribute(element, name, value,null);
  }

  public static void setAttribute(Element element, String name, String value, String namespaceUri) {
    if (value == null) {
      return;
    }
    if (namespaceUri == null) {
      element.setAttribute(name, value);
      return;
    }
    element.setAttributeNS(namespaceUri, name, value);
  }

  public static String getAttributeValue(Element element, String name) {
    return getAttributeValue(element, name, null);
  }

  public static String getAttributeValue(Element element, String name, String namespaceUri) {
    String val = namespaceUri == null
      ? element.getAttribute(name)
      : element.getAttributeNS(namespaceUri, name);

    return (val != null && val.length() > 0) ? val : null;
  }

  public static List<Attr> getOtherAttributes(Element element, List<String> excludeList) {

    List<Attr> attrList = new ArrayList<>();
    NamedNodeMap attributes = element.getAttributes();
    for (int i = 0; i < attributes.getLength(); i++) {
      Node item = attributes.item(i);
      if (item instanceof Attr) {
        Attr attrItem = (Attr) item;
        if (!excludeList.contains(attrItem.getName())) {
          attrList.add(attrItem);
        }
      }
    }
    return attrList;
  }


  public static void adoptElements(Element adoptingElement, Document document, List<Element> anyList) {
    if (anyList == null) {
      return;
    }
    anyList.forEach(element -> {
      document.adoptNode(element);
      adoptingElement.appendChild(element);
    });
  }

  public static void adoptAttributes(Element adoptingElement, Document document, List<Attr> anyAttrList) {
    if (anyAttrList == null) {
      return;
    }
    anyAttrList.forEach(attr -> {
      document.adoptNode(attr);
      adoptingElement.setAttributeNode(attr);
    });
  }

  public static String instantToString(Instant instant) {
    if (instant == null) {
      return null;
    }
    return XML_DATE_TIME_FORMATTER.format(instant);
  }

  public static Instant parseTime(String xmlTimeStr) {
    if (xmlTimeStr == null) {
      return null;
    }
    return LocalDateTime.parse(xmlTimeStr, XML_DATE_TIME_FORMATTER).toInstant(ZoneOffset.UTC);
  }

  /**
   * Generates a pretty XML print of an XML document based on java.xml
   * functions.
   *
   * @param doc The doc being processed
   * @return Test representation of the XML document
   */
  public static String getDocText(Document doc) throws TransformerException {
    Objects.requireNonNull(doc, "Document must not be null");
    DOMSource domSource = new DOMSource(doc);
    java.io.StringWriter sw = new java.io.StringWriter();
    StreamResult sr = new StreamResult(sw);
    transformer.transform(domSource, sr);
    String xml = sw.toString();
    return xml;
  }

  /**
   * Provides a canonical print of the XML document. The purpose of this print
   * is to try to preserve integrity of an existing signature.
   *
   * @param doc The XML document being processed.
   * @return XML String
   */
  public static byte[] getCanonicalDocText(Document doc) throws TransformerException {
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    plainTransformer.transform(new DOMSource(doc), new StreamResult(os));
    byte[] xmlData = os.toByteArray();
    return xmlData;
  }

  public static Document getNormalizedDocument(byte[] xmlData)
    throws ParserConfigurationException, IOException, SAXException {
    Document doc = safeDocBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(xmlData));
    doc.getDocumentElement().normalize();
    return doc;
  }

  public static Document getDocument(byte[] xmlData) throws IOException, SAXException, ParserConfigurationException {
    Document doc = safeDocBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(xmlData));
    return doc;
  }

  /**
   * Pare an XML file and returns an XML document
   *
   * @param xmlFile The XML file being parsed
   * @return XML document
   */
  public static Document loadXMLContent(File xmlFile) throws IOException, ParserConfigurationException, SAXException {
    Document doc;
    InputStream is = new FileInputStream(xmlFile);

    doc = safeDocBuilderFactory.newDocumentBuilder().parse(is);
    doc.getDocumentElement().normalize();
    return doc;

  }

  /**
   * Parse an XML file and returns an XML string
   *
   * @param xmlFile The XML file being parsed
   * @return XML String
   */
  public static String getParsedXMLText(File xmlFile)
    throws IOException, ParserConfigurationException, SAXException, TransformerException {
    return getDocText(loadXMLContent(xmlFile));
  }

  public static Element createStringAttributeValue(Document document, String value) {
    Element attrValue = document.createElementNS(AbstractDomData.SAML_ASSERTION_NS,
      SAMLAttribute.ATTRIBUTE_VALUE_ELEMENT_NAME);
    attrValue.setPrefix("saml");
    attrValue.setTextContent(value);
    Attr xsiAttr = document.createAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type");
    xsiAttr.setValue("xs:string");
    attrValue.setAttribute("xmlns:xs","http://www.w3.org/2001/XMLSchema");
    attrValue.setAttribute("xmlns:xsi","http://www.w3.org/2001/XMLSchema-instance");
    attrValue.setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type", "xs:string");
    attrValue.setAttributeNode(xsiAttr);
    return attrValue;
  }

}
