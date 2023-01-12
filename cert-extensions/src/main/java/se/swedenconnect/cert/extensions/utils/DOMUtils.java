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
import java.util.Objects;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

/**
 * XML DOM Utils
 */
@Slf4j
public class DOMUtils {

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

}
