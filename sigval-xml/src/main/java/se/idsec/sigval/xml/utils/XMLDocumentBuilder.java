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

package se.idsec.sigval.xml.utils;

import lombok.extern.slf4j.Slf4j;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

/**
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class XMLDocumentBuilder {

  private static Transformer trans;
  private static Transformer transformer;
  private static DocumentBuilderFactory safeDocBuilderFactory;

  static {
    /**
     * This document builder factory is created in line with recommendations by OWASP
     * <p>https://www.owasp.org/index.php/XML_External_Entity_(XXE)_Prevention_Cheat_Sheet#JAXP_DocumentBuilderFactory.2C_SAXParserFactory_and_DOM4J</p>
     * This Document builder disables the use of DTD and mitigates XEE attack threats
     */
    safeDocBuilderFactory = DocumentBuilderFactory.newInstance();
    safeDocBuilderFactory.setNamespaceAware(true);
    //safeDocBuilderFactory.setValidating(true);
    try {
      safeDocBuilderFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
      safeDocBuilderFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
      safeDocBuilderFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
      safeDocBuilderFactory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
      safeDocBuilderFactory.setXIncludeAware(false);
      safeDocBuilderFactory.setExpandEntityReferences(false);
    }
    catch (ParserConfigurationException ex) {
      log.error("Error setting up safe document builder factory", ex);
    }

    TransformerFactory tf = TransformerFactory.newInstance();
    try {
      trans = tf.newTransformer();
      transformer = tf.newTransformer();
      transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
      //transformer.setOutputProperty(OutputKeys.STANDALONE, "no");
      transformer.setOutputProperty(OutputKeys.METHOD, "xml");
      transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");
      transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "4");
      transformer.setOutputProperty(OutputKeys.INDENT, "yes");
    }
    catch (Exception ex) {
      log.error("Error setting up transformer", ex);
    }
  }

  /**
   * Generates a pretty XML print of an XML document based on java.xml
   * functions.
   *
   * @param doc The doc being processed
   * @return Test representation of the XML document
   */
  public static String getDocText(Document doc) throws IOException {
    if (doc == null) {
      return null;
    }

    DOMSource domSource = new DOMSource(doc);
    try {
      java.io.StringWriter sw = new java.io.StringWriter();
      StreamResult sr = new StreamResult(sw);
      transformer.transform(domSource, sr);
      String xml = sw.toString();
      return xml;
    }
    catch (Exception ex) {
      throw new IOException("Error parsing XML document", ex);
    }
  }

  /**
   * Provides a canonical print of the XML document. The purpose of this print
   * is to try to preserve integrity of an existing signature.
   *
   * @param doc The XML document being processed.
   * @return XML String
   */

  /**
   * Provides a canonical print of the XML document. The purpose of this print
   * is to try to preserve integrity of an existing signature.
   *
   * @param doc The XML document being processed.
   * @return The bytes of the xml document
   * @throws TransformerException
   */
  public static byte[] getCanonicalDocBytes(Document doc) throws TransformerException {
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    trans.transform(new DOMSource(doc), new StreamResult(os));
    byte[] xmlData = os.toByteArray();
    return xmlData;
  }

  /**
   * Returns an XML document from a safe document builder process
   * @param xmlData XML document bytes
   * @return XML document
   * @throws IOException On IO errors
   * @throws SAXException Error parsing XML content
   * @throws ParserConfigurationException Error in configuration of the parser
   */
  public static Document getDocument(byte[] xmlData) throws IOException, SAXException, ParserConfigurationException {
    Document doc = safeDocBuilderFactory.newDocumentBuilder().parse(new ByteArrayInputStream(xmlData));
    return doc;
  }

  /**
   * Parse an XML file and returns an XML document
   *
   * @param xmlFile The XML file being parsed
   * @return XML Document
   * @throws IOException On IO errors
   * @throws SAXException Error parsing XML content
   * @throws ParserConfigurationException Error in configuration of the parser
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
  public static String getParsedXMLText(File xmlFile) throws ParserConfigurationException, SAXException, IOException {
    return getDocText(loadXMLContent(xmlFile));
  }

  public static DocumentBuilderFactory getDbFactory() {
    return safeDocBuilderFactory;
  }
}
