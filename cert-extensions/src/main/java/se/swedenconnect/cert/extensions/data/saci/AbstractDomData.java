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

package se.swedenconnect.cert.extensions.data.saci;

import java.security.cert.CertificateException;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import lombok.NoArgsConstructor;

/**
 * Abstract class providing basics for xml elements
 */
@NoArgsConstructor
public abstract class AbstractDomData {

  public static final DateTimeFormatter XML_DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern(
    "yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ",
    Locale.ENGLISH).withZone(ZoneId.systemDefault());

  public static final String SACI_NS = "http://id.elegnamnden.se/auth-cont/1.0/saci";
  public static final String SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

  public AbstractDomData(Element element) throws CertificateException {
    setValuesFromElement(element);
    validate();
  }

  /**
   * Creates an instance of this elements data from a DOM element
   *
   * @param element xml element providing content data
   */
  protected abstract void setValuesFromElement(Element element) throws CertificateException;

  /**
   * Gets a DOM element from the element data fields
   *
   * @param document the document this element shall belong to
   * @return DOM element populated with the field data of this object
   */
  protected abstract Element getElement(Document document);

  /**
   * Validates the data fields of this object to assert that it meets basic content requirements
   *
   * @throws CertificateException
   */
  protected abstract void validate() throws CertificateException;

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
    setAttribute(element, name, value, null);
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

    return (val.length() > 0) ? val : null;
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

}
