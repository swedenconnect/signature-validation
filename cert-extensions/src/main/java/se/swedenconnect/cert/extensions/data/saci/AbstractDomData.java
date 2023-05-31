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
import java.time.ZonedDateTime;
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
 * Abstract class providing basics for xml elements that are part of the SAMLAuthContext implementation
 */
@NoArgsConstructor
public abstract class AbstractDomData {

  /** Formatter for XML date element content */
  public static final DateTimeFormatter XML_DATE_TIME_FORMATTER = DateTimeFormatter.ofPattern(
    "yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ", Locale.ENGLISH).withZone(ZoneId.systemDefault());

  /** XML name space URI for the RFC 7773 SAMLAuthContext XML element */
  public static final String SACI_NS = "http://id.elegnamnden.se/auth-cont/1.0/saci";
  /** XML name space URI for SAML assertion data */
  public static final String SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

  /** indicates if content validation should be done with strict compliance requirements */
  protected boolean strictMode;

  /**
   * Constructor for the base Abstract class
   *
   * @param element The element holding a SAMLAuthContextExtension extension
   *
   * @throws CertificateException content validation error
   */
  public AbstractDomData(final Element element) throws CertificateException {
    this(element, false);
  }

  /**
   * Constructor for the base Abstract class setting strict mode
   *
   * @param element The element holding a SAMLAuthContextExtension extension
   * @param strictMode true to strictly enforce content requirement rules
   * @throws CertificateException content validation error
   */
  public AbstractDomData(final Element element, final boolean strictMode) throws CertificateException {
    this.strictMode = strictMode;
    setValuesFromElement(element);
    validate();
  }

  /**
   * Creates an instance of this elements data from a DOM element
   *
   * @param element xml element providing content data
   * @throws CertificateException content validation error
   */
  protected abstract void setValuesFromElement(final Element element) throws CertificateException;

  /**
   * Gets a DOM element from the element data fields
   *
   * @param document the document this element shall belong to
   * @return DOM element populated with the field data of this object
   */
  protected abstract Element getElement(final Document document);

  /**
   * Validates the data fields of this object to assert that it meets basic content requirements
   *
   * @throws CertificateException validation errors
   */
  protected abstract void validate() throws CertificateException;

  /**
   * Get the first available element from a parent element matching specified name parameters
   *
   * @param parent the parent element
   * @param namespaceUri name space URI for the requested element
   * @param elementName the name of the requested element
   * @return the first available element matching the name criteria or null if no such element exists in the parent element
   */
  public static Element getSingleElement(final Element parent, final String namespaceUri, final String elementName) {
    final List<Element> elementList = getElements(parent, namespaceUri, elementName);
    if (elementList.isEmpty()) {
      return null;
    }
    return elementList.get(0);
  }

  /**
   * Get elements from parent element that meets name requirements
   *
   * @param parent the parent element
   * @param namespaceUri name space URI for the requested element
   * @param elementName the name of the requested elements
   * @return all available elements matching the name criteria or null if no such element exists in the parent element
   */
  public static List<Element> getElements(final Element parent, final String namespaceUri, final String elementName) {
    final NodeList elements = parent.getElementsByTagNameNS(namespaceUri, elementName);
    List<Element> elementList = new ArrayList<>();
    for (int i = 0; i < elements.getLength(); i++) {
      final Node node = elements.item(i);
      if (node instanceof Element) {
        elementList.add((Element) node);
      }
    }
    return elementList;
  }

  /**
   * Sets an XML element attribute
   *
   * @param element the element where the attribute should be added
   * @param name name of the attribute
   * @param value value of the attribute
   */
  public static void setAttribute(Element element, String name, String value) {
    setAttribute(element, name, value, null);
  }

  /**
   * Sets an XML element attribute with namespace URI declaration
   *
   * @param element the element where the attribute should be added
   * @param name name of the attribute
   * @param value value of the attribute
   * @param namespaceUri name space URI of the attribute
   */
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

  /**
   * Get the attribute value of an element attribute
   *
   * @param element the element holding the attribute value
   * @param name name of the attribute
   * @return attribute value or null if no such attribute is present with a non-empty value
   */
  public static String getAttributeValue(Element element, String name) {
    return getAttributeValue(element, name, null);
  }

  /**
   * Get the attribute value of an element attribute supporting a defined name space URI
   *
   * @param element the element holding the attribute value
   * @param name name of the attribute
   * @param namespaceUri name space URI of the attribute
   * @return attribute value or null if no such attribute is present with a non-empty value
   */
  public static String getAttributeValue(Element element, String name, String namespaceUri) {
    String val = namespaceUri == null
      ? element.getAttribute(name)
      : element.getAttributeNS(namespaceUri, name);

    return (val.length() > 0) ? val : null;
  }

  /**
   * Get all attributes of an element that is not listed in an excludeList.
   * This is used to locate extension attributes with any declaration that are not part of the defined set.
   *
   * @param element element holding attributes
   * @param excludeList list of attribute names that should be excluded from the result list
   * @return list of attributes not present in the exclude list
   */
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

  /**
   * Adopting a list of elements in a document and adding them to a specific element
   *
   * @param adoptingElement the element where the adopted elements should be added
   * @param document document adopting the elements
   * @param toBeAdoptedList list of elements to be adopted and added to the adopting element
   */
  public static void adoptElements(Element adoptingElement, Document document, List<Element> toBeAdoptedList) {
    if (toBeAdoptedList == null) {
      return;
    }
    toBeAdoptedList.forEach(element -> {
      document.adoptNode(element);
      adoptingElement.appendChild(element);
    });
  }

  /**
   * Adopting a list of attribute nodes in an element
   *
   * @param adoptingElement the element where the provided attributes should be added
   * @param document document adopting the attribute nodes
   * @param toBeAdoptedList list of attributes to be adopted and added
   */
  public static void adoptAttributes(Element adoptingElement, Document document, List<Attr> toBeAdoptedList) {
    if (toBeAdoptedList == null) {
      return;
    }
    toBeAdoptedList.forEach(attr -> {
      document.adoptNode(attr);
      adoptingElement.setAttributeNode(attr);
    });
  }

  /**
   * Converts an Instant time to an XML formatted xs:dateTime value
   *
   * @param instant time to be converted
   * @return XML string formatted as xs:dateTime
   */
  public static String instantToString(Instant instant) {
    if (instant == null) {
      return null;
    }
    return XML_DATE_TIME_FORMATTER.format(instant);
  }

  /**
   * Converts an XML xs:dateTime string to Instant
   *
   * @param xmlTimeStr string expression of an xs:dateTime value
   * @return Instant object
   */
  public static Instant parseTime(String xmlTimeStr) {
    if (xmlTimeStr == null) {
      return null;
    }
    ZonedDateTime zonedDateTime = LocalDateTime.parse(xmlTimeStr, XML_DATE_TIME_FORMATTER)
      .atZone(ZoneId.systemDefault());
    return Instant.from(zonedDateTime);
  }

}
