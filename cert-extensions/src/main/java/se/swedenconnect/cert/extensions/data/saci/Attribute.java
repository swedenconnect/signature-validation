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
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.cert.extensions.utils.DOMUtils;

/**
 * SAML Attribute dom implementation
 */
@NoArgsConstructor
@Slf4j
public class Attribute extends AbstractDomData {

  /** Attribute element name */
  public static final String ATTRIBUTE_ELEMENT = "Attribute";
  /** AttributeValue element name */
  public static final String ATTRIBUTE_VALUE_ELEMENT = "AttributeValue";

  /** Name attribute name */
  public static final String NAME = "Name";
  /** NameFormat attribute name */
  public static final String NAME_FORMAT = "NameFormat";
  /** FriendlyName attribute name */
  public static final String FRIENDLY_NAME = "FriendlyName";

  /** SAML attribute name */
  @Getter
  @Setter
  private String name;

  /** SAML attribute nameFormat */
  @Getter
  @Setter
  private String nameFormat;

  /** SAML attribute friendly name */
  @Getter
  @Setter
  private String friendlyName;

  /** SAML attribute other attributes */
  @Setter
  private List<Attr> anyAttrList;

  /** SAML attribute value elements */
  @Setter
  private List<Element> attributeValues;

  /**
   * Constructs a SAML attribute from XML element
   * @param element source XML element
   * @param strictMode true to strictly enforce content requirement rules
   * @throws CertificateException content validation error
   */
  public Attribute(final Element element, final boolean strictMode) throws CertificateException {
    super(element, strictMode);
  }

  /**
   * Get the list of attribute values. If this list is absent, a new list will be created
   *
   * @return the list of attribute values
   */
  public List<Element> getAttributeValues() {
    if (attributeValues == null) {
      attributeValues = new ArrayList<>();
    }
    return attributeValues;
  }

  /**
   * Get the list of additional element attributes. If this list is absent, a new list will be created
   *
   * @return the list of element attributes
   */
  public List<Attr> getAnyAttrList() {
    if (anyAttrList == null) {
      anyAttrList = new ArrayList<>();
    }
    return anyAttrList;
  }

  /** {@inheritDoc} */
  @Override protected void validate() throws CertificateException {
    try {
      if (strictMode){
        Objects.requireNonNull(name, "Name attribute must be present");
      }
    }
    catch (final Exception ex) {
      throw new CertificateException(ex);
    }
  }

  /** {@inheritDoc} */
  @Override public Element getElement(final Document document) {
    final Element attribute = document.createElementNS(SAML_ASSERTION_NS, ATTRIBUTE_ELEMENT);
    attribute.setPrefix("saml");
    setAttribute(attribute, NAME, name);
    setAttribute(attribute, NAME_FORMAT, nameFormat);
    setAttribute(attribute, FRIENDLY_NAME, friendlyName);
    adoptAttributes(attribute, document, anyAttrList);
    adoptElements(attribute, document, attributeValues);
    return attribute;
  }

  /** {@inheritDoc} */
  @Override protected void setValuesFromElement(final Element element) throws CertificateException {
    this.name = getAttributeValue(element, NAME);
    this.nameFormat = getAttributeValue(element, NAME_FORMAT);
    this.friendlyName = getAttributeValue(element, FRIENDLY_NAME);
    this.anyAttrList = getOtherAttributes(element, List.of(NAME, NAME_FORMAT, FRIENDLY_NAME));
    this.attributeValues = getElements(element, SAML_ASSERTION_NS, ATTRIBUTE_VALUE_ELEMENT);
  }

  /**
   * Creates a new attribute value with string content where the value is declared as xs:string
   * The attribute value gets created from a new DOM document.
   *
   * @param value string value
   * @return attribute value element
   */
  public static Element createStringAttributeValue(final String value) {
    return createStringAttributeValue(DOMUtils.createNewDocument(), value);
  }

  /**
   * Creates a new attribute value with string content where the value is declared as xs:string.
   * The attribute value gets created as belonging to a provided DOM document
   *
   * @param document document to which this attribute belongs
   * @param value string value
   * @return attribute value element
   */
  public static Element createStringAttributeValue(final Document document, final String value) {
    final Element attrValue = document.createElementNS(AbstractDomData.SAML_ASSERTION_NS,
      Attribute.ATTRIBUTE_VALUE_ELEMENT);
    attrValue.setPrefix("saml");
    attrValue.setTextContent(value);
    Attr xsiAttr = document.createAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type");
    xsiAttr.setValue("xs:string");
    attrValue.setAttribute("xmlns:xs", "http://www.w3.org/2001/XMLSchema");
    attrValue.setAttribute("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance");
    attrValue.setAttributeNS("http://www.w3.org/2001/XMLSchema-instance", "xsi:type", "xs:string");
    attrValue.setAttributeNode(xsiAttr);
    return attrValue;
  }

}
