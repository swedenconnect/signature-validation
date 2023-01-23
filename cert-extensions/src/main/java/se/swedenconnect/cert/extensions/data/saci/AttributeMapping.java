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
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Attribute mapping element
 */
@NoArgsConstructor
public class AttributeMapping extends AbstractDomData {

  /** AttributeMapping element name */
  public static final String ATTRIBUTE_MAPPING_ELEMENT = "AttributeMapping";

  /** Type attribute name */
  public static final String TYPE = "Type";
  /** Ref attribute name */
  public static final String REF = "Ref";

  /** Type of attribute mapping */
  @Getter
  @Setter
  private Type type;

  /** Reference identifying the certificate destination object (attribute, Subj alt name or directory attribute */
  @Getter
  @Setter
  private String ref;

  /** The source SAML attribute data */
  @Getter
  @Setter
  private Attribute attribute;

  /** List of extension elements */
  @Setter
  private List<Element> anyList;

  /**
   * Constructing attribute mapping from xml element
   * @param element xml element holding the attribute mapping data
   * @param strictMode true to strictly enforce content requirement rules
   * @throws CertificateException content validation error
   */
  public AttributeMapping(final Element element, final boolean strictMode) throws CertificateException {
    super(element, strictMode);
  }


  /**
   * Get the list of additional elements. If this list is absent, a new list will be created
   *
   * @return the list of additional elements
   */
  public List<Element> getAnyList() {
    if (anyList == null) {
      anyList = new ArrayList<>();
    }
    return anyList;
  }

  /** {@inheritDoc} */
  @Override protected void validate() throws CertificateException {
    try {
      Objects.requireNonNull(type, "Type attribute must be present in AttributeMapping");
      Objects.requireNonNull(ref, "Ref attribute must be present in AttributeMapping");
      Objects.requireNonNull(attribute, "Attribute element must be present in AttributeMapping");
    }
    catch (Exception ex) {
      throw new CertificateException(ex);
    }
  }

  /** {@inheritDoc} */
  @Override public Element getElement(final Document document) {
    final Element attributeMapping = document.createElementNS(SACI_NS, ATTRIBUTE_MAPPING_ELEMENT);
    setAttribute(attributeMapping, TYPE, type.name());
    setAttribute(attributeMapping, REF, ref);
    attributeMapping.appendChild(attribute.getElement(document));
    adoptElements(attributeMapping, document, anyList);
    return attributeMapping;
  }

  /** {@inheritDoc} */
  @Override protected void setValuesFromElement(final Element element) throws CertificateException {
    type = Type.getTypeFromName(getAttributeValue(element, TYPE));
    ref = getAttributeValue(element, REF);

    final Element attributeElm = getSingleElement(element, SAML_ASSERTION_NS, Attribute.ATTRIBUTE_ELEMENT);
    if (attributeElm != null) {
      this.attribute = new Attribute(attributeElm, strictMode);
    }
    anyList = new ArrayList<>();
    final NodeList childNodes = element.getChildNodes();
    for (int i = 0; i < childNodes.getLength(); i++) {
      final Node node = childNodes.item(i);
      if (node instanceof Element) {
        if (!node.getNamespaceURI().equals(SAML_ASSERTION_NS) || !node.getLocalName()
          .equals(Attribute.ATTRIBUTE_ELEMENT)) {
          anyList.add((Element) node);
        }
      }
    }
  }

  /**
   * Enumeration of mapping types
   */
  public static enum Type {
    /** The target certificate object is a Relative Distinguished Name in the Subject field */
    rdn,
    /** The target certificate object is a SubjectAltName value */
    san,
    /** The target certificate object is a Subject Directory Attribute extension value */
    sda;

    /**
     * Get type matching the name of the type
     * @param name name of the Type
     * @return the Type enum object matching the name or null no such value is present
     */
    public static Type getTypeFromName(String name) {
      return Arrays.stream(values())
        .filter(type -> type.name().equals(name))
        .findFirst().orElse(null);
    }
  }
}
