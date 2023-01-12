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

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Attribute mapping element
 */
@Data
@NoArgsConstructor
public class AttributeMapping extends AbstractDomData {

  public static final String ATTRIBUTE_MAPPING_ELEMENT = "AttributeMapping";

  public static final String TYPE = "Type";
  public static final String REF = "Ref";

  private Type type;
  private String ref;
  private SAMLAttribute attribute;
  private List<Element> anyList;

  public AttributeMapping(Element element, boolean strictMode) throws CertificateException {
    super(element, strictMode);
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

  @Override public Element getElement(Document document) {
    Element attributeMapping = document.createElementNS(SACI_NS, ATTRIBUTE_MAPPING_ELEMENT);
    setAttribute(attributeMapping, TYPE, type.name());
    setAttribute(attributeMapping, REF, ref);
    attributeMapping.appendChild(attribute.getElement(document));
    adoptElements(attributeMapping, document, anyList);
    return attributeMapping;
  }

  @Override protected void setValuesFromElement(Element element) throws CertificateException {
    type = Type.getTypeFromName(getAttributeValue(element, TYPE));
    ref = getAttributeValue(element, REF);

    Element attributeElm = getSingleElement(element, SAML_ASSERTION_NS, SAMLAttribute.ATTRIBUTE_ELEMENT);
    if (attributeElm != null) {
      this.attribute = new SAMLAttribute(attributeElm, strictMode);
    }
    anyList = new ArrayList<>();
    NodeList childNodes = element.getChildNodes();
    for (int i = 0; i < childNodes.getLength(); i++) {
      Node node = childNodes.item(i);
      if (node instanceof Element) {
        if (!node.getNamespaceURI().equals(SAML_ASSERTION_NS) || !node.getLocalName()
          .equals(SAMLAttribute.ATTRIBUTE_ELEMENT)) {
          anyList.add((Element) node);
        }
      }
    }
  }

  public static enum Type {
    rdn, san, sda;

    public static Type getTypeFromName(String name) {
      return Arrays.stream(values())
        .filter(type -> type.name().equals(name))
        .findFirst().orElse(null);
    }
  }
}
