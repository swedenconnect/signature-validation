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

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * IdAttributes dom implementation
 */
@NoArgsConstructor
public class IdAttributes extends AbstractDomData {

  /** IdAttributes element name */
  public static final String ID_ATTRIBUTES_ELEMENT = "IdAttributes";

  /** List of attribute mapping data elements */
  @Setter
  private List<AttributeMapping> attributeMappings;

  /**
   * Constructs a new IdAttributes element data object from an existing XML element
   *
   * @param element IdAttributes XML element
   * @param strictMode true to strictly enforce content requirement rules
   * @throws CertificateException content requirement errors
   */
  public IdAttributes(Element element, boolean strictMode) throws CertificateException {
    super(element, strictMode);
  }

  /**
   * Get the list of attribute mappings. If no list exist, a new list is created
   *
   * @return the list of attribute mappings
   */
  public List<AttributeMapping> getAttributeMappings() {
    if (attributeMappings == null) {
      attributeMappings = new ArrayList<>();
    }
    return attributeMappings;
  }

  /** {@inheritDoc} */
  @Override protected void validate() throws CertificateException {
    if (attributeMappings == null || attributeMappings.isEmpty()) {
      throw new CertificateException("No AttributeMapping present in IdAttributes. "
        + "At least one Attribute mapping must be present in IdAttributes");
    }
  }

  /** {@inheritDoc} */
  @Override public Element getElement(final Document document) {
    Element idAttributes = document.createElementNS(SACI_NS, ID_ATTRIBUTES_ELEMENT);
    if (attributeMappings != null) {
      attributeMappings.forEach(attributeMapping -> idAttributes.appendChild(attributeMapping.getElement(document)));
    }
    return idAttributes;
  }

  @Override protected void setValuesFromElement(final Element element) throws CertificateException {
    List<Element> elements = getElements(element, SACI_NS, AttributeMapping.ATTRIBUTE_MAPPING_ELEMENT);
    attributeMappings = new ArrayList<>();
    for (Element attrMapElm : elements) {
      attributeMappings.add(new AttributeMapping(attrMapElm, strictMode));
    }
  }

}
