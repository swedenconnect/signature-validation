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

import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.cert.extensions.utils.DOMUtils;

/**
 * IdAttributes of SAMLAuthContextExtension
 */
@Data
@NoArgsConstructor
public class IdAttributes  extends AbstractDomData{

  public static final String ID_ATTRIBUTES = "IdAttributes";

  private List<AttributeMapping> attributeMappingList;

  public IdAttributes(Element element) throws CertificateException {
    super(element);
  }

  @Override public Element getElement(Document document) {
    Element idAttributes = document.createElementNS(SACI_NS, ID_ATTRIBUTES);
    if (attributeMappingList != null) {
      attributeMappingList.forEach(attributeMapping -> idAttributes.appendChild(attributeMapping.getElement(document)));
    }
    return idAttributes;
  }

  @Override protected void setValuesFromElement(Element element) throws CertificateException {
    List<Element> elements = DOMUtils.getElements(element, SACI_NS, AttributeMapping.ATTRIBUTE_MAPPING_ELEMENT_NAME);
    attributeMappingList = new ArrayList<>();
    for (Element attrMapElm : elements) {
      attributeMappingList.add(new AttributeMapping(attrMapElm));
    }
    validate();
  }

  /** {@inheritDoc} */
  @Override protected void validate() throws CertificateException {
    try {
      //TODO field validation check
    }
    catch (Exception ex) {
      throw new CertificateException(ex);
    }
  }

}
