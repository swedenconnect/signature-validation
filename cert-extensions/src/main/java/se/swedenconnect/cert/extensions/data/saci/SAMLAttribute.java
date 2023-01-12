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
import java.util.List;

import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.Data;
import lombok.NoArgsConstructor;
import se.swedenconnect.cert.extensions.utils.DOMUtils;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@NoArgsConstructor
public class SAMLAttribute extends AbstractDomData {

  public static final String ATTRIBUTE_ELEMENT_NAME = "Attribute";
  public static final String ATTRIBUTE_VALUE_ELEMENT_NAME = "AttributeValue";

  public static final String NAME = "Name";
  public static final String NAME_FORMAT = "NameFormat";
  public static final String FRIENDLY_NAME = "FriendlyName";

  private String name;
  private String nameFormat;
  private String friendlyName;
  private List<Attr> anyAttrList;
  private List<Element> attributeValues;

  public SAMLAttribute(Element element) throws CertificateException {
    super(element);
  }

  @Override public Element getElement(Document document) {
    Element attribute = document.createElementNS(SAML_ASSERTION_NS, ATTRIBUTE_ELEMENT_NAME);
    attribute.setPrefix("saml");
    DOMUtils.setAttribute(attribute, NAME, name);
    DOMUtils.setAttribute(attribute, NAME_FORMAT, nameFormat);
    DOMUtils.setAttribute(attribute, FRIENDLY_NAME, friendlyName);
    DOMUtils.adoptAttributes(attribute, document, anyAttrList);
    DOMUtils.adoptElements(attribute, document, attributeValues);
    return attribute;
  }

  @Override protected void setValuesFromElement(Element element) throws CertificateException {
    this.name = DOMUtils.getAttributeValue(element, NAME);
    this.nameFormat = DOMUtils.getAttributeValue(element, NAME_FORMAT);
    this.friendlyName = DOMUtils.getAttributeValue(element, FRIENDLY_NAME);
    this.anyAttrList = DOMUtils.getOtherAttributes(element, List.of(NAME, NAME_FORMAT, FRIENDLY_NAME));
    this.attributeValues = DOMUtils.getElements(element, SAML_ASSERTION_NS, ATTRIBUTE_VALUE_ELEMENT_NAME);
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
