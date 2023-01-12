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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.util.Objects;

import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import lombok.Data;
import lombok.EqualsAndHashCode;
import se.swedenconnect.cert.extensions.utils.DOMUtils;

/**
 * DOM based implementation of SAMLAuthContext for the Auhtn Context extension RFC 7773
 */
@EqualsAndHashCode(callSuper = true) @Data
public class SAMLAuthContext extends AbstractDomData {

  private AuthContextInfo authContextInfo;
  private IdAttributes idAttributes;

  private Document document;

  public SAMLAuthContext() {
    this.document = createNewDocument();
  }

  public SAMLAuthContext(Document document) throws CertificateException {
    super(document.getDocumentElement());
    this.document = document;
  }

  public SAMLAuthContext(String xml)
    throws IOException, ParserConfigurationException, SAXException, CertificateException {
    this.document = DOMUtils.getDocument(xml.getBytes(StandardCharsets.UTF_8));
    setValuesFromElement(document.getDocumentElement());
    validate();
  }

  /**
   * Builds a new document for SAMLAuthContext
   *
   * @return SAMLAuthContext XML document
   */
  public Document getDocument() {
    this.document = createNewDocument();
    Element samlAuthContext = getElement(document);
    document.appendChild(samlAuthContext);
    return document;
  }

  /** {@inheritDoc} */
  @Override protected Element getElement(Document owner) {
    Element samlAuthContext = owner.createElementNS(SACI_NS, "SAMLAuthContext");
    samlAuthContext.appendChild(authContextInfo.getElement(owner));
    samlAuthContext.appendChild(idAttributes.getElement(owner));
    return samlAuthContext;
  }

  /** {@inheritDoc} */
  @Override protected void setValuesFromElement(Element element) throws CertificateException {
    Element authContextInfoElm = getSingleElement(element, SACI_NS, "AuthContextInfo");
    if (authContextInfoElm != null) {
      authContextInfo = new AuthContextInfo(authContextInfoElm);
    }
    Element idAttributesElm = getSingleElement(element, AbstractDomData.SACI_NS, "IdAttributes");
    if (idAttributesElm != null) {
      idAttributes = new IdAttributes(idAttributesElm);
    }
  }

  /** {@inheritDoc} */
  @Override protected void validate() throws CertificateException {
    try {
      Objects.requireNonNull(authContextInfo, "AuthContextInfo element is not present");
      Objects.requireNonNull(idAttributes, "IdAttributes element is not present");
    }
    catch (Exception ex) {
      throw new CertificateException(ex);
    }
  }

  private Document createNewDocument() {
    try {
      return DOMUtils.getSafeDocBuilderFactory().newDocumentBuilder().newDocument();
    }
    catch (ParserConfigurationException e) {
      throw new RuntimeException("Failed to create XML document");
    }

  }
}
