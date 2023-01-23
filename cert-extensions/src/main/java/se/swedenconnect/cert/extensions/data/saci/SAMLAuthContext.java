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

import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import lombok.Data;
import lombok.EqualsAndHashCode;
import se.swedenconnect.cert.extensions.utils.DOMUtils;

/**
 * DOM based implementation of SAMLAuthContext for the AuhtnContext extension RFC 7773
 */
@EqualsAndHashCode(callSuper = true) @Data
public class SAMLAuthContext extends AbstractDomData {

  /** SAMLAuthContext element name */
  private static final String SAML_AUTH_CONTEXT_ELEMENT = "SAMLAuthContext";

  /** AuthContextInfo element data */
  private AuthContextInfo authContextInfo;
  /** IdAttributes element data */
  private IdAttributes idAttributes;

  /** The XML document of the created SAMLAuthContext XML used to create all its elements */
  private Document document;

  /**
   * Creates a new empty SAMLAuthContext object
   *
   * @param strictMode true to strictly enforce content requirement rules
   */
  public SAMLAuthContext(final boolean strictMode) {
    this.document = DOMUtils.createNewDocument();
    this.strictMode = strictMode;
  }

  /**
   * Creates a SAMLAuthContext object from an XML document
   *
   * @param document document holding SAMLAuthContext data
   * @param strictMode true to strictly enforce content requirement rules
   * @throws CertificateException content validation errors
   */
  public SAMLAuthContext(final Document document, final boolean strictMode) throws CertificateException {
    super(document.getDocumentElement(), strictMode);
    this.document = document;
    validateDocument();
  }

  /**
   * Creates a SAMLAuthContext object from XML text
   *
   * @param xml xml text source
   * @param strictMode true to strictly enforce content requirement rules
   * @throws IOException errors parsing xml content
   * @throws ParserConfigurationException errors parsing xml content
   * @throws SAXException errors parsing xml content
   * @throws CertificateException content validation errors
   */
  public SAMLAuthContext(final String xml, final boolean strictMode)
    throws IOException, ParserConfigurationException, SAXException, CertificateException {
    this.strictMode = strictMode;
    this.document = DOMUtils.getDocument(xml.getBytes(StandardCharsets.UTF_8));
    setValuesFromElement(document.getDocumentElement());
    validate();
  }

  /** {@inheritDoc} */
  @Override protected void validate() throws CertificateException {
    /**
     * Checks made here are called from the Abstract class constructor.
     *
     * These checks are unaware of the Document that may be set and used to
     * import data and only includes checks of the actual content of the XML element
     * represented by this class.
     *
     * As no elements are required (all optional) no checks are done here
     */
  }

  /**
   * Additional checks made on the root element adding checks on the actual DOM document
   * used to import data to ensure that the actual root element properties are valid
   *
   * @throws CertificateException content validation errors
   */
  private void validateDocument() throws CertificateException {
    final Element root = document.getDocumentElement();
    if (!SACI_NS.equals(root.getNamespaceURI()) && !SAML_AUTH_CONTEXT_ELEMENT.equals(root.getLocalName())) {
      throw new CertificateException("Illegal root element name");
    }
  }

  /**
   * Builds a new document for SAMLAuthContext
   *
   * @return SAMLAuthContext XML document
   */
  public Document getDocument() {
    this.document = DOMUtils.createNewDocument();
    final Element samlAuthContext = getElement(document);
    document.appendChild(samlAuthContext);
    return document;
  }

  /** {@inheritDoc} */
  @Override protected Element getElement(final Document owner) {
    final Element samlAuthContext = owner.createElementNS(SACI_NS, SAML_AUTH_CONTEXT_ELEMENT);
    if (authContextInfo != null){
      samlAuthContext.appendChild(authContextInfo.getElement(owner));
    }
    if (idAttributes != null) {
      samlAuthContext.appendChild(idAttributes.getElement(owner));
    }
    return samlAuthContext;
  }

  /** {@inheritDoc} */
  @Override protected void setValuesFromElement(final Element element) throws CertificateException {
    final Element authContextInfoElm = getSingleElement(element, SACI_NS, AuthContextInfo.AUTH_CONTEXT_INFO_ELEMENT);
    if (authContextInfoElm != null) {
      authContextInfo = new AuthContextInfo(authContextInfoElm, strictMode);
    }
    final Element idAttributesElm = getSingleElement(element, AbstractDomData.SACI_NS, IdAttributes.ID_ATTRIBUTES_ELEMENT);
    if (idAttributesElm != null) {
      idAttributes = new IdAttributes(idAttributesElm, strictMode);
    }
  }

}
