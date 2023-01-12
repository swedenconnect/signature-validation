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

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import lombok.NoArgsConstructor;

/**
 * Abstract class providing basics for RFC7773 SAMLAuthContext xml elements
 */
@NoArgsConstructor
public abstract class AbstractDomData {

  public static final String SACI_NS = "http://id.elegnamnden.se/auth-cont/1.0/saci";
  public static final String SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";

  public AbstractDomData(Element element) throws CertificateException {
    setValuesFromElement(element);
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
   * @throws CertificateException
   */
  protected abstract void validate() throws CertificateException;

}
