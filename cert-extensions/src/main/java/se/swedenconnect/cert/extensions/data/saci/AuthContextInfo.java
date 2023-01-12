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
import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Description
 */
@Data
@NoArgsConstructor
public class AuthContextInfo extends AbstractDomData {

  public static final String AUTH_CONTEXT_INFO_ELEMENT_NAME = "AuthContextInfo";

  public static final String IDENTITY_PROVIDER = "IdentityProvider";
  public static final String AUTHENTICATION_INSTANT = "AuthenticationInstant";
  public static final String AUTHN_CONTEXT_CLASS_REF = "AuthnContextClassRef";
  public static final String ASSERTION_REF = "AssertionRef";
  public static final String SERVICE_ID = "ServiceID";

  private String identityProvider;
  private Instant authenticationInstant;
  private String authnContextClassRef;
  private String assertionRef;
  private String serviceId;
  private List<Element> anyList;

  public AuthContextInfo(Element element) throws CertificateException {
    super(element);
  }

  @Override public Element getElement(Document document) {
    Element authContextInfo = document.createElementNS(SACI_NS, AUTH_CONTEXT_INFO_ELEMENT_NAME);
    setAttribute(authContextInfo, IDENTITY_PROVIDER, identityProvider);
    setAttribute(authContextInfo, AUTHENTICATION_INSTANT, instantToString(authenticationInstant));
    setAttribute(authContextInfo, AUTHN_CONTEXT_CLASS_REF, authnContextClassRef);
    setAttribute(authContextInfo, ASSERTION_REF, assertionRef);
    setAttribute(authContextInfo, SERVICE_ID, serviceId);
    adoptElements(authContextInfo, document, anyList);
    return authContextInfo;
  }

  @Override protected void setValuesFromElement(Element element) throws CertificateException {
    this.identityProvider = getAttributeValue(element, IDENTITY_PROVIDER);
    this.authenticationInstant = parseTime(getAttributeValue(element, AUTHENTICATION_INSTANT));
    this.authnContextClassRef = getAttributeValue(element, AUTHN_CONTEXT_CLASS_REF);
    this.assertionRef = getAttributeValue(element, ASSERTION_REF);
    this.serviceId = getAttributeValue(element, SERVICE_ID);

    anyList = new ArrayList<>();
    NodeList childNodes = element.getChildNodes();
    for (int i = 0; i < childNodes.getLength(); i++) {
      Node node = childNodes.item(i);
      if (node instanceof Element) {
        anyList.add((Element) node);
      }
    }
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
