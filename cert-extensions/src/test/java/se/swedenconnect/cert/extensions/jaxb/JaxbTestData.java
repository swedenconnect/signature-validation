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

package se.swedenconnect.cert.extensions.jaxb;

import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import se.swedenconnect.schemas.cert.authcont.saci_1_0.AttributeMapping;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.AuthContextInfo;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.IdAttributes;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.SAMLAuthContext;
import se.swedenconnect.schemas.saml_2_0.assertion.Attribute;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class JaxbTestData {

  public static JaxbAuthnContext validJaxbAuthContext;
  public static JaxbAuthnContext nullSamlNameJaxbAuthContext;

  static {
    try {
      SAMLAuthContext validSAMLAuthContext = new SAMLAuthContext();
      validSAMLAuthContext.setAuthContextInfo(getAuthContextInfo());
      IdAttributes validIdAttr = new IdAttributes();
      List<AttributeMapping> validAttrMap = validIdAttr.getAttributeMappings();
      addValidAttrMappings(validAttrMap);
      validSAMLAuthContext.setIdAttributes(validIdAttr);
      validJaxbAuthContext = new JaxbAuthnContext(List.of(validSAMLAuthContext));
    } catch (Exception ex) {
      ex.printStackTrace();
    }

    try {
      SAMLAuthContext nullNameSAMLAuthContext = new SAMLAuthContext();
      nullNameSAMLAuthContext.setAuthContextInfo(getAuthContextInfo());
      IdAttributes nullNameIdAttr = new IdAttributes();
      List<AttributeMapping> nullNameAttrMap = nullNameIdAttr.getAttributeMappings();
      addNullDefaultAttrMappings(nullNameAttrMap);
      nullNameSAMLAuthContext.setIdAttributes(nullNameIdAttr);
      nullSamlNameJaxbAuthContext = new JaxbAuthnContext(List.of(nullNameSAMLAuthContext));
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

  public static JaxbAuthnContext getTestContext() throws Exception {
    SAMLAuthContext jaxbSAMLAuthContext = new SAMLAuthContext();
    jaxbSAMLAuthContext.setAuthContextInfo(getAuthContextInfo());

    IdAttributes idAttributes = new IdAttributes();
    List<AttributeMapping> attributeMappings = idAttributes.getAttributeMappings();
    addValidAttrMappings(attributeMappings);
    jaxbSAMLAuthContext.setIdAttributes(idAttributes);

    return new JaxbAuthnContext(List.of(jaxbSAMLAuthContext));
  }

  private static void addValidAttrMappings(List<AttributeMapping> attributeMappings) {
    attributeMappings.add(createAttributeMapping("urn:oid:1.2.752.29.4.13", "rdn", "2.5.4.5", "123123123"));
    attributeMappings.add(createAttributeMapping("default", "rdn", "2.5.4.6", "SE"));
    attributeMappings.add(createAttributeMapping("urn:oid:2.5.4.42", "rdn", "2.5.4.42", "Majlis"));
    attributeMappings.add(createAttributeMapping("urn:oid:2.5.4.4", "rdn", "2.5.4.4", "Medin"));
    attributeMappings.add(
      createAttributeMapping("urn:oid:2.16.840.1.113730.3.1.241", "rdn", "2.5.4.3", "Majlis Medin"));
  }

  private static void addNullDefaultAttrMappings(List<AttributeMapping> attributeMappings) {
    attributeMappings.add(createAttributeMapping("urn:oid:1.2.752.29.4.13", "rdn", "2.5.4.5", "123123123"));
    attributeMappings.add(createAttributeMapping(null, "rdn", "2.5.4.6", "SE"));
    attributeMappings.add(createAttributeMapping("urn:oid:2.5.4.42", "rdn", "2.5.4.42", "Majlis"));
    attributeMappings.add(createAttributeMapping("urn:oid:2.5.4.4", "rdn", "2.5.4.4", "Medin"));
    attributeMappings.add(
      createAttributeMapping("urn:oid:2.16.840.1.113730.3.1.241", "rdn", "2.5.4.3", "Majlis Medin"));
  }

  private static AuthContextInfo getAuthContextInfo() throws Exception {
    AuthContextInfo authContextInfo = new AuthContextInfo();
    authContextInfo.setIdentityProvider("http://example.com/idp");
    authContextInfo.setAuthnContextClassRef("http://example.com/loa");
    authContextInfo.setAssertionRef("_123123123");
    final GregorianCalendar gcal = new GregorianCalendar();
    gcal.setTime(new Date());
    authContextInfo.setAuthenticationInstant(DatatypeFactory.newInstance().newXMLGregorianCalendar(gcal));
    authContextInfo.setServiceID("service");
    return authContextInfo;
  }

  private static AttributeMapping createAttributeMapping(String samlName, String type, String ref, String val) {
    AttributeMapping mapping = new AttributeMapping();
    mapping.setType(type);
    mapping.setRef(ref);

    Attribute attribute = new Attribute();
    attribute.setName(samlName);
    attribute.getAttributeValues().add(val);
    mapping.setAttribute(attribute);
    return mapping;
  }
}
