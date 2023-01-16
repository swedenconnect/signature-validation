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

package se.swedenconnect.cert.extensions;

import java.security.Security;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.List;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.cert.extensions.data.saci.AbstractDomData;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import se.swedenconnect.cert.extensions.data.saci.SAMLAttribute;
import se.swedenconnect.cert.extensions.data.saci.SAMLAuthContext;
import se.swedenconnect.cert.extensions.jaxb.JaxbAuthnContext;
import se.swedenconnect.cert.extensions.jaxb.JaxbTestData;

/**
 * Testing AuthContext DOM implementation
 */
@Slf4j
class AuthnContextTest {

  @BeforeAll
  static void setUp() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  void getAuthnContext() throws Exception {

    SAMLAuthContext samlAuthnContext = AuthnContext.getAuthnContext(TestData.samlAuthContextXml, false);

    String xmlPrint = AuthnContext.printAuthnContext(samlAuthnContext, true);
    log.info("Parsed formatted SAMLAuthcontext \n", xmlPrint);

    AttributeMapping attributeMapping = samlAuthnContext.getIdAttributes().getAttributeMappings().get(0);
    SAMLAttribute attribute = attributeMapping.getAttribute();
    Element attrVal = attribute.getAttributeValues().get(0);
    NamedNodeMap attributes = attrVal.getAttributes();
    Assertions.assertEquals(3, attributes.getLength());
    String textContent = attrVal.getTextContent();
    Assertions.assertEquals("197010632391", textContent);

    Element newValue = SAMLAttribute.createStringAttributeValue("1234209871934789");
    String newTextContent = newValue.getTextContent();
    Assertions.assertEquals("1234209871934789", newTextContent);
    NamedNodeMap newAttrNodeMap = newValue.getAttributes();
    Assertions.assertEquals(3, newAttrNodeMap.getLength());

    attribute.setAttributeValues(List.of(newValue));
    String xmlPrint3 = AuthnContext.printAuthnContext(samlAuthnContext, false);
  }

  @Test
  void interopTest() throws Exception {
    AuthnContext.getInstance(JaxbTestData.getTestContext().toASN1Primitive());
    AuthnContext.getInstance(JaxbTestData.nullSamlNameJaxbAuthContext.toASN1Primitive(), false);

    IllegalArgumentException exception = Assertions.assertThrows(IllegalArgumentException.class, () -> {
      AuthnContext.getInstance(JaxbTestData.nullSamlNameJaxbAuthContext.toASN1Primitive(), true);
    });

    AuthnContext testContext = TestData.getTestContext(true);
    SAMLAuthContext samlAuthContext = testContext.getStatementInfoList().get(0);
    Instant authInstant = samlAuthContext.getAuthContextInfo().getAuthenticationInstant();
    String printAuthContext = AuthnContext.printAuthnContext(samlAuthContext, false);
    SAMLAuthContext parseSAMLAuthContext = new SAMLAuthContext(printAuthContext, false);
    Assertions.assertEquals(
      AbstractDomData.instantToString(authInstant),
      AbstractDomData.instantToString(parseSAMLAuthContext.getAuthContextInfo().getAuthenticationInstant()));
    log.info("Time expressed is expected: " + AbstractDomData.instantToString(authInstant));

    JaxbAuthnContext jaxbAuthnContext = JaxbAuthnContext.getInstance(TestData.getTestContext(true).toASN1Primitive());
  }


}