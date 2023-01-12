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

import static org.junit.jupiter.api.Assertions.*;

import java.security.Security;
import java.time.Instant;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import se.swedenconnect.cert.extensions.data.saci.SAMLAttribute;
import se.swedenconnect.cert.extensions.data.saci.SAMLAuthContext;
import se.swedenconnect.cert.extensions.utils.DOMUtils;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
class AuthnContextTest {

  @BeforeAll
  static void setUp() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 2);
    }
  }

  @Test
  void getAuthnContext() throws Exception {

    String parsedInstant = DOMUtils.XML_DATE_TIME_FORMATTER.format(Instant.now());
    Instant instant = DOMUtils.parseTime(parsedInstant);

    SAMLAuthContext samlAuthnContext = AuthnContext.getAuthnContext(TestData.samlAuthContextXml);

    String xmlPrint = AuthnContext.printAuthnContext(samlAuthnContext, true);
    String xmlPrint2 = AuthnContext.printAuthnContext(samlAuthnContext, true);

    AttributeMapping attributeMapping = samlAuthnContext.getIdAttributes().getAttributeMappingList().get(0);
    SAMLAttribute attribute = attributeMapping.getAttribute();
    Element attrVal = attribute.getAttributeValues().get(0);
    NamedNodeMap attributes = attrVal.getAttributes();
    String textContent = attrVal.getTextContent();
    //attribute.setAttributeValues(List.of(DOMUtils.createStringAttributeValue(samlAuthnContext.getDocument(), "new Value")));

    Element newValue = DOMUtils.createStringAttributeValue(samlAuthnContext.getDocument(), "1234209871934789");
    String newTextContent = newValue.getTextContent();
    NamedNodeMap newAttrNodeMap = newValue.getAttributes();

    attribute.setAttributeValues(List.of(newValue));
    String xmlPrint3 = AuthnContext.printAuthnContext(samlAuthnContext, true);

    int sdf=0;

  }
}