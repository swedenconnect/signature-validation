/*
 * Copyright (c) 2026. Sweden Connect
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

package se.swedenconnect.sigval.report;

import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.cert.extensions.AuthnContext;
import se.swedenconnect.cert.extensions.AuthnContextEntry;
import se.swedenconnect.cert.extensions.data.oaci.ClaimMapping;
import se.swedenconnect.cert.extensions.data.oaci.OIDCAuthContext;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import se.swedenconnect.id.authCont.x10.generic.AuthenticationContextDocument;
import se.swedenconnect.id.authCont.x10.generic.AuthenticationContextType;

/**
 * Tests the generic AuthenticationContext report element used for non-XML context types such as OACI.
 */
@Slf4j
class AuthenticationContextElementTest {

  @Test
  void oaciRoundTripThroughGenericElement() throws Exception {
    final OIDCAuthContext oaci = OIDCAuthContext.builder()
      .iss("https://op.example.com")
      .authTime(1792415045L)
      .acr("https://example.com/loa/3")
      .clientId("https://sign.example.com")
      .claimMappings(List.of(
        ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.42").claim("/given_name").build()))
      .build();

    // Build the element the way the report generator does, from an extension entry
    final AuthnContextEntry entry = AuthnContext.fromOidc(List.of(oaci)).getEntries().get(0);
    final AuthenticationContextDocument doc = AuthenticationContextDocument.Factory.newInstance();
    final AuthenticationContextType element = doc.addNewAuthenticationContext();
    element.setContextType(entry.getContextType());
    element.setStringValue(entry.getContextInfo(false));

    final String xml = doc.xmlText();
    log.info("Generic authentication context element:\n{}", xml);
    Assertions.assertTrue(doc.validate(), "element must validate against the schema");
    Assertions.assertTrue(xml.contains("http://id.swedenconnect.se/auth-cont/1.0/generic"));

    // Parse back: the context type and the OACI object survive the XML round trip
    final AuthenticationContextDocument parsed = AuthenticationContextDocument.Factory.parse(xml);
    Assertions.assertEquals(AuthnContext.OACI_CONTEXT_TYPE, parsed.getAuthenticationContext().getContextType());
    Assertions.assertEquals(oaci, OIDCAuthContext.parse(parsed.getAuthenticationContext().getStringValue(), true));
  }

  @Test
  void unknownContextTypeIsCarriedVerbatim() throws Exception {
    final AuthnContextEntry entry = new AuthnContextEntry("urn:example:auth-context:future", "<x>raw & odd</x>");
    final AuthenticationContextDocument doc = AuthenticationContextDocument.Factory.newInstance();
    final AuthenticationContextType element = doc.addNewAuthenticationContext();
    element.setContextType(entry.getContextType());
    element.setStringValue(entry.getContextInfo(false));
    Assertions.assertTrue(doc.validate());
    final AuthenticationContextDocument parsed = AuthenticationContextDocument.Factory.parse(doc.xmlText());
    Assertions.assertEquals("<x>raw & odd</x>", parsed.getAuthenticationContext().getStringValue());
  }

}
