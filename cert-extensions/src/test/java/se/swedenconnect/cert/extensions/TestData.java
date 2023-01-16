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

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;

import lombok.SneakyThrows;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import se.swedenconnect.cert.extensions.data.saci.AuthContextInfo;
import se.swedenconnect.cert.extensions.data.saci.IdAttributes;
import se.swedenconnect.cert.extensions.data.saci.SAMLAttribute;
import se.swedenconnect.cert.extensions.data.saci.SAMLAuthContext;
import se.swedenconnect.cert.extensions.utils.DOMUtils;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class TestData {

  public static String authContextCert = "MIILFzCCCr2gAwIBAgIQdBaehTOqOq8PJC/1oimnijAKBggqhkjOPQQDAjCBkTELMAkGA1UEBhMCU0UxLjAsBgNVBAoMJU15bmRpZ2hldGVuIGbDtnIgZGlnaXRhbCBmw7ZydmFsdG5pbmcxHzAdBgNVBAsMFlN3ZWRlbiBjb25uZWN0IHNhbmRib3gxFDASBgNVBGEMCzIwMjEwMC02ODgzMRswGQYDVQQDDBJTaWduIHNlcnZpY2UgQ0EgMDEwHhcNMjMwMTExMTI0NTQ2WhcNMjUwMTEwMTI0NjAxWjB8MRUwEwYDVQQFEwwxOTcwMTA2MzIzOTExCzAJBgNVBAYTAlNFMQ8wDQYDVQQqDAZTaXh0ZW4xHjAcBgNVBAQMFXZvbiBTYW1vcmRudW5nc251bW1lcjElMCMGA1UEAwwcU2l4dGVuIHZvbiBTYW1vcmRudW5nc251bW1lcjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNs/zaN13dlqe5JNxbfUs8KpOmhBcTN/DQywrZBGwTRMwBfYb+Ctp8hF4XB+BFTJBkKWG+VkFlx4cfyB0Zx7uyOjggkJMIIJBTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIGwDBEBgNVHR8EPTA7MDmgN6A1hjNodHRwczovL3NhbmRib3guc3dlZGVuY29ubmVjdC5zZS9zaWdjYS9jcmwvY2EwMS5jcmwwTAYIKwYBBQUHAQEEQDA+MDwGCCsGAQUFBzABhjBodHRwczovL3NhbmRib3guc3dlZGVuY29ubmVjdC5zZS9zaWdjYS9vY3NwL2NhMDEwgghSBgcqhXCBSQUBBIIIRTCCCEEwggg9DCtodHRwOi8vaWQuZWxlZ25hbW5kZW4uc2UvYXV0aC1jb250LzEuMC9zYWNpDIIIDDxTQU1MQXV0aENvbnRleHQgeG1sbnM9Imh0dHA6Ly9pZC5lbGVnbmFtbmRlbi5zZS9hdXRoLWNvbnQvMS4wL3NhY2kiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDphc3NlcnRpb24iPjxBdXRoQ29udGV4dEluZm8gSWRlbnRpdHlQcm92aWRlcj0iaHR0cDovL2Rldi50ZXN0LnN3ZWRlbmNvbm5lY3Quc2UvaWRwIiBBdXRoZW50aWNhdGlvbkluc3RhbnQ9IjIwMjMtMDEtMTFUMTM6NDY6MDAuNDM1KzAxOjAwIiBBdXRobkNvbnRleHRDbGFzc1JlZj0iaHR0cDovL2lkLmVsZWduYW1uZGVuLnNlL2xvYS8xLjAvbG9hMyIgQXNzZXJ0aW9uUmVmPSJfOGRiNmViOWU4ZGMwNDNkNTU0ZWFhMGRhZDE0NWNmZGEiIFNlcnZpY2VJRD0iaHR0cHM6Ly9laWQyY3NzcC4zeGFzZWN1cml0eS5jb20vc2lnbiIvPjxJZEF0dHJpYnV0ZXM+PEF0dHJpYnV0ZU1hcHBpbmcgVHlwZT0icmRuIiBSZWY9IjIuNS40LjUiPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjEuMi43NTIuMjkuNC4xMyIgRnJpZW5kbHlOYW1lPSJwZXJzb25hbElkZW50aXR5TnVtYmVyIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIiB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiPjE5NzAxMDYzMjM5MTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvQXR0cmlidXRlTWFwcGluZz48QXR0cmlidXRlTWFwcGluZyBUeXBlPSJyZG4iIFJlZj0iMi41LjQuNiI+PHNhbWw6QXR0cmlidXRlIEZyaWVuZGx5TmFtZT0iY291bnRyeSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIj5TRTwvc2FtbDpBdHRyaWJ1dGVWYWx1ZT48L3NhbWw6QXR0cmlidXRlPjwvQXR0cmlidXRlTWFwcGluZz48QXR0cmlidXRlTWFwcGluZyBUeXBlPSJyZG4iIFJlZj0iMi41LjQuNDIiPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjIuNS40LjQyIiBGcmllbmRseU5hbWU9ImdpdmVuTmFtZSI+PHNhbWw6QXR0cmlidXRlVmFsdWUgeHNpOnR5cGU9InhzOnN0cmluZyIgeG1sbnM6eHM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hIiB4bWxuczp4c2k9Imh0dHA6Ly93d3cudzMub3JnLzIwMDEvWE1MU2NoZW1hLWluc3RhbmNlIj5TaXh0ZW48L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48L0F0dHJpYnV0ZU1hcHBpbmc+PEF0dHJpYnV0ZU1hcHBpbmcgVHlwZT0icmRuIiBSZWY9IjIuNS40LjQiPjxzYW1sOkF0dHJpYnV0ZSBOYW1lPSJ1cm46b2lkOjIuNS40LjQiIEZyaWVuZGx5TmFtZT0ic24iPjxzYW1sOkF0dHJpYnV0ZVZhbHVlIHhzaTp0eXBlPSJ4czpzdHJpbmciIHhtbG5zOnhzPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYSIgeG1sbnM6eHNpPSJodHRwOi8vd3d3LnczLm9yZy8yMDAxL1hNTFNjaGVtYS1pbnN0YW5jZSI+dm9uIFNhbW9yZG51bmdzbnVtbWVyPC9zYW1sOkF0dHJpYnV0ZVZhbHVlPjwvc2FtbDpBdHRyaWJ1dGU+PC9BdHRyaWJ1dGVNYXBwaW5nPjxBdHRyaWJ1dGVNYXBwaW5nIFR5cGU9InJkbiIgUmVmPSIyLjUuNC4zIj48c2FtbDpBdHRyaWJ1dGUgTmFtZT0idXJuOm9pZDoyLjE2Ljg0MC4xLjExMzczMC4zLjEuMjQxIiBGcmllbmRseU5hbWU9ImRpc3BsYXlOYW1lIj48c2FtbDpBdHRyaWJ1dGVWYWx1ZSB4c2k6dHlwZT0ieHM6c3RyaW5nIiB4bWxuczp4cz0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEiIHhtbG5zOnhzaT0iaHR0cDovL3d3dy53My5vcmcvMjAwMS9YTUxTY2hlbWEtaW5zdGFuY2UiPlNpeHRlbiB2b24gU2Ftb3JkbnVuZ3NudW1tZXI8L3NhbWw6QXR0cmlidXRlVmFsdWU+PC9zYW1sOkF0dHJpYnV0ZT48L0F0dHJpYnV0ZU1hcHBpbmc+PC9JZEF0dHJpYnV0ZXM+PC9TQU1MQXV0aENvbnRleHQ+MAoGCCqGSM49BAMCA0gAMEUCIDWcOtjqXvA8duel9OBsWpZB9GpAAElZu6FJHcPqVg1QAiEAk7p++5d6bAcd8Kf4uJHo8mMSP5dl8FA7qA7iU2RLyEs=";

  public static String samlAuthContextXml = "<SAMLAuthContext xmlns=\"http://id.elegnamnden.se/auth-cont/1.0/saci\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><AuthContextInfo IdentityProvider=\"http://dev.test.swedenconnect.se/idp\" AuthenticationInstant=\"2023-01-11T13:46:00.435+01:00\" AuthnContextClassRef=\"http://id.elegnamnden.se/loa/1.0/loa3\" AssertionRef=\"_8db6eb9e8dc043d554eaa0dad145cfda\" ServiceID=\"https://eid2cssp.3xasecurity.com/sign\"/><IdAttributes><AttributeMapping Type=\"rdn\" Ref=\"2.5.4.5\"><saml:Attribute Name=\"urn:oid:1.2.752.29.4.13\" FriendlyName=\"personalIdentityNumber\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">197010632391</saml:AttributeValue></saml:Attribute></AttributeMapping><AttributeMapping Type=\"rdn\" Ref=\"2.5.4.6\"><saml:Attribute FriendlyName=\"country\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">SE</saml:AttributeValue></saml:Attribute></AttributeMapping><AttributeMapping Type=\"rdn\" Ref=\"2.5.4.42\"><saml:Attribute Name=\"urn:oid:2.5.4.42\" FriendlyName=\"givenName\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Sixten</saml:AttributeValue></saml:Attribute></AttributeMapping><AttributeMapping Type=\"rdn\" Ref=\"2.5.4.4\"><saml:Attribute Name=\"urn:oid:2.5.4.4\" FriendlyName=\"sn\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">von Samordnungsnummer</saml:AttributeValue></saml:Attribute></AttributeMapping><AttributeMapping Type=\"rdn\" Ref=\"2.5.4.3\"><saml:Attribute Name=\"urn:oid:2.16.840.1.113730.3.1.241\" FriendlyName=\"displayName\"><saml:AttributeValue xsi:type=\"xs:string\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">Sixten von Samordnungsnummer</saml:AttributeValue></saml:Attribute></AttributeMapping></IdAttributes></SAMLAuthContext>\n";

  public static AuthnContext getTestContext(boolean strictMode) throws Exception {
    SAMLAuthContext authContext = new SAMLAuthContext(strictMode);
    authContext.setAuthContextInfo(getAuthContextInfo());

    IdAttributes idAttributes = new IdAttributes();
    List<AttributeMapping> attributeMappings = new ArrayList<>();
    addValidAttrMappings(attributeMappings);
    idAttributes.setAttributeMappings(attributeMappings);
    authContext.setIdAttributes(idAttributes);

    return new AuthnContext(List.of(authContext));
  }

  private static void addValidAttrMappings(List<AttributeMapping> attributeMappings) {
    attributeMappings.add(
      createAttributeMapping("urn:oid:1.2.752.29.4.13", AttributeMapping.Type.rdn, "2.5.4.5", "123123123"));
    attributeMappings.add(createAttributeMapping("default", AttributeMapping.Type.rdn, "2.5.4.6", "SE"));
    attributeMappings.add(createAttributeMapping("urn:oid:2.5.4.42", AttributeMapping.Type.rdn, "2.5.4.42", "Majlis"));
    attributeMappings.add(createAttributeMapping("urn:oid:2.5.4.4", AttributeMapping.Type.rdn, "2.5.4.4", "Medin"));
    attributeMappings.add(
      createAttributeMapping("urn:oid:2.16.840.1.113730.3.1.241", AttributeMapping.Type.rdn, "2.5.4.3",
        "Majlis Medin"));
  }

  private static AuthContextInfo getAuthContextInfo() throws Exception {
    AuthContextInfo authContextInfo = new AuthContextInfo();
    authContextInfo.setIdentityProvider("http://example.com/idp");
    authContextInfo.setAuthnContextClassRef("http://example.com/loa");
    authContextInfo.setAssertionRef("_123123123");
    authContextInfo.setAuthenticationInstant(Instant.now());
    authContextInfo.setServiceID("service");
    return authContextInfo;
  }

  @SneakyThrows
  private static AttributeMapping createAttributeMapping(String samlName, AttributeMapping.Type type, String ref,
    String val) {
    AttributeMapping mapping = new AttributeMapping();
    mapping.setType(type);
    mapping.setRef(ref);

    SAMLAttribute attribute = new SAMLAttribute();
    attribute.setName(samlName);
    attribute.setAttributeValues(List.of(SAMLAttribute.createStringAttributeValue(val)));
    mapping.setAttribute(attribute);
    return mapping;
  }

}
