/*
 * Copyright 2021-2025 Sweden Connect
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
package se.swedenconnect.cert.extensions.utils;

import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link ExtensionUtils}.
 */
class ExtensionUtilsTest {

  @Test
  void getGeneralNameStr_null_returnsNullString() {
    assertEquals("null", ExtensionUtils.getGeneralNameStr(null));
  }

  @Test
  void getGeneralNameStr_dnsName_startWithDNS() {
    GeneralName dns = new GeneralName(GeneralName.dNSName, "example.com");
    String result = ExtensionUtils.getGeneralNameStr(dns);
    assertTrue(result.startsWith("DNS"), "Expected DNS prefix, got: " + result);
    assertTrue(result.contains("example.com"));
  }

  @Test
  void getGeneralNameStr_email_startWithEMail() {
    GeneralName email = new GeneralName(GeneralName.rfc822Name, "user@example.com");
    String result = ExtensionUtils.getGeneralNameStr(email);
    assertTrue(result.startsWith("E-Mail"), "Expected E-Mail prefix, got: " + result);
    assertTrue(result.contains("user@example.com"));
  }

  @Test
  void getGeneralNameStr_uri_startWithURI() {
    GeneralName uri = new GeneralName(GeneralName.uniformResourceIdentifier, "http://example.com");
    String result = ExtensionUtils.getGeneralNameStr(uri);
    assertTrue(result.startsWith("URI"), "Expected URI prefix, got: " + result);
    assertTrue(result.contains("http://example.com"));
  }

  @Test
  void getGeneralNameStr_ipAddress_startWithIPAddress() {
    // IP address in GeneralName must be raw 4-byte or 16-byte DER
    GeneralName ip = new GeneralName(GeneralName.iPAddress, "192.168.1.1");
    String result = ExtensionUtils.getGeneralNameStr(ip);
    assertTrue(result.startsWith("IP Address"), "Expected IP Address prefix, got: " + result);
  }

  @Test
  void getGeneralNameStr_containsTagSeparator() {
    // The format after tag replacement is "DisplayName: value"
    GeneralName dns = new GeneralName(GeneralName.dNSName, "test.local");
    String result = ExtensionUtils.getGeneralNameStr(dns);
    assertTrue(result.contains(":"), "Result should contain ':' separator: " + result);
  }
}
