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

package se.swedenconnect.cert.extensions.data.oaci;

import java.math.BigDecimal;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Tests for the OpenID Connect Authentication Context Information (OACI) JSON model.
 */
@Slf4j
public class OIDCAuthContextTest {

  /** The example from the draft, Appendix A.1 */
  public static final String EXAMPLE_JSON = """
    {
      "iss": "https://op.example.com",
      "auth_time": 1792415045,
      "acr": "http://id.example.org/loa/3",
      "amr": ["sc", "pin"],
      "jti": "0f3e2c6a-7b1d-4e4c-9a2e-5d1c2b3a4f60",
      "client_id": "https://sign.example.com",
      "claim_mappings": [
        { "type": "rdn", "ref": "2.5.4.42", "claim": "/given_name" },
        { "type": "rdn", "ref": "2.5.4.4",  "claim": "/family_name" },
        { "type": "rdn", "ref": "2.5.4.5",
          "claim": "/https:~1~1id.example.org~1claims~1personal_identity_number" },
        { "type": "san", "ref": "1",        "claim": "/email" }
      ]
    }
    """;

  private static final JsonMapper MAPPER = JsonMapper.builder().build();

  @Test
  void parseDraftExample() throws Exception {
    for (final boolean strict : new boolean[] { false, true }) {
      final OIDCAuthContext oaci = OIDCAuthContext.parse(EXAMPLE_JSON, strict);
      Assertions.assertEquals("https://op.example.com", oaci.getIss());
      Assertions.assertEquals(1792415045L, oaci.getAuthTime());
      Assertions.assertEquals(Instant.parse("2026-10-19T13:04:05Z"), oaci.getAuthTimeInstant());
      Assertions.assertEquals("http://id.example.org/loa/3", oaci.getAcr());
      Assertions.assertEquals(List.of("sc", "pin"), oaci.getAmr());
      Assertions.assertEquals("0f3e2c6a-7b1d-4e4c-9a2e-5d1c2b3a4f60", oaci.getJti());
      Assertions.assertNull(oaci.getSub());
      Assertions.assertEquals("https://sign.example.com", oaci.getClientId());
      Assertions.assertEquals(4, oaci.getClaimMappings().size());

      final ClaimMapping third = oaci.getClaimMappings().get(2);
      Assertions.assertEquals(AttributeMapping.Type.rdn, third.getType());
      Assertions.assertEquals("2.5.4.5", third.getRef());
      Assertions.assertEquals("/https:~1~1id.example.org~1claims~1personal_identity_number", third.getClaim());
      Assertions.assertNull(third.getSource());
      Assertions.assertEquals(ClaimMapping.Source.id_token, third.getEffectiveSource());

      final ClaimMapping san = oaci.getClaimMappings().get(3);
      Assertions.assertEquals(AttributeMapping.Type.san, san.getType());
      Assertions.assertEquals("1", san.getRef());
    }
  }

  @Test
  void roundTripIsLossless() throws Exception {
    final OIDCAuthContext oaci = OIDCAuthContext.parse(EXAMPLE_JSON, true);
    final String compact = oaci.toJson(false);
    log.info("Compact OACI: {}", compact);
    Assertions.assertFalse(compact.contains("\n"));
    Assertions.assertFalse(compact.contains(": "));

    // Semantically identical to the input and byte-identical after a second round
    final JsonNode expected = MAPPER.readTree(EXAMPLE_JSON);
    Assertions.assertEquals(expected, MAPPER.readTree(compact));
    final OIDCAuthContext reparsed = OIDCAuthContext.parse(compact, true);
    Assertions.assertEquals(oaci, reparsed);
    Assertions.assertEquals(compact, reparsed.toJson(false));

    // Member order follows the specification
    Assertions.assertTrue(compact.indexOf("\"iss\"") < compact.indexOf("\"auth_time\""));
    Assertions.assertTrue(compact.indexOf("\"auth_time\"") < compact.indexOf("\"acr\""));
    Assertions.assertTrue(compact.indexOf("\"acr\"") < compact.indexOf("\"amr\""));
    Assertions.assertTrue(compact.indexOf("\"amr\"") < compact.indexOf("\"jti\""));
    Assertions.assertTrue(compact.indexOf("\"jti\"") < compact.indexOf("\"client_id\""));
    Assertions.assertTrue(compact.indexOf("\"client_id\"") < compact.indexOf("\"claim_mappings\""));

    final String pretty = oaci.toJson(true);
    log.info("Pretty OACI:\n{}", pretty);
    Assertions.assertTrue(pretty.contains("\n"));
    Assertions.assertEquals(expected, MAPPER.readTree(pretty));
  }

  @Test
  void builderProducesValidJson() throws Exception {
    final OIDCAuthContext built = OIDCAuthContext.builder()
      .iss("https://op.example.com")
      .acr("http://id.elegnamnden.se/loa/1.0/loa3")
      .sub("248289761001")
      .clientId("https://sign.example.com")
      .claimMappings(List.of(
        ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.5")
          .claim("/personal_identity_number").source(ClaimMapping.Source.userinfo).build()))
      .build();
    built.setAuthTimeInstant(Instant.parse("2026-10-19T13:04:05Z"));

    final String json = built.toJson(false);
    final OIDCAuthContext parsed = OIDCAuthContext.parse(json, true);
    Assertions.assertEquals(built, parsed);
    Assertions.assertEquals(1792415045L, parsed.getAuthTime());
    Assertions.assertEquals(ClaimMapping.Source.userinfo, parsed.getClaimMappings().get(0).getSource());
    Assertions.assertFalse(json.contains("\"amr\""));
    Assertions.assertFalse(json.contains("\"jti\""));
  }

  @Test
  void additionalMembersAreRetainedInBothModes() throws Exception {
    // Top-level members not defined by the specification are retained and re-emitted after the defined members;
    // unknown members inside a claim mapping are ignored.
    final String json = """
      {"iss":"https://op.example.com","future_member":{"a":[1,2]},"https://example.com/claims/transaction_id":"dc6ac7656H89bfb51",
       "claim_mappings":[{"type":"rdn","ref":"2.5.4.42","claim":"/given_name","note":"x"}]}
      """;
    for (final boolean strict : new boolean[] { false, true }) {
      final OIDCAuthContext oaci = OIDCAuthContext.parse(json, strict);
      Assertions.assertEquals("https://op.example.com", oaci.getIss());
      Assertions.assertEquals(1, oaci.getClaimMappings().size());
      Assertions.assertEquals(2, oaci.getAdditionalMembers().size());
      Assertions.assertEquals(List.of("future_member", "https://example.com/claims/transaction_id"),
        List.copyOf(oaci.getAdditionalMembers().keySet()));
      Assertions.assertEquals("dc6ac7656H89bfb51",
        oaci.getAdditionalMembers().get("https://example.com/claims/transaction_id").asString());

      final String out = oaci.toJson(false);
      Assertions.assertTrue(out.indexOf("\"claim_mappings\"") < out.indexOf("\"future_member\""));
      Assertions.assertFalse(out.contains("\"note\""));
      Assertions.assertEquals(MAPPER.readTree(json.replace(",\"note\":\"x\"", "")), MAPPER.readTree(out));
      Assertions.assertEquals(oaci, OIDCAuthContext.parse(out, strict));
    }
  }

  @Test
  void additionalMemberMustNotCollideWithDefinedMember() throws Exception {
    final OIDCAuthContext oaci = OIDCAuthContext.parse("{\"iss\":\"https://op.example.com\"}", true);
    oaci.setAdditionalMembers(new java.util.LinkedHashMap<>(java.util.Map.of("acr", MAPPER.readTree("\"x\""))));
    Assertions.assertThrows(CertificateException.class, () -> oaci.validate(true));
    // ... and a colliding name is never emitted, even without validation
    Assertions.assertFalse(oaci.toJson(false).contains("acr"));
  }

  @Test
  void lenientModeAcceptsMissingRequirements() throws Exception {
    final OIDCAuthContext oaci = OIDCAuthContext.parse("{\"acr\":\"http://id.example.org/loa/3\"}", false);
    Assertions.assertNull(oaci.getIss());
    Assertions.assertEquals("http://id.example.org/loa/3", oaci.getAcr());
    // ... and the empty object
    Assertions.assertNotNull(OIDCAuthContext.parse("{}", false));
  }

  @Test
  void strictModeEnforcesContentRules() {
    assertRejected(true, "{}", "missing iss");
    assertRejected(true, "{\"iss\":\"http://op.example.com\"}", "iss not https");
    assertRejected(true, "{\"iss\":\"https://op.example.com?x=1\"}", "iss with query");
    assertRejected(true, "{\"iss\":\"https://op.example.com\",\"amr\":[]}", "empty amr");
    assertRejected(true, "{\"iss\":\"https://op.example.com\",\"acr\":\"\"}", "empty acr");
    assertRejected(true, "{\"iss\":\"https://op.example.com\",\"claim_mappings\":[]}", "empty claim_mappings");
    assertRejected(true, "{\"iss\":\"https://op.example.com\",\"auth_time\":-1}", "negative auth_time");
    assertRejected(true, "{\"iss\":\"https://op.example.com\",\"claim_mappings\":[{\"type\":\"rdn\",\"ref\":\"2.5.4.42\"}]}",
      "mapping without claim");
    assertRejected(true, "{\"iss\":\"https://op.example.com\",\"claim_mappings\":[{\"type\":\"rdn\",\"ref\":\"2.5.4.42\",\"claim\":\"given_name\"}]}",
      "claim not a JSON pointer");
    assertRejected(true, "{\"iss\":\"https://op.example.com\",\"claim_mappings\":[{\"type\":\"rdn\",\"ref\":\"2.5.4.42.\",\"claim\":\"/x\"}]}",
      "malformed ref");
    assertRejected(true, "{\"iss\":\"https://op.example.com\",\"claim_mappings\":[{\"ref\":\"2.5.4.42\",\"claim\":\"/x\"}]}",
      "mapping without type");
  }

  @Test
  void malformedContentIsRejectedInBothModes() {
    for (final boolean strict : new boolean[] { false, true }) {
      assertRejected(strict, "[\"https://op.example.com\"]", "top level not an object");
      assertRejected(strict, "\"https://op.example.com\"", "top level string");
      assertRejected(strict, "{\"iss\":\"https://op.example.com\",\"iss\":\"https://other.example.com\"}",
        "duplicate member (I-JSON)");
      assertRejected(strict, "{\"iss\":42}", "iss not a string");
      assertRejected(strict, "{\"auth_time\":\"2026-10-19T13:04:05Z\"}", "auth_time not a number");
      assertRejected(strict, "{\"acr\":[\"a\",\"b\"]}", "acr not a string");
      assertRejected(strict, "{\"amr\":\"sc\"}", "amr not an array");
      assertRejected(strict, "{\"amr\":[\"sc\",1]}", "amr with non-string");
      assertRejected(strict, "{\"claim_mappings\":{}}", "claim_mappings not an array");
      assertRejected(strict, "{\"claim_mappings\":[\"x\"]}", "claim mapping not an object");
      assertRejected(strict, "{\"claim_mappings\":[{\"type\":\"xyz\",\"ref\":\"1\",\"claim\":\"/x\"}]}",
        "unknown mapping type");
      assertRejected(strict, "{\"claim_mappings\":[{\"type\":\"rdn\",\"ref\":\"1\",\"claim\":\"/x\",\"source\":\"token\"}]}",
        "unknown source");
      assertRejected(strict, "{\"iss\":\"https://op.example.com\"", "truncated JSON");
      assertRejected(strict, null, "null input");
    }
  }

  @Test
  void fractionalAuthTimeIsPreserved() throws Exception {
    final OIDCAuthContext oaci = OIDCAuthContext.parse("{\"auth_time\":1792415045.5}", false);
    Assertions.assertTrue(oaci.getAuthTime() instanceof BigDecimal);
    Assertions.assertEquals(Instant.parse("2026-10-19T13:04:05.500Z"), oaci.getAuthTimeInstant());
    Assertions.assertEquals("{\"auth_time\":1792415045.5}", oaci.toJson(false));
  }

  private static void assertRejected(final boolean strict, final String json, final String reason) {
    final CertificateException ex = Assertions.assertThrows(CertificateException.class,
      () -> OIDCAuthContext.parse(json, strict), "Expected rejection (" + reason + ") strict=" + strict);
    log.debug("Rejected as expected ({}, strict={}): {}", reason, strict, ex.getMessage());
  }

}
