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

import java.io.ByteArrayInputStream;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.cert.extensions.data.oaci.ClaimMapping;
import se.swedenconnect.cert.extensions.data.oaci.OIDCAuthContext;
import se.swedenconnect.cert.extensions.data.oaci.OIDCAuthContextTest;
import se.swedenconnect.cert.extensions.data.saci.Attribute;
import se.swedenconnect.cert.extensions.data.saci.AttributeMapping;
import se.swedenconnect.cert.extensions.data.saci.SAMLAuthContext;

/**
 * Testing AuthContext DOM implementation
 */
@Slf4j
class AuthnContextTest {

  private static final String UNKNOWN_TYPE = "urn:example:auth-context:future";
  private static final String UNKNOWN_INFO = "{\"anything\":[1,2,3]}";

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
    Attribute attribute = attributeMapping.getAttribute();
    Element attrVal = attribute.getAttributeValues().get(0);
    NamedNodeMap attributes = attrVal.getAttributes();
    Assertions.assertEquals(3, attributes.getLength());
    String textContent = attrVal.getTextContent();
    Assertions.assertEquals("197010632391", textContent);

    Element newValue = Attribute.createStringAttributeValue("1234209871934789");
    String newTextContent = newValue.getTextContent();
    Assertions.assertEquals("1234209871934789", newTextContent);
    NamedNodeMap newAttrNodeMap = newValue.getAttributes();
    Assertions.assertEquals(3, newAttrNodeMap.getLength());

    attribute.setAttributeValues(List.of(newValue));
    String xmlPrint3 = AuthnContext.printAuthnContext(samlAuthnContext, false);
  }

  @Test
  void legacySaciApiIsPreserved() throws Exception {
    // The existing test certificate carries a SACI entry
    final X509Certificate cert = (X509Certificate) CertificateFactory.getInstance("X.509")
      .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(TestData.authContextCert)));
    // The no-flag factory is strict; the real test certificate is parsed leniently as its SACI content predates the
    // strict rules applied here, and the purpose of the test is the legacy accessor API.
    final AuthnContext authnContext = AuthnContext.fromExtensions(new JcaX509CertificateHolder(cert).getExtensions(), false);

    @SuppressWarnings("deprecation")
    final List<SAMLAuthContext> legacy = authnContext.getStatementInfoList();
    Assertions.assertEquals(1, legacy.size());
    Assertions.assertEquals(1, authnContext.getSamlAuthContexts().size());
    Assertions.assertTrue(authnContext.getOidcAuthContexts().isEmpty());
    Assertions.assertEquals(1, authnContext.getEntries().size());
    Assertions.assertEquals(authnContext.SACI_CONTEXT_TYPE, authnContext.getEntries().get(0).getContextType());
    Assertions.assertNotNull(authnContext.getEntries().get(0).getRawContextInfo());
    Assertions.assertEquals("http://id.elegnamnden.se/loa/1.0/loa3",
      legacy.get(0).getAuthContextInfo().getAuthnContextClassRef());

    // The legacy constructor still works and round-trips
    final AuthnContext built = TestData.getTestContext(true);
    final AuthnContext reparsed = authnContext.getInstance(built.toASN1Primitive().getEncoded(), false);
    Assertions.assertEquals(1, reparsed.getSamlAuthContexts().size());
    log.info("Legacy SACI extension:\n{}", reparsed);
  }

  @Test
  void oaciRoundTrip() throws Exception {
    final OIDCAuthContext oaci = OIDCAuthContext.parse(OIDCAuthContextTest.EXAMPLE_JSON, true);
    final AuthnContext built = AuthnContext.fromOidc(List.of(oaci));
    final byte[] encoded = built.toASN1Primitive().getEncoded();

    // Encoded form: one entry, correct type URI, compact JSON
    final ASN1Sequence seq = ASN1Sequence.getInstance(encoded);
    Assertions.assertEquals(1, seq.size());
    final ASN1Sequence entry = ASN1Sequence.getInstance(seq.getObjectAt(0));
    Assertions.assertEquals(AuthnContext.OACI_CONTEXT_TYPE, DERUTF8String.getInstance(entry.getObjectAt(0)).getString());
    Assertions.assertEquals(oaci.toJson(false), DERUTF8String.getInstance(entry.getObjectAt(1)).getString());

    for (final boolean strict : new boolean[] { false, true }) {
      final AuthnContext parsed = AuthnContext.getInstance(encoded, strict);
      Assertions.assertEquals(1, parsed.getOidcAuthContexts().size());
      Assertions.assertTrue(parsed.getSamlAuthContexts().isEmpty());
      Assertions.assertEquals(oaci, parsed.getOidcAuthContexts().get(0));
      Assertions.assertTrue(parsed.getEntries().get(0).isOidc());
      Assertions.assertArrayEquals(encoded, parsed.toASN1Primitive().getEncoded());
    }
    log.info("OACI extension:\n{}", AuthnContext.getInstance(encoded));
  }

  @Test
  void oaciBuiltWithBuilder() throws Exception {
    final OIDCAuthContext oaci = OIDCAuthContext.builder()
      .iss("https://op.example.com")
      .authTime(1792415045L)
      .acr("http://id.elegnamnden.se/loa/1.0/loa3")
      .clientId("https://sign.example.com")
      .claimMappings(List.of(
        ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.5").claim("/personal_identity_number").build(),
        ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.42").claim("/given_name").build(),
        ClaimMapping.builder().type(AttributeMapping.Type.rdn).ref("2.5.4.4").claim("/family_name").build()))
      .build();
    final AuthnContext parsed = AuthnContext.getInstance(
      AuthnContext.fromOidc(List.of(oaci)).toASN1Primitive().getEncoded(), true);
    Assertions.assertEquals(oaci, parsed.getOidcAuthContexts().get(0));
  }

  @Test
  void unsupportedContextTypesAreIgnoredAndRetained() throws Exception {
    // An extension with a SACI entry, an unknown entry with content, and an unknown entry without contextInfo
    final String saciXml = AuthnContext.printAuthnContext(TestData.getTestContext(true).getSamlAuthContexts().get(0), false);
    final ASN1EncodableVector contexts = new ASN1EncodableVector();
    contexts.add(seq(AuthnContext.SACI_CONTEXT_TYPE, saciXml));
    contexts.add(seq(UNKNOWN_TYPE, UNKNOWN_INFO));
    contexts.add(seq(UNKNOWN_TYPE + ":empty", null));
    final byte[] encoded = new DERSequence(contexts).getEncoded();

    for (final boolean strict : new boolean[] { false, true }) {
      final AuthnContext parsed = AuthnContext.getInstance(encoded, strict);
      Assertions.assertEquals(3, parsed.getEntries().size());
      Assertions.assertEquals(1, parsed.getSamlAuthContexts().size());
      Assertions.assertTrue(parsed.getOidcAuthContexts().isEmpty());

      final AuthnContextEntry unknown = parsed.getEntries().get(1);
      Assertions.assertFalse(unknown.isSaml());
      Assertions.assertFalse(unknown.isOidc());
      Assertions.assertNull(unknown.getParsed());
      Assertions.assertEquals(UNKNOWN_TYPE, unknown.getContextType());
      Assertions.assertEquals(UNKNOWN_INFO, unknown.getRawContextInfo());
      Assertions.assertEquals(UNKNOWN_INFO, unknown.getContextInfo(false));

      final AuthnContextEntry empty = parsed.getEntries().get(2);
      Assertions.assertNull(empty.getRawContextInfo());
      Assertions.assertNull(empty.getContextInfo(false));
      log.info("Mixed extension (strict={}):\n{}", strict, parsed);
    }

    // An extension consisting only of unknown entries re-encodes byte for byte
    final ASN1EncodableVector unknownOnly = new ASN1EncodableVector();
    unknownOnly.add(seq(UNKNOWN_TYPE, UNKNOWN_INFO));
    unknownOnly.add(seq(UNKNOWN_TYPE + ":empty", null));
    final byte[] unknownEncoded = new DERSequence(unknownOnly).getEncoded();
    final AuthnContext parsedUnknown = AuthnContext.getInstance(unknownEncoded, true);
    Assertions.assertTrue(parsedUnknown.getSamlAuthContexts().isEmpty());
    Assertions.assertTrue(parsedUnknown.getOidcAuthContexts().isEmpty());
    Assertions.assertArrayEquals(unknownEncoded, parsedUnknown.toASN1Primitive().getEncoded());

    // ... and can be constructed directly from entries
    final AuthnContext fromEntries = AuthnContext.fromEntries(List.of(
      new AuthnContextEntry(UNKNOWN_TYPE, UNKNOWN_INFO),
      new AuthnContextEntry(UNKNOWN_TYPE + ":empty", null)));
    Assertions.assertArrayEquals(unknownEncoded, fromEntries.toASN1Primitive().getEncoded());
  }

  @Test
  void malformedSupportedTypeIsRejected() throws Exception {
    final byte[] badOaci = new DERSequence(seq(AuthnContext.OACI_CONTEXT_TYPE, "not json")).getEncoded();
    final byte[] badSaci = new DERSequence(seq(AuthnContext.SACI_CONTEXT_TYPE, "<not-saci/>")).getEncoded();
    final byte[] missingInfo = new DERSequence(seq(AuthnContext.OACI_CONTEXT_TYPE, null)).getEncoded();
    for (final boolean strict : new boolean[] { false, true }) {
      Assertions.assertThrows(IllegalArgumentException.class, () -> AuthnContext.getInstance(badOaci, strict));
      Assertions.assertThrows(IllegalArgumentException.class, () -> AuthnContext.getInstance(badSaci, strict));
      Assertions.assertThrows(IllegalArgumentException.class, () -> AuthnContext.getInstance(missingInfo, strict));
    }

    // Content rule violations are only rejected in strict mode
    final byte[] lenientOnly = new DERSequence(seq(AuthnContext.OACI_CONTEXT_TYPE, "{\"acr\":\"x\"}")).getEncoded();
    Assertions.assertEquals(1, AuthnContext.getInstance(lenientOnly, false).getOidcAuthContexts().size());
    Assertions.assertThrows(IllegalArgumentException.class, () -> AuthnContext.getInstance(lenientOnly, true));
  }

  private static DERSequence seq(final String contextType, final String contextInfo) {
    final ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new DERUTF8String(contextType));
    if (contextInfo != null) {
      v.add(new DERUTF8String(contextInfo));
    }
    return new DERSequence(v);
  }

}
