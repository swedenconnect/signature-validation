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
package se.swedenconnect.sigval.commons.algorithms;

import com.nimbusds.jose.JWSAlgorithm;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link JWSAlgorithmRegistry}.
 */
class JWSAlgorithmRegistryTest {

  @Test
  void getByUri_ecdsaSha256_returnsES256() throws NoSuchAlgorithmException {
    JWSAlgorithm algo = JWSAlgorithmRegistry.get(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256);
    assertEquals(JWSAlgorithm.ES256, algo);
  }

  @Test
  void getByUri_ecdsaSha384_returnsES384() throws NoSuchAlgorithmException {
    JWSAlgorithm algo = JWSAlgorithmRegistry.get(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA384);
    assertEquals(JWSAlgorithm.ES384, algo);
  }

  @Test
  void getByUri_ecdsaSha512_returnsES512() throws NoSuchAlgorithmException {
    JWSAlgorithm algo = JWSAlgorithmRegistry.get(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA512);
    assertEquals(JWSAlgorithm.ES512, algo);
  }

  @Test
  void getByUri_rsaSha256_returnsRS256() throws NoSuchAlgorithmException {
    JWSAlgorithm algo = JWSAlgorithmRegistry.get(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256);
    assertEquals(JWSAlgorithm.RS256, algo);
  }

  @Test
  void getByUri_rsaSha384_returnsRS384() throws NoSuchAlgorithmException {
    JWSAlgorithm algo = JWSAlgorithmRegistry.get(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA384);
    assertEquals(JWSAlgorithm.RS384, algo);
  }

  @Test
  void getByUri_rsaSha512_returnsRS512() throws NoSuchAlgorithmException {
    JWSAlgorithm algo = JWSAlgorithmRegistry.get(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512);
    assertEquals(JWSAlgorithm.RS512, algo);
  }

  @Test
  void getByUri_null_throwsNoSuchAlgorithmException() {
    assertThrows(NoSuchAlgorithmException.class, () -> JWSAlgorithmRegistry.get((String) null));
  }

  @Test
  void getByUri_unknownUri_throwsNoSuchAlgorithmException() {
    assertThrows(NoSuchAlgorithmException.class,
        () -> JWSAlgorithmRegistry.get("http://unknown.example.com/sig"));
  }

  @Test
  void getUri_es256_returnsEcdsaSha256Uri() throws NoSuchAlgorithmException {
    String uri = JWSAlgorithmRegistry.getUri(JWSAlgorithm.ES256);
    assertEquals(XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, uri);
  }

  @Test
  void getUri_rs512_returnsRsaSha512Uri() throws NoSuchAlgorithmException {
    String uri = JWSAlgorithmRegistry.getUri(JWSAlgorithm.RS512);
    assertEquals(XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA512, uri);
  }

  @Test
  void getUri_null_throwsNoSuchAlgorithmException() {
    assertThrows(NoSuchAlgorithmException.class, () -> JWSAlgorithmRegistry.getUri(null));
  }

  @Test
  void getUri_unregisteredAlgorithm_throwsNoSuchAlgorithmException() {
    assertThrows(NoSuchAlgorithmException.class,
        () -> JWSAlgorithmRegistry.getUri(JWSAlgorithm.PS256));
  }

  @Test
  void register_existingUri_returnsFalse() {
    boolean result = JWSAlgorithmRegistry.register(
        XMLSignature.ALGO_ID_SIGNATURE_ECDSA_SHA256, JWSAlgorithm.ES256);
    assertFalse(result);
  }

  @Test
  void register_newUri_returnsTrue() throws NoSuchAlgorithmException {
    String newUri = "http://test.example.com/sig/unique-" + System.nanoTime();
    boolean result = JWSAlgorithmRegistry.register(newUri, JWSAlgorithm.PS256);
    assertTrue(result);
    assertEquals(JWSAlgorithm.PS256, JWSAlgorithmRegistry.get(newUri));
  }
}
