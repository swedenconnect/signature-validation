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

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link DigestAlgorithmRegistry}.
 */
class DigestAlgorithmRegistryTest {

  @Test
  void getByUri_sha1_returnsMatchingAlgorithm() throws NoSuchAlgorithmException {
    DigestAlgorithm algo = DigestAlgorithmRegistry.get(DigestAlgorithm.ID_SHA1);
    assertEquals(DigestAlgorithm.ID_SHA1, algo.getUri());
    assertEquals(DigestAlgorithm.OID_SHA1, algo.getOid());
  }

  @Test
  void getByUri_sha256_returnsMatchingAlgorithm() throws NoSuchAlgorithmException {
    DigestAlgorithm algo = DigestAlgorithmRegistry.get(DigestAlgorithm.ID_SHA256);
    assertEquals(DigestAlgorithm.ID_SHA256, algo.getUri());
    assertEquals(DigestAlgorithm.OID_SHA256, algo.getOid());
  }

  @Test
  void getByUri_sha512_returnsMatchingAlgorithm() throws NoSuchAlgorithmException {
    DigestAlgorithm algo = DigestAlgorithmRegistry.get(DigestAlgorithm.ID_SHA512);
    assertEquals(DigestAlgorithm.ID_SHA512, algo.getUri());
    assertEquals(DigestAlgorithm.OID_SHA512, algo.getOid());
  }

  @Test
  void getByUri_sha3_256_returnsMatchingAlgorithm() throws NoSuchAlgorithmException {
    DigestAlgorithm algo = DigestAlgorithmRegistry.get(DigestAlgorithm.ID_SHA3_256);
    assertEquals(DigestAlgorithm.ID_SHA3_256, algo.getUri());
    assertEquals(DigestAlgorithm.OID_SHA3_256, algo.getOid());
  }

  @Test
  void getByUri_sha3_512_returnsMatchingAlgorithm() throws NoSuchAlgorithmException {
    DigestAlgorithm algo = DigestAlgorithmRegistry.get(DigestAlgorithm.ID_SHA3_512);
    assertEquals(DigestAlgorithm.ID_SHA3_512, algo.getUri());
    assertEquals(DigestAlgorithm.OID_SHA3_512, algo.getOid());
  }

  @Test
  void getByUri_nullUri_throwsNoSuchAlgorithmException() {
    assertThrows(NoSuchAlgorithmException.class, () -> DigestAlgorithmRegistry.get((String) null));
  }

  @Test
  void getByUri_unknownUri_throwsNoSuchAlgorithmException() {
    assertThrows(NoSuchAlgorithmException.class,
        () -> DigestAlgorithmRegistry.get("http://unknown.example.com/digest"));
  }

  @Test
  void getByOid_sha1_returnsMatchingAlgorithm() throws NoSuchAlgorithmException {
    DigestAlgorithm algo = DigestAlgorithmRegistry.get(DigestAlgorithm.OID_SHA1);
    assertEquals(DigestAlgorithm.OID_SHA1, algo.getOid());
  }

  @Test
  void getByOid_sha256_returnsMatchingAlgorithm() throws NoSuchAlgorithmException {
    DigestAlgorithm algo = DigestAlgorithmRegistry.get(DigestAlgorithm.OID_SHA256);
    assertEquals(DigestAlgorithm.OID_SHA256, algo.getOid());
  }

  @Test
  void getByOid_sha512_returnsMatchingAlgorithm() throws NoSuchAlgorithmException {
    DigestAlgorithm algo = DigestAlgorithmRegistry.get(DigestAlgorithm.OID_SHA512);
    assertEquals(DigestAlgorithm.OID_SHA512, algo.getOid());
  }

  @Test
  void getByOid_nullOid_throwsNoSuchAlgorithmException() {
    assertThrows(NoSuchAlgorithmException.class,
        () -> DigestAlgorithmRegistry.get((ASN1ObjectIdentifier) null));
  }

  @Test
  void getByOid_unknownOid_throwsNoSuchAlgorithmException() {
    ASN1ObjectIdentifier unknownOid = new ASN1ObjectIdentifier("1.2.3.4.5.99999");
    assertThrows(NoSuchAlgorithmException.class, () -> DigestAlgorithmRegistry.get(unknownOid));
  }

  @Test
  void registerDigestAlgorithm_existingUri_returnsFalse() {
    boolean result = DigestAlgorithmRegistry.registerDigestAlgorithm(
        DigestAlgorithm.ID_SHA256, DigestAlgorithm.OID_SHA256);
    assertFalse(result);
  }

  @Test
  void registerDigestAlgorithm_newUri_returnsTrue() throws NoSuchAlgorithmException {
    String newUri = "http://test.example.com/digest/unique-" + System.nanoTime();
    ASN1ObjectIdentifier newOid = new ASN1ObjectIdentifier("1.2.3.4.5." + System.nanoTime() % 100000);
    boolean result = DigestAlgorithmRegistry.registerDigestAlgorithm(newUri, newOid);
    assertTrue(result);
    // Verify it is retrievable
    DigestAlgorithm algo = DigestAlgorithmRegistry.get(newUri);
    assertEquals(newUri, algo.getUri());
    assertEquals(newOid, algo.getOid());
  }
}
