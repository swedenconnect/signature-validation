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

import org.junit.jupiter.api.Test;
import se.swedenconnect.sigval.commons.data.SigValIdentifiers;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link PublicKeyType}.
 */
class PublicKeyTypeTest {

  @Test
  void getTypeFromOid_ecdsaOid_returnsEC() {
    PublicKeyType type = PublicKeyType.getTypeFromOid(SigValIdentifiers.ID_ECDSA);
    assertEquals(PublicKeyType.EC, type);
  }

  @Test
  void getTypeFromOid_rsaOid_returnsRSA() {
    PublicKeyType type = PublicKeyType.getTypeFromOid(SigValIdentifiers.ID_RSA);
    assertEquals(PublicKeyType.RSA, type);
  }

  @Test
  void getTypeFromOid_ecdsaOidUpperCase_returnsECCaseInsensitive() {
    String upperCaseOid = SigValIdentifiers.ID_ECDSA.toUpperCase();
    PublicKeyType type = PublicKeyType.getTypeFromOid(upperCaseOid);
    assertEquals(PublicKeyType.EC, type);
  }

  @Test
  void ec_getObjectId_returnsEcdsaOid() {
    assertEquals(SigValIdentifiers.ID_ECDSA, PublicKeyType.EC.getObjectId());
  }

  @Test
  void rsa_getObjectId_returnsRsaOid() {
    assertEquals(SigValIdentifiers.ID_RSA, PublicKeyType.RSA.getObjectId());
  }

  @Test
  void unknown_getObjectId_returnsNull() {
    assertNull(PublicKeyType.Unknown.getObjectId());
  }
}
