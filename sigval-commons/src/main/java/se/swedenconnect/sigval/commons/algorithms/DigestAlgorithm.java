/*
 * Copyright (c) 2020. IDsec Solutions AB
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

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.xml.security.algorithms.MessageDigestAlgorithm;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.operator.AlgorithmNameFinder;
import org.bouncycastle.operator.DefaultAlgorithmNameFinder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * This class stores data about a digest algorithm
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
public class DigestAlgorithm {
  /** Finder for converting OIDs and AlgorithmIdentifiers into strings. */
  private static AlgorithmNameFinder algorithmNameFinder = new DefaultAlgorithmNameFinder();

  /** SHA-1 ID */
  public static final String ID_SHA1 = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA1;
  /** SHA-1 OID */
  public static final ASN1ObjectIdentifier OID_SHA1 = OIWObjectIdentifiers.idSHA1;

  /** SHA224 ID */
  public static final String ID_SHA224 = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA224;
  /** SHA224 OID */
  public static final ASN1ObjectIdentifier OID_SHA224 = NISTObjectIdentifiers.id_sha224;

  /** SHA256 ID */
  public static final String ID_SHA256 = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA256;
  /** SHA256 OID */
  public static final ASN1ObjectIdentifier OID_SHA256 = NISTObjectIdentifiers.id_sha256;

  /** SHA384 ID */
  public static final String ID_SHA384 = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_384;
  /** SHA384 OID */
  public static final ASN1ObjectIdentifier OID_SHA384 = NISTObjectIdentifiers.id_sha384;

  /** SHA512 ID */
  public static final String ID_SHA512 = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA512;
  /** SHA512 OID */
  public static final ASN1ObjectIdentifier OID_SHA512 = NISTObjectIdentifiers.id_sha512;

  /** SHA3-224 ID */
  public static final String ID_SHA3_224 = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_224;
  /** SHA3-224 OID */
  public static final ASN1ObjectIdentifier OID_SHA3_224 = NISTObjectIdentifiers.id_sha3_224;

  /** SHA3-256 ID */
  public static final String ID_SHA3_256 = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_256;
  /** SHA3-256 OID */
  public static final ASN1ObjectIdentifier OID_SHA3_256 = NISTObjectIdentifiers.id_sha3_256;

  /** SHA3-384 ID */
  public static final String ID_SHA3_384 = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_384;
  /** SHA3-384 OID */
  public static final ASN1ObjectIdentifier OID_SHA3_384 = NISTObjectIdentifiers.id_sha3_384;

  /** SHA3-512 ID */
  public static final String ID_SHA3_512 = MessageDigestAlgorithm.ALGO_ID_DIGEST_SHA3_512;
  /** SHA3-512 OID */
  public static final ASN1ObjectIdentifier OID_SHA3_512 = NISTObjectIdentifiers.id_sha3_512;

  /**
   * URI identifier of the digest algorithm
   *
   * @return URI identifier of the digest algorithm
   */
  @Getter private final String uri;
  /**
   * OID identifier of the digest algorithm
   *
   * @return OID identifier of the digest algorithm
   */
  @Getter private final ASN1ObjectIdentifier oid;

  /**
   * Get a {@link MessageDigest} instance of the digest algorithm
   *
   * @return a {@link MessageDigest} instance of the digest algorithm
   * @throws NoSuchAlgorithmException if the requested diegest algorithm is not available
   */
  public MessageDigest getInstance() throws NoSuchAlgorithmException {
    return MessageDigest.getInstance(algorithmNameFinder.getAlgorithmName(oid));
  }

}
