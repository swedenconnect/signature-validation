/*
 * Copyright (c) 2026.  Sweden Connect
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

import lombok.Getter;
import lombok.Setter;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1UTF8String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.jcajce.util.MessageDigestUtils;
import org.bouncycastle.util.encoders.Hex;

import java.util.Objects;

/**
 * The {@code SignedDocumentBinding} certificate extension.
 *
 * <p>
 * This extension binds a certificate to a specific signed content, and its presence is the signal by which a relying
 * party recognizes the certificate as a one signature certificate, as defined in
 * {@code draft-ietf-lamps-one-signature-certs}. Adding this extension is a statement by the CA that the signing key was
 * generated exclusively for signing the bound document and was destroyed after signing.
 * </p>
 *
 * <p>
 * The ASN.1 syntax is:
 * </p>
 *
 * <pre>
 * SignedDocumentBinding ::= SEQUENCE {
 *     dataTbsHash     OCTET STRING,
 *     hashAlg         DigestAlgorithmIdentifier,
 *     bindingType     UTF8String OPTIONAL }
 * </pre>
 *
 * <p>
 * The extension is identified by the OID {@code 1.3.6.1.5.5.7.1.37} ({@code id-pe 37}) and is intended to be marked
 * non-critical.
 * </p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class SignedDocumentBinding extends ASN1Object {

  /** The OID of the signedDocumentBinding extension: {@code 1.3.6.1.5.5.7.1.37} ({@code id-pe 37}). */
  public static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.37");

  /** The hash of the data to be signed, binding this certificate to that content. */
  @Getter @Setter
  private byte[] dataTbsHash;

  /** The algorithm identifier of the hash algorithm used to produce {@link #dataTbsHash}. */
  @Getter @Setter
  private AlgorithmIdentifier hashAlg;

  /**
   * Optional identifier specifying how {@link #dataTbsHash} is derived from the signed document. A {@code null} value
   * means the default binding applies.
   */
  @Getter @Setter
  private String bindingType;

  /**
   * Parses an object into a {@link SignedDocumentBinding}.
   *
   * @param obj an existing {@link SignedDocumentBinding}, or an encoding of the extension value (e.g. a {@code byte[]}
   *          or an {@link ASN1Sequence})
   * @return the {@link SignedDocumentBinding}
   * @throws IllegalArgumentException if {@code obj} is {@code null} or cannot be parsed
   */
  public static SignedDocumentBinding getInstance(final Object obj) {
    if (obj instanceof SignedDocumentBinding) {
      return (SignedDocumentBinding) obj;
    }
    if (obj != null) {
      return new SignedDocumentBinding(ASN1Sequence.getInstance(obj));
    }
    throw new IllegalArgumentException("Invalid object: " + obj);
  }

  /**
   * Decodes a {@link SignedDocumentBinding} from its ASN.1 SEQUENCE.
   *
   * @param seq the ASN.1 SEQUENCE holding the extension value
   * @throws IllegalArgumentException if the sequence does not have two or three elements, or if any element has an
   *           unexpected type
   */
  private SignedDocumentBinding(final ASN1Sequence seq) {
    if (seq.size() < 2 || seq.size() > 3) {
      throw new IllegalArgumentException("Bad SignedDocumentBinding sequence size: " + seq.size());
    }
    this.dataTbsHash = ASN1OctetString.getInstance(seq.getObjectAt(0)).getOctets();
    this.hashAlg = AlgorithmIdentifier.getInstance(seq.getObjectAt(1));
    if (seq.size() == 3) {
      this.bindingType = ASN1UTF8String.getInstance(seq.getObjectAt(2)).getString();
    }
  }

  /** Creates an empty instance; populate the fields via the setters before encoding. */
  public SignedDocumentBinding() {
  }

  /**
   * Creates a fully populated instance.
   *
   * @param dataTbsHash the hash of the data to be signed
   * @param hashAlg the hash algorithm identifier
   * @param bindingType the binding type identifier, or {@code null} for the default binding
   */
  public SignedDocumentBinding(final byte[] dataTbsHash, final AlgorithmIdentifier hashAlg,
      final String bindingType) {
    this.dataTbsHash = dataTbsHash;
    this.hashAlg = hashAlg;
    this.bindingType = bindingType;
  }

  /**
   * Encodes this extension value as an ASN.1 SEQUENCE. The {@code bindingType} field is omitted when {@code null}.
   *
   * @return the DER-encodable SEQUENCE
   * @throws NullPointerException if {@link #dataTbsHash} or {@link #hashAlg} is {@code null}
   */
  @Override
  public ASN1Primitive toASN1Primitive() {
    Objects.requireNonNull(this.dataTbsHash, "dataTbsHash must not be null");
    Objects.requireNonNull(this.hashAlg, "hashAlg must not be null");
    final ASN1EncodableVector v = new ASN1EncodableVector();
    v.add(new DEROctetString(this.dataTbsHash));
    v.add(this.hashAlg);
    if (this.bindingType != null) {
      v.add(new DERUTF8String(this.bindingType));
    }
    return new DERSequence(v);
  }

  /**
   * Returns a human-readable representation, rendering the hash algorithm as its JCA digest name (e.g. {@code SHA-256})
   * where known, and falling back to the OID otherwise.
   *
   * @return a string representation of this extension
   */
  @Override
  public String toString() {
    final String hash = this.dataTbsHash != null ? Hex.toHexString(this.dataTbsHash) : "null";
    final String digestName = this.hashAlg != null
        ? MessageDigestUtils.getDigestName(this.hashAlg.getAlgorithm())
        : "null";
    return "SignedDocumentBinding [dataTbsHash=" + hash
        + ", hashAlg=" + digestName
        + ", bindingType=" + this.bindingType + "]";
  }
}
