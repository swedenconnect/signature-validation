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

import java.util.Objects;

public class SignedDocumentBinding extends ASN1Object {

  public static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.37");

  @Getter @Setter
  private byte[] dataTbsHash;
  @Getter @Setter
  private AlgorithmIdentifier hashAlg;
  @Getter @Setter
  private String bindingType;

  public static SignedDocumentBinding getInstance(final Object obj) {
    if (obj instanceof SignedDocumentBinding) {
      return (SignedDocumentBinding) obj;
    }
    if (obj != null) {
      return new SignedDocumentBinding(ASN1Sequence.getInstance(obj));
    }
    throw new IllegalArgumentException("Invalid object: " + obj);
  }

  public SignedDocumentBinding(final ASN1Sequence seq) {
    for (int i = 0; i < seq.size(); i++) {
      final ASN1Primitive p = seq.getObjectAt(i).toASN1Primitive();
      if (i == 0 && p instanceof ASN1OctetString) {
        this.dataTbsHash = ((ASN1OctetString) p).getOctets();
      }
      try {
        this.hashAlg = AlgorithmIdentifier.getInstance(p);
      } catch (Exception ignored) {}
      if (p instanceof ASN1UTF8String) {
        this.bindingType = ((ASN1UTF8String) p).getString();
      }
    }
  }

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
}
