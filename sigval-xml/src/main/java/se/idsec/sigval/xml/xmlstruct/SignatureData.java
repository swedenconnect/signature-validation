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

package se.idsec.sigval.xml.xmlstruct;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.xml.security.signature.XMLSignature;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * Signature data for an XML signature
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SignatureData {

  /** XMLSignature object for the signature */
  private XMLSignature signature;
  /** map holding reference URI values and the bytes of data referenced/signed from each URI */
  private Map<String, byte[]> refDataMap;
  /** true if this signature covers the whole XML document where the signature is located */
  private boolean coversWholeDoc;
  /** the signed canonical bytes of the document signed by this signature */
  private byte[] signedDocument;
  /** The signature value bytes of this signature */
  private byte[] signatureBytes;
  /** The canonical SignedInfo bytes that are hashed and signed by this signature */
  private byte[] signedInfoBytes;
  /** The signer certificate */
  private X509Certificate signerCertificate;
  /** The full certificate path provided with the signature */
  private List<X509Certificate> signatureCertChain;

}
