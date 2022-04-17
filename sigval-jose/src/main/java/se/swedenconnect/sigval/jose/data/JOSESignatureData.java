/*
 * Copyright (c) 2020. Sweden Connect
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

package se.swedenconnect.sigval.jose.data;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.UnprotectedHeader;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Signature data for an JSON signature
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class JOSESignatureData {

  /** Indicates if the data payload is detached */
  boolean detached;
  /** Indicates if signature data validates the payload with the provided public key  */
  boolean isVerified;
  /** Any exception caught while verifying or parsing the signature data */
  Exception exception;
  /** The JOSE headers associated with this signature */
  JWSHeader header;
  /** The signature algorithm used to create the signature */
  String signatureAlgorithm;
  /** Unprotected headers associated with this signature */
  UnprotectedHeader unprotectedHeader;
  /** The payload signed by this signature */
  private Payload payload;
  /** The signature value bytes */
  private byte[] signatureBytes;
  /** The signer certificate */
  private X509Certificate signerCertificate;
  /** The full certificate path provided with the signature */
  private List<X509Certificate> signatureCertChain;

}
