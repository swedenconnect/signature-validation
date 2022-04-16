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

package se.swedenconnect.sigval.commons.data;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.nimbusds.jwt.SignedJWT;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import se.idsec.signservice.security.sign.impl.DefaultSignatureValidationResult;
import se.swedenconnect.sigval.svt.claims.PolicyValidationClaims;
import se.swedenconnect.sigval.svt.claims.SignatureClaims;

/**
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
public class ExtendedSigValResult extends DefaultSignatureValidationResult {

  /**
   * The complete list of certificates provided with the signature which may differ from the constructed path to a trust
   * anchor.
   */
  @Setter
  @Getter
  private List<X509Certificate> signatureCertificateChain;

  /**
   * Indicator if the signature covers the whole signed document. False value indicates that there may be content
   * changes added after signing.
   **/
  @Setter
  @Getter
  private boolean coversDocument = false;

  /**
   * The document data that was actually signed, in the form it had before this signature was added to the document.
   */
  @Setter
  @Getter
  private byte[] signedDocument;

  /**
   * Indicator if the signature is an AdES signature but certificate match the AdES signed certificate hash.
   **/
  @Setter
  @Getter
  private boolean invalidSignCert = false;

  /**
   * Public key parameters.
   */
  @Setter
  @Getter
  private PubKeyParams pubKeyParams;

  /**
   * List of validation policies applied to the validation process and if they succeeded or failed.
   **/
  @Setter
  @Getter
  private List<PolicyValidationClaims> validationPolicyResultList = new ArrayList<>();

  /**
   * List of verified times and information about how time verification was done.
   **/
  @Setter
  @Getter
  private List<TimeValidationResult> timeValidationResults = new ArrayList<>();

  /**
   * The signature SVA claims of this signature.
   **/
  @Setter
  @Getter
  private SignatureClaims signatureClaims;

  /**
   * The signed SVT JWT. Null content if the verification is not SVT verified.
   **/
  @Setter
  @Getter
  private SignedJWT svtJWT;

  /** {@inheritDoc} */
  @Override
  public List<X509Certificate> getAdditionalCertificates() {
    if (this.signatureCertificateChain == null) {
      return new ArrayList<>();
    }
    return this.signatureCertificateChain.stream()
      .filter(x509Certificate -> !x509Certificate.equals(getSignerCertificate()))
      .collect(Collectors.toList());
  }
}
