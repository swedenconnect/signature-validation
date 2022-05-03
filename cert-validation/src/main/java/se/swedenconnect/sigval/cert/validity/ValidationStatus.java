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

package se.swedenconnect.sigval.cert.validity;

import lombok.*;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Certificate validation status
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Setter @Getter
public class ValidationStatus {

  /**
   * The certificate being checked
   *
   * @param certificate certificate checked for revocation
   * @return certificate checked for revocation
   */
  private X509Certificate certificate;
  /**
   * Issuer
   *
   * @param  issuer
   * @return issuer
   */
  private X509Certificate issuer;
  /**
   * Validity status
   *
   * @param validity validity status
   * @return validity status
   */
  private CertificateValidity validity;
  /**
   * Location of validation source
   *
   * @param valdationSourceLocation location of validation source
   * @return location of validation source
   */
  private String valdationSourceLocation;
  /**
   * Type of validation check source type
   *
   * @param sourceType type of validation check source type
   * @return type of validation check source type
   */
  private ValidatorSourceType sourceType;
  /**
   * Issuing time for validity status information
   *
   * @param revocationObjectIssuingTime issuing time for validity status information
   * @return issuing time for validity status information
   */
  private Date revocationObjectIssuingTime;
  /**
   * Revocation time
   *
   * @param revocationTime revocation time
   * @return revocation time if certificate is revoked or else null
   */
  private Date revocationTime;
  /**
   * Validatin time
   *
   * @param validationTime validatin time
   * @return Validation time
   */
  private Date validationTime;
  /**
   * The certificate used to sign the status information
   */
  private X509Certificate statusSignerCertificate;
  /**
   * The unordered certificate chain used to sign the status information, including the signer certificate
   */
  private List<X509Certificate> statusSignerCertificateChain;
  /** Indicates if the signature on validation status data is valid and verifies against the specified status signer certificate */
  private boolean statusSignatureValid;
  /** Indication of a reason for revocation according to RFC 5280 */
  private int reason;
  /** Exception thrown during validation checking */
  private Exception exception;

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("CertificateValidationStatus [certificate=").append(certificate != null ? certificate.getSerialNumber() : "null")
      .append(", issuer=").append(issuer != null ? issuer.getSerialNumber() : "null")
      .append(", validity=").append(validity)
      .append(", sourceType=").append(sourceType)
      .append(", sourceLocation=").append(valdationSourceLocation)
      .append(", revocationObjectIssuingTime=").append(revocationObjectIssuingTime)
      .append(", revocationTime=").append(revocationTime)
      .append(", validationTime=").append(validationTime)
      .append("]");
    return builder.toString();
  }

  public enum ValidatorSourceType {
    OCSP, CRL, SELF_SIGNED
  }

  public enum CertificateValidity {
    VALID, INVALID, REVOKED, UNKNOWN
  }

}