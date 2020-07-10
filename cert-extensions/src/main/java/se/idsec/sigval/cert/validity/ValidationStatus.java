/*
 * Software in this class is available under the MIT License (2008). See http://opensource.org/licenses/MIT for full text.
 *
 * Copyright (c) 2014, Gluu
 */

package se.idsec.sigval.cert.validity;

import lombok.*;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/**
 * Certificate validation status
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
   * @param revocationDate revocation time
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

  @Override
  public String toString() {
    StringBuilder builder = new StringBuilder();
    builder.append("CertificateValidationStatus [certificate=").append(certificate.getSerialNumber())
      .append(", issuer=").append(issuer.getSerialNumber())
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