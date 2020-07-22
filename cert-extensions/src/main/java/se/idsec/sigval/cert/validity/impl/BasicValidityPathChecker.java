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

package se.idsec.sigval.cert.validity.impl;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import se.idsec.sigval.cert.utils.CertUtils;
import se.idsec.sigval.cert.validity.CertificateValidityChecker;
import se.idsec.sigval.cert.validity.ValidationStatus;
import se.idsec.sigval.cert.validity.ValidityPathChecker;
import se.idsec.sigval.cert.validity.crl.CRLCache;

import java.security.cert.X509Certificate;
import java.util.List;

/**
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class BasicValidityPathChecker implements ValidityPathChecker {

  CRLCache crlCache;

  public BasicValidityPathChecker(CRLCache crlCache) {
    this.crlCache = crlCache;
  }

  @Override public void verifyValidityStatusTrustPath(ValidationStatus validityStatus) throws RuntimeException {
    ValidationStatus.ValidatorSourceType sourceType = validityStatus.getSourceType();
    switch (sourceType) {
    case OCSP:
      checkOcspTrustPath(validityStatus);
      break;
    case CRL:
      checkCrlTrustPath(validityStatus);
    }
  }

  /**
   * This implementation of CRL trust path validator requires that the CRL and the target certificate being validated can both be
   * verified using the same CA certificate. That is, the issuer cert and the CRL signing cert must be the same certificate.
   *
   * @param validityStatus validity status obtains from CRL validation
   * @throws RuntimeException is thrown if CRL certificate trust path is not valid.
   */
  private void checkCrlTrustPath(ValidationStatus validityStatus) throws RuntimeException {
    X509Certificate issuer = validityStatus.getIssuer();
    X509Certificate statusSignerCertificate = validityStatus.getStatusSignerCertificate();
    if (issuer == null || statusSignerCertificate == null) {
      log.debug("CRL validation failed: CRL issuer certificate missing for CRL validation");
      throw new RuntimeException("CRL validation failed: CRL issuer certificate missing for CRL validation");
    }

    if (!CertUtils.isCurrentlyValid(issuer)){
      log.debug("CRL validation failed: Expired or not yet valid CRL issuer certificate");
      throw new RuntimeException("CRL validation failed: Expired or not yet valid CRL issuer certificate");
    }

    if (!issuer.equals(statusSignerCertificate)) {
      log.debug("CRL validation failed: CRL is not verified through the target CA certificate");
      throw new RuntimeException("CRL validation failed: CRL is not verified through the target CA certificate");
    }

    //Check the cert extension
    if (statusSignerCertificate.getBasicConstraints() < 0) {
      // The CRL issuer is not a CA
      log.debug("CRL validation failed: Non CA CRL issuer");
      throw new RuntimeException("CRL validation failed: Non CA CRL issuer");
    }
    boolean[] keyUsage = statusSignerCertificate.getKeyUsage();
    if (keyUsage == null || !keyUsage[6]) {
      // The key usage does not allow CRL signing
      log.debug("CRL validation failed: CRL key usage bit not set");
      throw new RuntimeException("CRL validation failed: CRL key usage bit not set");
    }
  }

  /**
   * This implementation of the OCSP trust path validator requires that the target certificate and the OCSP responder certificate can be verified
   * by the same CA certificate. To avoid recursiveness, the target certificate must not appear in the trust path of the responder certificate.
   *
   * @param validityStatus validation status from OCSP validation
   * @throws RuntimeException is thrown if OCSP responder certificate trust path is not valid
   */
  private void checkOcspTrustPath(ValidationStatus validityStatus) throws RuntimeException {
    X509Certificate issuer = validityStatus.getIssuer();
    X509Certificate statusSignerCertificate = validityStatus.getStatusSignerCertificate();
    List<X509Certificate> statusSignerCertificateChain = validityStatus.getStatusSignerCertificateChain();
    if (issuer == null
      || statusSignerCertificate == null
      || statusSignerCertificateChain == null
      || statusSignerCertificateChain.isEmpty()) {
      log.debug("OCSP validation failed: Missing necessary certificates to validate OCSP response");
      throw new RuntimeException("OCSP validation failed: Missing necessary certificates to validate OCSP response");
    }

    if (!CertUtils.isCurrentlyValid(issuer)){
      log.debug("OCSP validation failed: Expired or not yet valid issuer certificate");
      throw new RuntimeException("OCSP validation failed: Expired or not yet valid issuer certificate");
    }

    if (!CertUtils.isCurrentlyValid(statusSignerCertificate)){
      log.debug("OCSP validation failed: Expired or not yet valid OCSP signer certificate");
      throw new RuntimeException("OCSP validation failed: Expired or not yet valid OCSP signer certificate");
    }

    try {
      statusSignerCertificate.verify(issuer.getPublicKey());
    }
    catch (Exception e) {
      log.debug("OCSP validation failed: OCSP responder certificate can't be verified using target CA certificate", e);
      throw new RuntimeException("OCSP validation failed: OCSP responder certificate can't be verified using target CA certificate");
    }

    // Check recursiveness
    boolean targetCertInOcspPath = statusSignerCertificateChain.stream()
      .filter(certificate -> certificate.equals(validityStatus.getCertificate()))
      .findFirst().isPresent();
    if (targetCertInOcspPath) {
      log.debug("OCSP validation failed: OCSP responder certificate trust path contains target certificate");
      throw new RuntimeException("OCSP validation failed: OCSP responder certificate trust path contains target certificate");
    }

    //Check OCSP extended key usage
    boolean ocspKeyUsage = false;
    try {
      ocspKeyUsage = statusSignerCertificate.getExtendedKeyUsage().stream()
        .filter(s -> KeyPurposeId.id_kp_OCSPSigning.getId().equalsIgnoreCase(s))
        .findFirst().isPresent();
    }
    catch (Exception ignored) {
    }
    if (!ocspKeyUsage) {
      log.debug("OCSP validation failed: OCSP responder certificate lacks OCSP key usage");
      throw new RuntimeException("OCSP validation failed: OCSP responder certificate lacks OCSP key usage");
    }

    //Check OCSP responder cert validity status
    boolean ocspNocheck = CertUtils.isOCSPNocheckExt(statusSignerCertificate);
    if (!ocspNocheck) {
      CertificateValidityChecker certChecker = new BasicCertificateValidityChecker(
        statusSignerCertificate, issuer, crlCache);
      ValidationStatus validationStatus = certChecker.checkValidity();
      if (!validationStatus.getValidity().equals(ValidationStatus.CertificateValidity.VALID)) {
        log.debug("OCSP validation failed: OCSP responder certificate failed validity check");
        throw new RuntimeException("OCSP validation failed: OCSP responder certificate failed validity check");
      }
    }
  }
}
