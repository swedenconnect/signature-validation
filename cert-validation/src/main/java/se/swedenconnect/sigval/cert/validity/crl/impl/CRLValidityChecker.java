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

package se.swedenconnect.sigval.cert.validity.crl.impl;

import java.beans.PropertyChangeListener;
import java.security.cert.CRLReason;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

import org.bouncycastle.asn1.x509.CRLDistPoint;

import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.sigval.cert.utils.CertUtils;
import se.swedenconnect.sigval.cert.validity.AbstractValidityChecker;
import se.swedenconnect.sigval.cert.validity.ValidationStatus;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;
import se.swedenconnect.sigval.cert.validity.crl.CRLInfo;

/**
 * The general implementation of a CRL checker
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CRLValidityChecker extends AbstractValidityChecker {

  public static final String EVENT_ID = "crl-validity";
  private CRLCache crlCache;

  public CRLValidityChecker(X509Certificate certificate, X509Certificate issuer, CRLCache crlCache,
    PropertyChangeListener... propertyChangeListeners) {
    super(certificate, issuer, EVENT_ID, propertyChangeListeners);
    this.crlCache = crlCache;
  }

  /**
   * {@inheritDoc}
   */
  @Override public ValidationStatus checkValidity() {
    ValidationStatus.ValidationStatusBuilder builder = ValidationStatus.builder();
    builder
      .sourceType(ValidationStatus.ValidatorSourceType.CRL)
      .certificate(certificate)
      .validationTime(new Date())
      .validity(ValidationStatus.CertificateValidity.UNKNOWN);

    try {
      CRLDistPoint crlDistPoint = CertUtils.getCrlDistPoint(certificate);
      CRLInfo crlInfo = crlCache.getCRL(crlDistPoint);
      builder.valdationSourceLocation(crlInfo.getLocation());
      X509CRL crl = crlInfo.getCrl();
      crl.verify(issuer.getPublicKey());
      builder.statusSignatureValid(true).issuer(issuer).statusSignerCertificate(issuer).statusSignerCertificateChain(Arrays.asList(issuer));
      boolean revoked = crl.isRevoked(certificate);
      if (revoked) {
        builder.validity(ValidationStatus.CertificateValidity.REVOKED);
        X509CRLEntry crlEntry = crl.getRevokedCertificate(certificate);
        builder.revocationTime(crlEntry.getRevocationDate());
        CRLReason reason = crlEntry.getRevocationReason();
        if (reason != null) {
          builder.reason(getReasonCode(reason));
          log.debug("The certificate was revoked with reason: " + reason.name());
        }
      }
      else {
        builder.validity(ValidationStatus.CertificateValidity.VALID);
      }
    }
    catch (Exception ex) {
      log.debug("This certificate does not support CRL checking: " + ex.getMessage());
      builder.exception(ex);
    }
    return builder.build();
  }

  private int getReasonCode(CRLReason reason) {
    /**
     The CRLReason enumeration.
     CRLReason ::= ENUMERATED {
     unspecified             (0),
     keyCompromise           (1),
     cACompromise            (2),
     affiliationChanged      (3),
     superseded              (4),
     cessationOfOperation    (5),
     certificateHold         (6),
     removeFromCRL           (8),
     privilegeWithdrawn      (9),
     aACompromise           (10)
     }
     */

    switch (reason){

    case KEY_COMPROMISE:
      return 1;
    case CA_COMPROMISE:
      return 2;
    case AFFILIATION_CHANGED:
      return 3;
    case SUPERSEDED:
      return 4;
    case CESSATION_OF_OPERATION:
      return 5;
    case CERTIFICATE_HOLD:
      return 6;
    case REMOVE_FROM_CRL:
      return 8;
    case PRIVILEGE_WITHDRAWN:
      return 9;
    case AA_COMPROMISE:
      return 10;
    default:
      return 0;
    }
  }

}
