package se.idsec.sigval.cert.validity.crl.impl;

import lombok.extern.java.Log;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import se.idsec.sigval.cert.utils.CertUtils;
import se.idsec.sigval.cert.validity.AbstractValidityChecker;
import se.idsec.sigval.cert.validity.ValidationStatus;
import se.idsec.sigval.cert.validity.crl.CRLCache;
import se.idsec.sigval.cert.validity.crl.CRLInfo;

import java.beans.PropertyChangeListener;
import java.security.cert.CRLReason;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;

/**
 * The general implementation of a CRL checker
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
          builder.reason(reason.name());
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

}
