package se.idsec.sigval.cert.validity.impl;

import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.sigval.cert.validity.CertificateValidityChecker;
import se.idsec.sigval.cert.validity.ValidationStatus;
import se.idsec.sigval.cert.validity.crl.CRLCache;
import se.idsec.sigval.cert.validity.crl.impl.CRLValidityChecker;
import se.idsec.sigval.cert.validity.ocsp.OCSPCertificateVerifier;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
public class BasicCertificateValidityChecker extends CertificateValidityChecker {

  public static final String EVENT_ID = "cert-validity";
  /**
   * Gets the resulting validation results for CRL and OCSP
   *
   * @return validation results for CRL and OCSP checking
   */
  @Getter private List<ValidationStatus> validationStatusList;
  /**
   * Force the validation operations to be performed in a single thread.
   *
   * @param singleThreaded set to true to perform all validation tasks in a single thread.
   */
  @Setter private boolean singleThreaded;
  /**
   * The maximum number of seconds to wait for conclusion of the first validation task in multithreaded operation.
   */
  @Setter private int maxValidationSeconds = 10;

  public BasicCertificateValidityChecker(X509Certificate certificate, X509Certificate issuer, CRLCache crlCache,
    PropertyChangeListener... propertyChangeListeners) {
    super(certificate, issuer, EVENT_ID, propertyChangeListeners);
    this.setValidityCheckers(Arrays.asList(
      new CRLValidityChecker(certificate, issuer, crlCache, this),
      new OCSPCertificateVerifier(certificate, issuer, this)
    ));
    this.setValidityPathChecker(new BasicValidityPathChecker(crlCache));
  }

  /**
   * Perform certificate validation by means of
   * @return the resulting validation status
   * @throws RuntimeException if no validation status information could be obtained due to timeout.
   */
  @Override public ValidationStatus checkValidity() {
    validationStatusList = new ArrayList<>();

    if (singleThreaded){
      // Singlethreaded
      validityCheckers.stream().forEach(validityChecker -> {
        ValidationStatus status = validityChecker.checkValidity();
        try {
          if (status.getValidity().equals(ValidationStatus.CertificateValidity.VALID) && status.isStatusSignatureValid()){
            validityPathChecker.verifyValidityStatusTrustPath(status);
          }
        } catch (Exception ex){
          status.setValidity(ValidationStatus.CertificateValidity.UNKNOWN);
          status.setException(ex);
        }
        validationStatusList.add(status);
      });
    } else {
      // Multithreaded
      validityCheckers.stream().forEach(validityChecker -> {
        Thread validityThread = new Thread(validityChecker);
        validityThread.start();
      });

      long startTime = System.currentTimeMillis();
      while (true){
        boolean isComplete = isCompleteValidation(validityCheckers.size());
        if (isComplete || System.currentTimeMillis() > startTime + (maxValidationSeconds * 1000) ){
          break;
        }
        try {
          Thread.sleep(30);
        }
        catch (InterruptedException e) {
          log.error("Thread sleep exception", e);
        }
      }
    }

    // Pick result status
    Optional<ValidationStatus> revokedStatusOptional = validationStatusList.stream()
      .filter(status -> status.isStatusSignatureValid())
      .filter(status -> status.getValidity().equals(ValidationStatus.CertificateValidity.REVOKED))
      .findFirst();

    Optional<ValidationStatus> validStatusOptional = validationStatusList.stream()
      .filter(status -> status.isStatusSignatureValid())
      .filter(status -> status.getValidity().equals(ValidationStatus.CertificateValidity.VALID))
      .findFirst();

    if (revokedStatusOptional.isPresent()){
      log.warn("Certificate REVOKED for {}", revokedStatusOptional.get().getCertificate().getSubjectX500Principal().toString());
      return revokedStatusOptional.get();
    }
    if (validStatusOptional.isPresent()){
      log.info("Certificate status VALID for {}", validStatusOptional.get().getCertificate().getSubjectX500Principal().toString());
      return validStatusOptional.get();
    }
    if (validationStatusList.isEmpty()){
      log.warn("Certificate validity checking aborted: No valid responses");
      throw new RuntimeException("Validity checking: No valid responses");
    }
    ValidationStatus validationStatus = validationStatusList.get(0);
    log.info("Certificate status {} for {}",
      validationStatus.getValidity().name(), validationStatus.getCertificate().getSubjectX500Principal().toString());
    return validationStatus;
  }

  private boolean isCompleteValidation(int size) {
    if (validationStatusList.isEmpty()){
      return false;
    }
    // Complete if all results are in
    if (validationStatusList.size() == size){
      return true;
    }

    List<ValidationStatus> conclusiveList = validationStatusList.stream()
      .filter(status -> status.isStatusSignatureValid())
      .filter(status -> status.getValidity().equals(ValidationStatus.CertificateValidity.REVOKED)
        || status.getValidity().equals(ValidationStatus.CertificateValidity.VALID))
      .collect(Collectors.toList());

    return !conclusiveList.isEmpty();
  }

  @Override public void propertyChange(PropertyChangeEvent evt) {
    String id = evt.getPropertyName();
    if (id.equals(CRLValidityChecker.EVENT_ID) || id.equals(OCSPCertificateVerifier.EVENT_ID)) {
      ValidationStatus status = (ValidationStatus) evt.getNewValue();
      try {
        if (status.getValidity().equals(ValidationStatus.CertificateValidity.VALID) && status.isStatusSignatureValid()){
          validityPathChecker.verifyValidityStatusTrustPath(status);
        }
      } catch (Exception ex){
        status.setValidity(ValidationStatus.CertificateValidity.UNKNOWN);
        status.setException(ex);
      }
      validationStatusList.add(status);
    }
  }
}
