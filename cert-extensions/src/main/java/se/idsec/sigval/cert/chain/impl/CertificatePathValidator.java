package se.idsec.sigval.cert.chain.impl;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.sigval.cert.chain.AbstractPathValidator;
import se.idsec.sigval.cert.chain.PathValidationResult;
import se.idsec.sigval.cert.validity.ValidationStatus;
import se.idsec.sigval.cert.validity.crl.CRLCache;
import se.idsec.sigval.cert.validity.impl.BasicCertificateValidityChecker;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.security.cert.CertStore;
import java.security.cert.PKIXCertPathBuilderResult;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
public class CertificatePathValidator extends AbstractPathValidator implements PropertyChangeListener {

  public static final String EVENT_ID = "certPathValidator";
  /**
   * Force the validation operations to be performed in a single thread.
   *
   * @param singleThreaded set to true to perform all validation tasks in a single thread.
   */
  @Setter protected boolean singleThreaded;
  /** Result list of certificate status checks */
  protected List<ValidationStatus> validationStatusList;
  /** The result of certificate path building and PKIX path validation except revocation checking */
  protected PKIXCertPathBuilderResult certPathBuilderResult;
  /** The Certificate path starting with the target certificate first and ending with the trust anchor certificate */
  protected List<X509Certificate> certPath;
  /**
   * The maximum number of seconds to wait for conclusion of path validation. This number is ignored in single threaded mode.
   *
   * @param maxValidationSeconds maximum validation seconds in multithreaded mode
   */
  @Setter private int maxValidationSeconds = 15;

  /**
   * Constructs the chain validator
   *
   * @param targetCert              the certificate being validated
   * @param chain                   the supporting chain of certificates which may include the target certificate and root certificates
   * @param trustAnchors            a list of trust anchors that must be used to terminate the validated chain
   * @param certStore               certificate store providing complementary intermediary certificates
   * @param crlCache                CRL cache providing access to certificate revocation lists
   * @param propertyChangeListeners listeners that are notified when the validation process is complete
   */
  public CertificatePathValidator(X509Certificate targetCert, List<X509Certificate> chain,
    List<TrustAnchor> trustAnchors, CertStore certStore, CRLCache crlCache,
    PropertyChangeListener... propertyChangeListeners) {
    super(targetCert, chain, crlCache, new BasicPathBuilder(), trustAnchors, certStore, EVENT_ID, propertyChangeListeners);
  }

  @Override public PathValidationResult validateCertificatePath() {

    //First step is to construct a valid path to a trusted root
    try {
      certPathBuilderResult = (PKIXCertPathBuilderResult) pathBuilder.buildPath(targetCert, chain, certStore, trustAnchors);
      certPath = ((BasicPathBuilder) pathBuilder).getResultPath(certPathBuilderResult);
    }
    catch (Exception e) {
      log.warn("Unable to build path to trust anchor: {}", e.getMessage());
      Throwable cause = e.getCause();
      while (cause != null) {
        log.debug("Caused by: {}", cause.getMessage());
        cause = cause.getCause();
      }
      return PathValidationResult.builder()
        .validCert(false)
        .exception(e)
        .build();
    }

    if (certPath.size() < 2) {
      // This is an impossible outcome of a successful path validation. Something is wrong in the implementation
      log.error("Successful path validation provided insufficient chain length. Chain length must be at least 2");
      return PathValidationResult.builder()
        .validCert(false)
        .exception(new RuntimeException("Valid path too short for validity checking. Must be at least length = 2"))
        .build();
    }

    // We have a trusted path and all certificates pass PKIX path validation rules, including expiry date checking, basic constraints etc.
    // Now check validity
    validationStatusList = new ArrayList<>();
    if (singleThreaded) {
      getSingleThreadedValidityStatus();
    }
    else {
      runValidationThreads();
    }

    sortResults();

    // We should now have all validity status results. Check them top down (from TA to EE cert)
    PathValidationResult.PathValidationResultBuilder resultBuilder = PathValidationResult.builder();
    resultBuilder
      .validCert(false)
      .pkixCertPathBuilderResult(certPathBuilderResult)
      .validationStatusList(validationStatusList)
      .targetCertificate(certPath.get(0))
      .chain(certPath);

    for (int i = certPath.size() - 2; i >= 0; i--) {
      X509Certificate checkedCert = certPath.get(i);
      Optional<ValidationStatus> statusOptional = getStatus(checkedCert);
      if (!statusOptional.isPresent()) {
        log.warn("Validation status is missing for certificate {}", checkedCert.getSubjectX500Principal());
        return resultBuilder
          .exception(new RuntimeException("Missing path validation result for " + checkedCert.getSubjectX500Principal()))
          .build();
      }
      ValidationStatus status = statusOptional.get();
      if (status.getValidity().equals(ValidationStatus.CertificateValidity.VALID) && status.isStatusSignatureValid()) {
        continue;
      }
      if (status.getValidity().equals(ValidationStatus.CertificateValidity.UNKNOWN)) {
        log.warn("Certificate validity could not be determined for {}", checkedCert.getSubjectX500Principal());
        return resultBuilder
          .exception(new RuntimeException("Certificate validity could not be determined for " + checkedCert.getSubjectX500Principal()))
          .build();
      }
      if (status.getValidity().equals(ValidationStatus.CertificateValidity.REVOKED)) {
        log.warn("Certificate REVOKED for {}", checkedCert.getSubjectX500Principal());
        return resultBuilder
          .exception(new RuntimeException("Certificate REVOKED for " + checkedCert.getSubjectX500Principal()))
          .build();
      }
      log.warn("Certificate status checking failed for {}", checkedCert.getSubjectX500Principal());
      return resultBuilder
        .exception(new RuntimeException("Certificate status checking failed for " + checkedCert.getSubjectX500Principal()))
        .build();
    }
    return resultBuilder.validCert(true).build();
  }

  private void sortResults() {
    validationStatusList = certPath.stream()
      .map(certificate -> getStatus(certificate))
      .filter(validationStatus -> validationStatus.isPresent())
      .map(validationStatus -> validationStatus.get())
      .collect(Collectors.toList());
  }

  private Optional<ValidationStatus> getStatus(X509Certificate checkedCert) {
    return validationStatusList.stream()
      .filter(status -> status.getCertificate().equals(checkedCert))
      .findFirst();
  }

  private void runValidationThreads() {
    long startTime = System.currentTimeMillis();

    //Start validity threads
    for (int i = 0; i < certPath.size() - 1; i++) {
      BasicCertificateValidityChecker validityChecker = new BasicCertificateValidityChecker(certPath.get(i), certPath.get(i + 1), crlCache, this);
      validityChecker.setMaxValidationSeconds(maxValidationSeconds);
      Thread validityThread = new Thread(validityChecker);
      validityThread.setDaemon(true);
      validityThread.start();
    }

    //Wait for them to conclude or for timeout
    while (true) {
      if (System.currentTimeMillis() > startTime + (maxValidationSeconds * 1000)) {
        break;
      }
      if (validationStatusList.size() == certPath.size() - 1) {
        break;
      }
      try {
        Thread.sleep(30);
      }
      catch (InterruptedException e) {
        e.printStackTrace();
      }
    }
  }

  private void getSingleThreadedValidityStatus() {
    for (int i = 0; i < certPath.size() - 1; i++) {
      BasicCertificateValidityChecker validityChecker = new BasicCertificateValidityChecker(certPath.get(i), certPath.get(i + 1), crlCache);
      validityChecker.setSingleThreaded(true);
      validationStatusList.add(validityChecker.checkValidity());
    }
  }

  @Override public void propertyChange(PropertyChangeEvent evt) {
    String propertyName = evt.getPropertyName();
    if (!propertyName.equalsIgnoreCase(BasicCertificateValidityChecker.EVENT_ID)) {
      log.error("Wrong event ID in certificate validity check event. Expected {}. Found {}", BasicCertificateValidityChecker.EVENT_ID,
        propertyName);
      return;
    }
    if (evt.getNewValue() instanceof ValidationStatus) {
      ValidationStatus validationStatus = (ValidationStatus) evt.getNewValue();
      validationStatusList.add(validationStatus);
    }
    else {
      log.error("Wrong result object in certificate validity check event. Expected {}. Found {}", ValidationStatus.class,
        evt.getNewValue().getClass());
    }
  }
}
