/*
 * Copyright 2019-2020 IDsec Solutions AB
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
package se.idsec.sigval.cert.chain.impl;

import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.idsec.sigval.cert.chain.AbstractPathValidator;
import se.idsec.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.idsec.sigval.cert.chain.PathBuilder;
import se.idsec.sigval.cert.chain.PathValidationResult;
import se.idsec.sigval.cert.utils.CertUtils;
import se.idsec.sigval.cert.validity.ValidationStatus;

import se.idsec.sigval.cert.validity.crl.CRLCache;
import se.idsec.sigval.cert.validity.impl.BasicCertificateValidityChecker;
import sun.security.provider.certpath.X509CertPath;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Certificate path validator implementation. This path validator can be executed as a runnable object in a designated Thread
 * The result is delivered to the callback function of any registered PropertyChange listeners. Alternatively, path validation
 * can be executed by calling the validateCertificatePath() function.
 *
 * The option to set the boolean singleThreaded applies only to underlying validity checks and has nothing to do with whether this
 * path validator itself is executed as a runnable or as a direct function call.
 *
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
public class CertificatePathValidator extends AbstractPathValidator implements PropertyChangeListener {

  public static final String DEFAULT_EVENT_ID = "certPathValidator";
  protected static final PathBuilder PATH_BUILDER = new BasicPathBuilder();
  /**
   * Force the underlying validation operations to be performed in a single thread.
   */
  @Setter protected boolean singleThreaded;
  /** Result list of certificate status checks */
  protected List<ValidationStatus> validationStatusList;
  /** The result of certificate path building and PKIX path validation except revocation checking */
  protected PKIXCertPathBuilderResult certPathBuilderResult;
  /** The Certificate path starting with the target certificate first and ending with the trust anchor certificate */
  protected List<X509Certificate> pathBuilderCertPath;
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
    super(targetCert, chain, crlCache, PATH_BUILDER, trustAnchors, certStore, DEFAULT_EVENT_ID, propertyChangeListeners);
  }

  @Override public PathValidationResult validateCertificatePath() throws ExtendedCertPathValidatorException {

    // Check if the target certificate is a trust anchor
    try {
      Optional<TrustAnchor> taMatchOptional = trustAnchors.stream()
        .filter(ta -> ta.getTrustedCert().equals(targetCert))
        .findFirst();
      if (taMatchOptional.isPresent()){
        //Target certificate is found among the trust anchors
        CertPath certPath= new X509CertPath(Arrays.asList(targetCert));
        return PathValidationResult.builder()
          .pkixCertPathBuilderResult(new PKIXCertPathBuilderResult(certPath, taMatchOptional.get(), null, targetCert.getPublicKey()))
          .targetCertificate(targetCert)
          .validatedCertificatePath(Arrays.asList(targetCert))
          .validationStatusList(Arrays.asList(ValidationStatus.builder()
            .certificate(targetCert)
            .sourceType(ValidationStatus.ValidatorSourceType.SELF_SIGNED)
            .validity(ValidationStatus.CertificateValidity.VALID)
            .issuer(targetCert)
            .validationTime(new Date())
            .build()))
          .build();
      }
    } catch (Exception ex){
      log.error("Unexpected error while validating directly trusted cert", ex);
    }

    //First step is to construct a valid path to a trusted root
    try {
      certPathBuilderResult = (PKIXCertPathBuilderResult) pathBuilder.buildPath(targetCert, chain, certStore, trustAnchors);
      pathBuilderCertPath = CertUtils.getResultPath(certPathBuilderResult);
    }
    catch (Exception e) {
      log.warn("Unable to build path to trust anchor: {}", e.getMessage());
      Throwable cause = e.getCause();
      while (cause != null) {
        log.debug("Caused by: {}", cause.getMessage());
        cause = cause.getCause();
      }
      throw new ExtendedCertPathValidatorException(e);
    }

    if (pathBuilderCertPath.size() < 2) {
      // This is an impossible outcome of a successful path validation. Something is wrong in the implementation
      log.error("Successful path validation provided insufficient chain length. Chain length must be at least 2");
      throw new ExtendedCertPathValidatorException(new RuntimeException("Valid path too short for validity checking. Must be at least length = 2"));
    }

    // We have a trusted path and all certificates pass PKIX path validation rules, including expiry date checking, basic constraints etc.
    // Now check validity
    validationStatusList = new ArrayList<>();
    if (singleThreaded) {
      getSingleThreadedValidityStatus();
    }
    else {
      runValidationThreads();
      if (validationStatusList.size() != pathBuilderCertPath.size() - 1) {
        log.debug("Unable to obtain status information for all certificates in the path. Expected {} results, got {}", pathBuilderCertPath.size() - 1, validationStatusList.size());
        throw new ExtendedCertPathValidatorException(new RuntimeException("Unable to obtain status information for all certificates in the path"));
      }
    }

    sortResults();

    // We should now have all validity status results. Check them top down (from TA to EE cert)
    PathValidationResult.PathValidationResultBuilder resultBuilder = PathValidationResult.builder();
    resultBuilder
      .pkixCertPathBuilderResult(certPathBuilderResult)
      .validationStatusList(validationStatusList)
      .targetCertificate(pathBuilderCertPath.get(0))
      .validatedCertificatePath(pathBuilderCertPath);


    for (int i = pathBuilderCertPath.size() - 2; i >= 0; i--) {
      X509Certificate checkedCert = pathBuilderCertPath.get(i);
      Optional<ValidationStatus> statusOptional = getStatus(checkedCert);
      if (!statusOptional.isPresent()) {
        log.warn("Validation status is missing for certificate {}", checkedCert.getSubjectX500Principal());
        throw new ExtendedCertPathValidatorException(
          new RuntimeException("Missing path validation result for " + checkedCert.getSubjectX500Principal()),
          resultBuilder.build());
      }
      ValidationStatus status = statusOptional.get();
      if (status.getValidity().equals(ValidationStatus.CertificateValidity.VALID) && status.isStatusSignatureValid()) {
        continue;
      }
      if (status.getValidity().equals(ValidationStatus.CertificateValidity.UNKNOWN)) {
        log.debug("Certificate validity could not be determined for {}", checkedCert.getSubjectX500Principal());
        throw new ExtendedCertPathValidatorException(
          new RuntimeException("Certificate validity could not be determined for " + checkedCert.getSubjectX500Principal()),
          resultBuilder.build()
        );
      }
      if (status.getValidity().equals(ValidationStatus.CertificateValidity.REVOKED)) {
        log.debug("Certificate REVOKED for {}", checkedCert.getSubjectX500Principal());
        throw new ExtendedCertPathValidatorException(
          new RuntimeException("Certificate REVOKED for " + checkedCert.getSubjectX500Principal()),
          resultBuilder.build()
        );
      }
      log.warn("Certificate status checking failed for {}", checkedCert.getSubjectX500Principal());
      throw new ExtendedCertPathValidatorException(
        new RuntimeException("Certificate status checking failed for " + checkedCert.getSubjectX500Principal()),
        resultBuilder.build()
      );
    }
    return extendedPathChecks(resultBuilder.build());
  }

  /**
   * Override this function to perform additional path validation checks
   * @param result results of certificate path building
   * @return result of certificate path building after extended path checks
   */
  private PathValidationResult extendedPathChecks(PathValidationResult result) {
    return result;
  }

  /**
   * sort the validation status list to match the order of the certificate path.
   */
  private void sortResults() {
    validationStatusList = pathBuilderCertPath.stream()
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

  /**
   * Perform parallel validation checks in separate threads
   */
  private void runValidationThreads() {
    long startTime = System.currentTimeMillis();

    //Start validity threads
    for (int i = 0; i < pathBuilderCertPath.size() - 1; i++) {
      BasicCertificateValidityChecker validityChecker = new BasicCertificateValidityChecker(
        pathBuilderCertPath.get(i), pathBuilderCertPath.get(i + 1), crlCache, this);
      validityChecker.setMaxValidationSeconds(maxValidationSeconds);
      Thread validityThread = new Thread(validityChecker);
      validityThread.setDaemon(true);
      validityThread.start();
    }

    //Wait for validation checks to conclude or to timeout
    while (true) {
      if (System.currentTimeMillis() > startTime + (maxValidationSeconds * 1000)) {
        break;
      }
      if (validationStatusList.size() == pathBuilderCertPath.size() - 1) {
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

  /**
   * Perform sequential validation checks in the main thread
   */
  private void getSingleThreadedValidityStatus() {
    for (int i = 0; i < pathBuilderCertPath.size() - 1; i++) {
      BasicCertificateValidityChecker validityChecker = new BasicCertificateValidityChecker(
        pathBuilderCertPath.get(i), pathBuilderCertPath.get(i + 1), crlCache);
      validityChecker.setSingleThreaded(true);
      validationStatusList.add(validityChecker.checkValidity());
    }
  }

  /**
   * Callback function to collect validation results from validation threads
   * @param evt event holding validation result data
   */
  @Override public synchronized void propertyChange(PropertyChangeEvent evt) {
    String propertyName = evt.getPropertyName();
    if (!propertyName.equalsIgnoreCase(BasicCertificateValidityChecker.EVENT_ID)) {
      log.error("Wrong event ID in certificate validity check event. Expected {}. Found {}", BasicCertificateValidityChecker.EVENT_ID,
        propertyName);
      return;
    }
    if (evt.getNewValue() instanceof ValidationStatus) {
      ValidationStatus validationStatus = (ValidationStatus) evt.getNewValue();
      validationStatusList.add(validationStatus);
      log.debug("Certificate status validation received for event '{}' with status '{}' for {}", propertyName, validationStatus.getValidity(), validationStatus.getCertificate().getSubjectX500Principal());
    }
    else {
      log.error("Wrong result object in certificate validity check event. Expected {}. Found {}", ValidationStatus.class,
        evt.getNewValue().getClass());
    }
  }
}
