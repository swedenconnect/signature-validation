package se.idsec.sigval.cert.validity;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * This is the complete certificate validity checker that attempts both CRL and OCSP and returns the result of the first conclusive method.
 *
 * <p>The process of each validation method is carried out as follows</p>
 * <ul>
 *   <li>Start 2 threads, each attempting to do CRL and OCSP validation</li>
 *   <li>For each process that concludes. Check that certificate chaining from validation data is trusted</li>
 *   <li>If certificate chaining is trusted, check if result is conclusive</li>
 *   <li>Return on first conclusive result or when max time has been reached</li>
 * </ul>
 *
 * Note that CRL caching will complete in the background even if OCSP was the first method to complete. It is common that OCSP is quicker on
 * the first pass, but CRL based on cached data on every following attempts.
 *
 */
public abstract class CertificateValidityChecker implements Runnable, PropertyChangeListener{

  private List<PropertyChangeListener> listeners;
  private String id;
  protected List<ValidityChecker> validityCheckers;
  protected ValidityPathChecker validityPathChecker;
  protected X509Certificate certificate;
  protected X509Certificate issuer;

  public CertificateValidityChecker(
    X509Certificate certificate,
    X509Certificate issuer,
    String id,
    PropertyChangeListener... propertyChangeListeners) {

    this.certificate = certificate;
    this.issuer = issuer;
    this.id = id;
    this.listeners = Arrays.asList(propertyChangeListeners);
  }

  public void setValidityCheckers(List<ValidityChecker> validityCheckers) {
    this.validityCheckers = validityCheckers;
  }

  public void setValidityPathChecker(ValidityPathChecker validityPathChecker) {
    this.validityPathChecker = validityPathChecker;
  }

  @Override public void run() {
    ValidationStatus validityCheckResult = checkValidity();
    PropertyChangeEvent event = new PropertyChangeEvent(this, id, null, validityCheckResult);
    listeners.stream().forEach(propertyChangeListener -> propertyChangeListener.propertyChange(event));
  }

  public abstract ValidationStatus checkValidity();

}
