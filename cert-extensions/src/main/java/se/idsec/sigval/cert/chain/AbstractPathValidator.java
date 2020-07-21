package se.idsec.sigval.cert.chain;

import se.idsec.sigval.cert.validity.crl.CRLCache;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

/**
 * Abstract class for implementations of a certificate chain validator
 *
 */
public abstract class AbstractPathValidator implements Runnable {

  private List<PropertyChangeListener> listeners;
  private String id;
  protected CRLCache crlCache;
  protected PathBuilder pathBuilder;
  protected X509Certificate targetCert;
  protected List<X509Certificate> chain;
  protected List<TrustAnchor> trustAnchors;
  protected CertStore certStore;

  /**
   * Constructs the chain validator
   * @param targetCert the certificate being validated
   * @param chain the supporting chain of certificates which may include the target certificate and root certificates
   * @param crlCache CRL cache providing access to certificate revocation lists
   * @param pathBuilder path builder used to find and verify the path to a trust anchor
   * @param trustAnchors a list of trust anchors that must be used to terminate the validated chain
   * @param certStore certificate store providing complementary intermediary certificates
   * @param id the name of the process returned to registered listeners
   * @param propertyChangeListeners listeners that are notified when the validation process is complete
   */
  protected AbstractPathValidator(X509Certificate targetCert, List<X509Certificate> chain,
    CRLCache crlCache, PathBuilder pathBuilder, List<TrustAnchor> trustAnchors,
    CertStore certStore, String id,  PropertyChangeListener... propertyChangeListeners) {
    this.id = id;
    this.crlCache = crlCache;
    this.pathBuilder = pathBuilder;
    this.targetCert = targetCert;
    this.chain = chain;
    this.trustAnchors = trustAnchors;
    this.certStore = certStore;
    this.listeners = Arrays.asList(propertyChangeListeners);
  }

  @Override public void run() {
    PathValidationResult pathValidationResult = validateCertificatePath();
    PropertyChangeEvent event = new PropertyChangeEvent(this, id, null, pathValidationResult);
    listeners.stream().forEach(propertyChangeListener -> propertyChangeListener.propertyChange(event));
  }

  /**
   * Validates a certificate path
   * @return {@link PathValidationResult}
   */
  public abstract PathValidationResult validateCertificatePath();
}
