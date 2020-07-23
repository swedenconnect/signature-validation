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
package se.idsec.sigval.cert.chain;

import lombok.Getter;
import lombok.Setter;
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
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractPathValidator implements Runnable {

  private final List<PropertyChangeListener> listeners;
  /**
   * The id of the event being communicated back to registered property change listeners as property name
   *
   * @param id the id being returned as the event property name
   */
  @Setter private String id;
  protected final CRLCache crlCache;
  protected final PathBuilder pathBuilder;
  protected final X509Certificate targetCert;
  protected final List<X509Certificate> chain;
  protected final List<TrustAnchor> trustAnchors;
  protected final CertStore certStore;

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

  /**
   * Running the validation task as {@link Runnable} task and returning result to the callback function of all property change listeners
   */
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
