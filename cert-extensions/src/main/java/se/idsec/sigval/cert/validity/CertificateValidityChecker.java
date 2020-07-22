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
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
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
