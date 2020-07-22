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
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public abstract class AbstractValidityChecker implements ValidityChecker {

  private List<PropertyChangeListener> listeners;
  private String id;
  protected X509Certificate certificate;
  protected X509Certificate issuer;


  public AbstractValidityChecker(X509Certificate certificate, X509Certificate issuer, String id, PropertyChangeListener... propertyChangeListeners) {
    this.certificate = certificate;
    this.issuer = issuer;
    this.id = id;
    this.listeners = Arrays.asList(propertyChangeListeners);
  }

  @Override public void run() {
    ValidationStatus validationStatus = checkValidity();
    PropertyChangeEvent event = new PropertyChangeEvent(this, id,null, validationStatus);
    listeners.stream().forEach(propertyChangeListener -> propertyChangeListener.propertyChange(event));
  }

  /**
   * {@inheritDoc}
   */
  @Override public abstract ValidationStatus checkValidity();

}
