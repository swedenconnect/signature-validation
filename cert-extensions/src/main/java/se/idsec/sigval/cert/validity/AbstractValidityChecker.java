package se.idsec.sigval.cert.validity;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

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
