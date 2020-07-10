package se.idsec.sigval.cert.validity;

import se.idsec.sigval.cert.validity.crl.CRLCache;

import java.beans.PropertyChangeEvent;
import java.beans.PropertyChangeListener;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

public class CertificateValidityChecker implements Runnable{

  List<PropertyChangeListener> listeners;
  CRLCache crlCache;

  public CertificateValidityChecker(X509Certificate certificate, X509Certificate issuer, CRLCache crlCache, PropertyChangeListener... propertyChangeListeners) {
    this.listeners = Arrays.asList(propertyChangeListeners);
    this.crlCache = crlCache;
  }

  @Override public void run() {
    ValidationStatus validityCheckResult = checkValidity();
    PropertyChangeEvent event = new PropertyChangeEvent(this, "cert-validation", null, validityCheckResult);
    listeners.stream().forEach(propertyChangeListener -> propertyChangeListener.propertyChange(event));
  }

  public ValidationStatus checkValidity(){
    //TODO execute the validity check
    return ValidationStatus.builder().build();
  }

}
