package se.idsec.sigval.cert.validity;

public interface ValidityChecker extends Runnable {

  /**
   * Checks the validity of a certificate
   * @return certificate validity status
   */
  ValidationStatus checkValidity ();

}
