package se.idsec.sigval.cert.validity.crl;

import org.bouncycastle.asn1.x509.CRLDistPoint;

import java.io.IOException;
import java.security.cert.X509CRL;

public interface CRLCache {

  /**
   * Obtains the current CRL indicated by a CRL distribution point extension and add this CRL to the active cache.
   *
   * @param crlDistributionPointExt CRL Distribution point extension
   * @return CRL
   * @throws IOException On error obtaining a CRL based on this extension
   */
  X509CRL getCRL(CRLDistPoint crlDistributionPointExt) throws IOException;

  X509CRL getCRL(String url) throws IOException;

  void recache();
}
