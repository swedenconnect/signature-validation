package se.swedenconnect.sigval.cert.validity.http;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import lombok.NoArgsConstructor;
import se.swedenconnect.sigval.cert.validity.crl.impl.CRLDataLoader;
import se.swedenconnect.sigval.cert.validity.ocsp.OCSPDataLoader;

/**
 * Standard Revocation data connector for downloading revocation data resources
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
public class DefaultRevocationDataConnector extends GenericHttpConnector implements CRLDataLoader, OCSPDataLoader {

  /** Map holding the standard OCSP HTTP request properties */
  private static final Map<String, String> ocspProperties;

  static {
    ocspProperties = new HashMap<>();
    ocspProperties.put("Content-Type", "application/ocsp-request");
    ocspProperties.put("Accept", "application/ocsp-response");
  }

  /** {@inheritDoc} */
  @Override public byte[] downloadCrl(String url, int connectTimeout, int readTimeout) throws IOException {
    final HttpResponse httpResponse = getResource(new URL(url), connectTimeout, readTimeout);
    return httpResponse.getData();
  }

  /** {@inheritDoc} */
  @Override public OCSPResp requestOCSPResponse(String url, OCSPReq ocspReq, int connectTimeout, int readTimeout) throws IOException {
    final HttpResponse response = getResource(new URL(url), connectTimeout, readTimeout, ocspReq.getEncoded(), ocspProperties);
    return new OCSPResp(response.getData());
  }
}
