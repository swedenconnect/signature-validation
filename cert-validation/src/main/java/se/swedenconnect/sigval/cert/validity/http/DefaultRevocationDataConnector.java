package se.swedenconnect.sigval.cert.validity.http;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import se.swedenconnect.sigval.cert.validity.crl.impl.CRLDataLoader;
import se.swedenconnect.sigval.cert.validity.ocsp.OCSPDataLoader;

import java.io.IOException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

/**
 * Standard Revocation data connector for downloading revocation data resources
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@NoArgsConstructor
public class DefaultRevocationDataConnector extends GenericHttpConnector implements CRLDataLoader, OCSPDataLoader {

  private static final Map<String, String> ocspProperties;

  static {
    ocspProperties = new HashMap<>();
    ocspProperties.put("Content-Type", "application/ocsp-request");
    ocspProperties.put("Accept", "application/ocsp-response");
  }

  @Override public byte[] downloadCrl(String url, int connectTimeout, int readTimeout) throws IOException {
    final HttpResponse httpResponse = getResource(new URL(url), connectTimeout, readTimeout);
    return httpResponse.getData();
  }

  @Override public OCSPResp requestOCSPResponse(String url, OCSPReq ocspReq, int connectTimeout, int readTimeout) throws IOException {
    final HttpResponse response = getResource(new URL(url), connectTimeout, readTimeout, ocspReq.getEncoded(), ocspProperties);
    return new OCSPResp(response.getData());
  }
}
