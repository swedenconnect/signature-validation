package se.swedenconnect.sigval.cert.validity.http;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.IOUtils;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@NoArgsConstructor
public class GenericHttpConnector {

  public HttpResponse getResource(URL requestUrl, int connectTimeout, int readTimeout){
    return getResource(requestUrl, connectTimeout, readTimeout, null, null);
  }
  public HttpResponse getResource(URL requestUrl, int connectTimeout, int readTimeout, byte[] data, Map<String, String> propertyMap){
    try {
      String method = data == null ? "GET" : "POST";
      propertyMap = propertyMap == null ? new HashMap<>() : propertyMap;
      HttpURLConnection connection = (HttpURLConnection) requestUrl.openConnection();
      connection.setRequestMethod(method);
      connection.setDoOutput(false);
      connection.setDoInput(true);
      if (connection instanceof HttpsURLConnection){
        ((HttpsURLConnection)connection).setSSLSocketFactory(getSSLContext().getSocketFactory());
      }
      for (String property : propertyMap.keySet()){
        connection.setRequestProperty(property, propertyMap.get(property));
      }
      connection.setConnectTimeout(connectTimeout);
      connection.setReadTimeout(readTimeout);
      if (data != null){
        connection.setDoOutput(true);
        OutputStream out = connection.getOutputStream();
        try {
          IOUtils.write(data, out);
          out.flush();
        }
        finally {
          IOUtils.close(out);
        }
      }
      connection.connect();

      int responseCode = connection.getResponseCode();
      byte[] bytes;
      try {
        if (responseCode > 205 || responseCode < 200) {
          bytes = IOUtils.toByteArray(connection.getErrorStream());
        }
        else {
          bytes = IOUtils.toByteArray(connection.getInputStream());
        }
      }
      catch (IOException ex) {
        log.debug("Error receiving http data stream {}", ex.toString());
        return HttpResponse.builder()
          .data(null)
          .exception(ex)
          .responseCode(responseCode)
          .build();
      }
      return HttpResponse.builder()
        .data(bytes)
        .exception(null)
        .responseCode(responseCode)
        .build();
    }
    catch (Exception ex) {
      log.debug("Error setting up HTTP connection {}", ex.toString());
      return HttpResponse.builder()
        .data(null)
        .exception(ex)
        .responseCode(0)
        .build();
    }
  }

  private SSLContext getSSLContext() throws NoSuchAlgorithmException, KeyManagementException {
    final SSLContext sslContext = SSLContext.getInstance("SSL");
    sslContext.init(null, new TrustManager[]{new TrustAllTrustManager()}, new SecureRandom());
    return sslContext;
  }

  @NoArgsConstructor
  public static class TrustAllTrustManager implements X509TrustManager {
    @Override public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    }

    @Override public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
    }

    @Override public X509Certificate[] getAcceptedIssuers() {
      return null;
    }
  }


}
