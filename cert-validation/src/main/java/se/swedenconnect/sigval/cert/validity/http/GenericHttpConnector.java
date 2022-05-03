/*
 * Copyright (c) 2020-2022. Sweden Connect
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
package se.swedenconnect.sigval.cert.validity.http;

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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.io.IOUtils;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Generic implementation of HTTP GET and POST to support download of revocation data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@NoArgsConstructor
public class GenericHttpConnector {

  /**
   * Get resource from URL using HTTP GET
   * @param requestUrl url for the resource
   * @param connectTimeout milliseconds allowed to establish an HTTP connection with the resource
   * @param readTimeout milliseconds allowed to download the resource data
   * @return response data
   */
  public HttpResponse getResource(URL requestUrl, int connectTimeout, int readTimeout){
    return getResource(requestUrl, connectTimeout, readTimeout, null, null);
  }

  /**
   * Get resrouce from URL using either GET or POST. POST is automatically selected if some data to be posted is included as an argument
   * @param requestUrl url for the resource
   * @param connectTimeout milliseconds allowed to establish an HTTP connection with the resource
   * @param readTimeout milliseconds allowed to download the resource data
   * @param data data to be posted or null to select HTTP GET
   * @param propertyMap map of HTTP connect properties to add to the HTTP connection. The map key is the property name and the map value is the property value
   * @return response data
   */
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

  /**
   * Provide an SSL context that allows any TLS certificate issuer. No specific trust in the TLS certificate is required as all revocation data is signed
   * @return {@link SSLContext}
   * @throws NoSuchAlgorithmException algorithm is not supported
   * @throws KeyManagementException error handling keys
   */
  private SSLContext getSSLContext() throws NoSuchAlgorithmException, KeyManagementException {
    final SSLContext sslContext = SSLContext.getInstance("SSL");
    sslContext.init(null, new TrustManager[]{new TrustAllTrustManager()}, new SecureRandom());
    return sslContext;
  }

  /**
   * Trust manager trusting all certificates
   */
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
