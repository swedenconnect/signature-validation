/*
 * Copyright 2021-2025 Sweden Connect
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
package se.swedenconnect.sigval.testca;

import java.io.IOException;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import se.swedenconnect.sigval.cert.validity.ocsp.OCSPDataLoader;

/**
 * An {@link OCSPDataLoader} that routes all OCSP requests to an in-memory {@link TestCA}
 * instead of making HTTP connections. The {@code url} parameter is matched against
 * {@link TestCA#ISSUING_OCSP_URL}; the actual host and port are irrelevant.
 *
 * <p>Usage:
 * <pre>{@code
 * TestCA testCA = TestCA.createDefault();
 * OCSPCertificateVerifier ocspVerifier = ...;
 * ocspVerifier.setOcspDataLoader(testCA.createOCSPDataLoader());
 * }</pre>
 */
public class TestOCSPDataLoader implements OCSPDataLoader {

  private final TestCA testCA;

  public TestOCSPDataLoader(final TestCA testCA) {
    this.testCA = testCA;
  }

  @Override
  public OCSPResp requestOCSPResponse(final String url, final OCSPReq ocspReq,
      final int connectTimeout, final int readTimeout) throws IOException {
    try {
      return testCA.getOCSPResponse(url, ocspReq);
    }
    catch (Exception e) {
      throw new IOException("TestOCSP responder failed for URL: " + url, e);
    }
  }
}
