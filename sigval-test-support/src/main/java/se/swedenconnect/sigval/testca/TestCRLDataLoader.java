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

import se.swedenconnect.sigval.cert.validity.crl.impl.CRLDataLoader;

/**
 * A {@link CRLDataLoader} that routes all CRL requests to an in-memory {@link TestCA}
 * instead of making HTTP connections. The {@code url} parameter is matched against the
 * URLs embedded in test certificates ({@link TestCA#ROOT_CRL_URL},
 * {@link TestCA#ISSUING_CRL_URL}); the actual host and port are irrelevant.
 *
 * <p>Usage:
 * <pre>{@code
 * TestCA testCA = TestCA.createDefault();
 * InMemoryCRLCache crlCache = new InMemoryCRLCache(0, testCA.createCRLDataLoader());
 * }</pre>
 */
public class TestCRLDataLoader implements CRLDataLoader {

  private final TestCA testCA;

  public TestCRLDataLoader(final TestCA testCA) {
    this.testCA = testCA;
  }

  @Override
  public byte[] downloadCrl(final String url, final int connectTimeout, final int readTimeout)
      throws IOException {
    return testCA.getCRL(url);
  }
}
