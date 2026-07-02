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

import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

/**
 * JUnit 5 extension that creates and exposes an embedded {@link TestCA} for a test class.
 *
 * <p>Declare it as a {@code static} field so it is shared across all test methods in the class:
 *
 * <pre>{@code
 * @RegisterExtension
 * static final SigValTestExtension CA = new SigValTestExtension();
 *
 * @Test
 * void myTest() {
 *   TestCA testCA = CA.getTestCA();
 *   X509Certificate cert = testCA.issueSigningCertificate(keyPair.getPublic(), "Test Signer");
 *   InMemoryCRLCache crlCache = new InMemoryCRLCache(0, testCA.createCRLDataLoader());
 *   // ... build validators and run assertions
 * }
 * }</pre>
 *
 * <p>To override the signing algorithm or EC curve, supply them in the constructor:
 * <pre>{@code
 * static final SigValTestExtension CA = new SigValTestExtension(
 *     CAAlgorithmRegistry.ALGO_ID_SIGNATURE_ECDSA_SHA384, "P-384");
 * }</pre>
 */
@Slf4j
public class SigValTestExtension implements BeforeAllCallback {

  private final String algorithm;
  private final String ecCurve;

  @Getter
  private TestCA testCA;

  /**
   * Creates the extension with the default algorithm ({@value TestCA#DEFAULT_ALGORITHM})
   * and curve (P-256).
   */
  public SigValTestExtension() {
    this(TestCA.DEFAULT_ALGORITHM, "P-256");
  }

  /**
   * Creates the extension with a specific signing algorithm and EC curve.
   *
   * @param algorithm XML algorithm URI, e.g. {@link se.swedenconnect.ca.engine.configuration.CAAlgorithmRegistry#ALGO_ID_SIGNATURE_ECDSA_SHA384}
   * @param ecCurve   EC curve name, e.g. {@code "P-384"}
   */
  public SigValTestExtension(final String algorithm, final String ecCurve) {
    this.algorithm = algorithm;
    this.ecCurve = ecCurve;
  }

  /**
   * Initialises the embedded CA before any test in the class runs.
   * When the extension field is {@code static}, this is called once per test class.
   */
  @Override
  public void beforeAll(final ExtensionContext context) throws Exception {
    if (testCA == null) {
      log.info("Initialising embedded test CA for {} [algorithm={}, curve={}]",
          context.getDisplayName(), algorithm, ecCurve);
      testCA = TestCA.create(algorithm, ecCurve);
      testCA.logCertificate(testCA.getRootCACertificate(), "Root CA certificate");
      testCA.logCertificate(testCA.getIssuingCACertificate(), "Issuing CA certificate");
    }
  }
}
