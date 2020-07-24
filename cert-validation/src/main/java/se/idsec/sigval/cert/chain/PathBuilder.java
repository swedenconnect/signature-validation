/*
 * Copyright (c) 2020. IDsec Solutions AB
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
package se.idsec.sigval.cert.chain;

import java.security.cert.*;
import java.util.List;

/**
 * Interface for a path builder used to construct valid X.509 Certificate paths from a target certificate to a trust anchor.
 * In order to support OCSP validity checking, all trust anchors must be in the form of X.509 Certificates as this is required
 * to construct the OCSP requester ID.
 *
 * Implementations of this interface MUST be thread safe, allowing one implemented object to serve multiple parallel threads.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface PathBuilder {

  /**
   * Builds the trusted path to a target certificate using the PKIX path building algorithm
   * @param targetCertificate the target certificate the should be validated through this path
   * @param supportingCertificates supporting certificates provided with the target certificate such as with the validated signature
   * @param intermediaryStore preconfigured store of intermediary CA certificates
   * @param trustAnchors certificates that are trusted as trust anchors in the path building process
   * @return {@link CertPathBuilderResult} results from path building
   * @throws Exception thrown if certificate path building fails
   */
  PKIXCertPathBuilderResult buildPath(
    X509Certificate targetCertificate,
    List<X509Certificate> supportingCertificates,
    CertStore intermediaryStore,
    List<TrustAnchor> trustAnchors) throws Exception;
}
