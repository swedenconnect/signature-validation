/*
 * Copyright 2019-2020 IDsec Solutions AB
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
package se.idsec.sigval.cert.chain.impl;

import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import se.idsec.sigval.cert.chain.PathBuilder;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Implementation of a basic path builder used to construct a certificate path from a specified target certificate to a specified set
 * of trust anchors via a finite set of supporting intermediary CA certificates.
 *
 * This implementation uses standard PKIX path validation rules to construct and validate the path.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Slf4j
@NoArgsConstructor
public class BasicPathBuilder implements PathBuilder {

  private static final String PKIX_ALGORITHM = "PKIX";

  /** {@inheritDoc} */
  @Override public PKIXCertPathBuilderResult buildPath(X509Certificate targetCertificate, List<X509Certificate> supportingCertificates,
    CertStore intermediaryStore, List<TrustAnchor> trustAnchors) throws Exception {

    Set<TrustAnchor> trustAnchorSet = new HashSet<>(trustAnchors);

    // Create chain certs as the complete set off certificates additional to the certstore, including the target cert.
    List<X509Certificate> chainCerts = supportingCertificates == null
      ? new ArrayList<>()
      : new ArrayList<>(supportingCertificates);
    if (!chainCerts.contains(targetCertificate)){
      log.debug("Target certificate is added to provided certificate chain");
      chainCerts.add(targetCertificate);
    }
    // Exclude any self issued certificates from the chainCerts or else it will end up in the path built to the TA
    chainCerts = chainCerts.stream()
      .filter(certificate -> {
        try {
          certificate.verify(certificate.getPublicKey());
          log.debug("Removing a self signed cert from the supporting cert chain");
          return false;  //This cert is self issued. Exclude it.
        } catch (Exception ex) {
          return true; // This cert was not self issued. Keep it.
        }
      })
      .collect(Collectors.toList());
    log.debug("Provided chain including target certificate and excluding trust anchor contains {} certificate(s)", chainCerts.size());

    // Get cert stores
    List<CertStore> certStoreList = new ArrayList<>();
    if (intermediaryStore!=null){
      log.debug("Adding provided intermediary CA certificate store");
      certStoreList.add(intermediaryStore);
    }
    CertStore chainStore = CertStore.getInstance(
      "Collection",
      new CollectionCertStoreParameters(chainCerts),
      BouncyCastleProvider.PROVIDER_NAME);
    certStoreList.add(chainStore);

    PKIXBuilderParameters builderParameters = getBuilderParameters(targetCertificate, certStoreList, trustAnchorSet);
    CertPathBuilder certPathBuilder = CertPathBuilder.getInstance(PKIX_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
    PKIXCertPathBuilderResult certPathBuilderResult = (PKIXCertPathBuilderResult) certPathBuilder.build(builderParameters);

    logResult(certPathBuilderResult);
    return certPathBuilderResult;
  }

  private void logResult(PKIXCertPathBuilderResult certPathBuilderResult) {
    log.trace("cert path result: {}", certPathBuilderResult);
    try {
      certPathBuilderResult.getCertPath().getCertificates().stream()
        .map(certificate -> (X509Certificate)certificate)
        .forEach(certificate -> log.debug("path cert: {}", certificate.getSubjectX500Principal()));
    } catch (Exception ex){
      log.error("Error reading result path certificates",ex);
    }
    PolicyNode policyTree = certPathBuilderResult.getPolicyTree();
    log.debug("Policy tree: {}", policyTree);
  }

  /**
   * Obtains the path builder parameters
   * @param targetCert the certificate to build from
   * @param certStores list of supporting certificate cert stores
   * @param trustAnchors list of trust anchors based on X.509 certificates
   * @return path builder parameters
   * @throws InvalidAlgorithmParameterException if algorithm parameters are illegal
   */
  private PKIXBuilderParameters getBuilderParameters(X509Certificate targetCert, List<CertStore> certStores, Set<TrustAnchor> trustAnchors)
    throws InvalidAlgorithmParameterException {
    X509CertSelector certSelect = new X509CertSelector();
    certSelect.setCertificate(targetCert);
    PKIXBuilderParameters pkixParameters = new PKIXBuilderParameters(trustAnchors, certSelect);
    certStores.stream().forEach(certStore -> pkixParameters.addCertStore(certStore));
    pkixParameters.setRevocationEnabled(false);
    pkixParameters.setMaxPathLength(-1);
    return pkixParameters;
  }

}
