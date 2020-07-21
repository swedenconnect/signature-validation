package se.idsec.sigval.cert.chain.impl;

import lombok.NoArgsConstructor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import se.idsec.sigval.cert.chain.PathBuilder;

import java.security.InvalidAlgorithmParameterException;
import java.security.cert.*;
import java.util.*;
import java.util.stream.Collectors;

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
      chainCerts.add(targetCertificate);
    }

    // Get cert stores
    List<CertStore> certStoreList = new ArrayList<>();
    if (intermediaryStore!=null){
      certStoreList.add(intermediaryStore);
    }
    CertStore chainStore = CertStore.getInstance(
      "Collection",
      new CollectionCertStoreParameters(chainCerts),
      BouncyCastleProvider.PROVIDER_NAME);
    certStoreList.add(chainStore);

    PKIXBuilderParameters builderParameters = getBuilderParameters(targetCertificate, certStoreList, trustAnchorSet);
    CertPathBuilder certPathBuilder = CertPathBuilder.getInstance(PKIX_ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
    return (PKIXCertPathBuilderResult) certPathBuilder.build(builderParameters);
  }

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

  /**
   * This method returns the resulting path as a list of certificates starting from the target certificate, ending in the trust anchor certificate
   * This method requires that the function "getTrustedPath" has been called
   * @param result
   * @return
   */
  public List<X509Certificate> getResultPath(PKIXCertPathBuilderResult result){
    try {
      List<X509Certificate> x509CertificateList = result.getCertPath().getCertificates().stream()
        .map(certificate -> (X509Certificate) certificate)
        .collect(Collectors.toList());
      List<X509Certificate> resultPath = new ArrayList<>(x509CertificateList);
      resultPath.add(result.getTrustAnchor().getTrustedCert());
      return resultPath;
    } catch (Exception ex){
      throw new RuntimeException(ex.getMessage());
    }
  }

}
