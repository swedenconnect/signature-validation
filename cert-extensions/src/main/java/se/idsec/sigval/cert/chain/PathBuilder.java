package se.idsec.sigval.cert.chain;

import java.security.cert.CertPathBuilderResult;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 *
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
  CertPathBuilderResult buildPath(
    X509Certificate targetCertificate,
    List<X509Certificate> supportingCertificates,
    CertStore intermediaryStore,
    List<TrustAnchor> trustAnchors) throws Exception;
}
