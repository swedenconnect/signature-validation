/*
 * Copyright (c) 2020. Sweden Connect
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

package se.swedenconnect.sigval.cert.chain.impl;

import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertStore;
import java.security.cert.TrustAnchor;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import lombok.Setter;
import se.idsec.signservice.security.certificate.CertificateValidator;
import se.swedenconnect.sigval.cert.chain.AbstractPathValidator;
import se.swedenconnect.sigval.cert.chain.ExtendedCertPathValidatorException;
import se.swedenconnect.sigval.cert.chain.PathValidationResult;
import se.swedenconnect.sigval.cert.validity.crl.CRLCache;

/**
 * This is an implementation of the Certificate validator interface {@link CertificateValidator} in the sign service
 * commons library. An instance of this interface can perform any number of validations based on validation data input.
 *
 * This implementation uses an implementation of the Runnable {@link AbstractPathValidator} class to perform path
 * validation. Because the {@link AbstractPathValidator} is runnable that can be executed in a separate thread, it must
 * be instantiated for every instance of validation.
 *
 * Because this class creates a new {@link CertificatePathValidator} for each instance of path validation, a Factory
 * class is configured that provides instances of an implementation of the {@link AbstractPathValidator}. A default
 * implementation of this factory is included here but this can be replaced by a setter.
 *
 * If you need to run path validation in an isolated thread as a runnable object, then use the
 * {@link CertificatePathValidator} class directly instead of using this interface implementation.
 */
public class StatusCheckingCertificateValidatorImpl implements CertificateValidator, CertificatePathValidatorFactory {

  /** The CRL cache used to store and retrieve CRL data */
  private final CRLCache crlCache;
  
  /** Optional cert store holding additional supporting certificates but not trust anchors */
  private final CertStore certStore;
  
  /** default trust anchors always trusted */
  private List<X509Certificate> defaultTrustAnchors;
  
  /** Provider for the certificate path validator instance for each checked certificate path */
  @Setter
  private CertificatePathValidatorFactory certificatePathValidatorFactory;
  
  /** Setting this to true force revocation checking to be carried out in the main thread in a sequential process */
  @Setter
  private boolean singleThreaded = false;

  /**
   * Constructor for the CertificateValidator implementations
   *
   * @param crlCache
   *          The CRLCache used to support CRL status checking
   * @param certStore
   *          Optional cert store (mey be null) providing intermediary certificates
   * @param defaultTrustAnchors
   *          Optional default trust anchors used to validate certificate paths
   */
  public StatusCheckingCertificateValidatorImpl(CRLCache crlCache, CertStore certStore, X509Certificate... defaultTrustAnchors) {
    this.crlCache = crlCache;
    this.certStore = certStore;
    this.defaultTrustAnchors = Arrays.asList(defaultTrustAnchors);
    this.certificatePathValidatorFactory = this;
  }

  /**
   * Validate a certificate using default trust anchors
   *
   * <p>
   * This implementation does not support CRL input. the CRL input MUST be null or an empty list
   * </p>
   *
   * @param subjectCertificate
   *          The certificate to validate
   * @param additionalCertificates
   *          Supporting certificates used to construct a path to trusted certificates
   * @param crls
   *          Certificate revocation lists. This MUST be null or an empty list.
   * @return Result of certificate path building {@link PathValidationResult}
   * @throws CertPathBuilderException
   *           if certificate path building fails
   * @throws ExtendedCertPathValidatorException
   *           if certificate validation fails
   * @throws GeneralSecurityException
   *           never thrown but required by interface
   */
  @Override
  public PathValidationResult validate(final X509Certificate subjectCertificate,
      final List<X509Certificate> additionalCertificates,
      final List<X509CRL> crls)
      throws CertPathBuilderException, CertPathValidatorException, GeneralSecurityException {

    if (crls != null && !crls.isEmpty()) {
      throw new ExtendedCertPathValidatorException(new IllegalArgumentException("CRL input is not allowed in this implementation"));
    }
    return validatePath(subjectCertificate, additionalCertificates, defaultTrustAnchors);
  }

  /**
   * Validate a certificate using default trust anchors
   *
   * <p>
   * This implementation does not support CRL input. the CRL input MUST be null or an empty list
   * </p>
   *
   * @param subjectCertificate
   *          The certificate to validate
   * @param additionalCertificates
   *          Supporting certificates used to construct a path to trusted certificates
   * @param crls
   *          Certificate revocation lists. This MUST be null or an empty list
   * @param trustAnchors
   *          Trust anchors provided in addition to the default trust anchors
   * @return Path validation result
   * @throws CertPathBuilderException
   *           if certificate path building fails
   * @throws ExtendedCertPathValidatorException
   *           if certificate validation fails
   * @throws GeneralSecurityException
   *           never thrown but required by interface
   */
  @Override
  public PathValidationResult validate(final X509Certificate subjectCertificate,
      final List<X509Certificate> additionalCertificates,
      final List<X509CRL> crls,
      final List<X509Certificate> trustAnchors) throws CertPathBuilderException, CertPathValidatorException, GeneralSecurityException {
    if (crls != null && !crls.isEmpty()) {
      throw new ExtendedCertPathValidatorException(new IllegalArgumentException("CRL input is not allowed in this implementation"));
    }

    // Add provided trust anchors
    List<X509Certificate> allTrustedCerts = new ArrayList<>(defaultTrustAnchors);
    if (trustAnchors != null && !trustAnchors.isEmpty()) {
      trustAnchors.stream().forEach(x509Certificate -> allTrustedCerts.add(x509Certificate));
    }

    return validatePath(subjectCertificate, additionalCertificates, trustAnchors);
  }

  /**
   * Validate a certificate using default trust anchors
   *
   * @param subjectCertificate
   *          The certificate to validate
   * @param additionalCertificates
   *          Supporting certificates used to construct a path to trusted certificates
   * @return Result of certificate path building {@link PathValidationResult}
   * @throws CertPathBuilderException
   *           if certificate path building fails
   * @throws ExtendedCertPathValidatorException
   *           if certificate validation fails
   * @throws GeneralSecurityException
   *           never thrown but required by interface
   */
  public PathValidationResult validate(final X509Certificate subjectCertificate,
      final List<X509Certificate> additionalCertificates)
      throws CertPathBuilderException, CertPathValidatorException, GeneralSecurityException {

    return validatePath(subjectCertificate, additionalCertificates, defaultTrustAnchors);
  }

  private PathValidationResult validatePath(
      X509Certificate subjectCertificate, List<X509Certificate> additionalCertificates, List<X509Certificate> trustAnchorCerts)
      throws CertPathBuilderException, ExtendedCertPathValidatorException {

    if (trustAnchorCerts == null || trustAnchorCerts.isEmpty()) {
      throw new CertPathBuilderException("No trust anchor is provided for path building");
    }
    List<TrustAnchor> trustAnchors = trustAnchorCerts.stream()
      .map(x509Certificate -> new TrustAnchor(x509Certificate, null))
      .collect(Collectors.toList());

    AbstractPathValidator pathValidator = certificatePathValidatorFactory.getPathValidator(
      subjectCertificate, additionalCertificates, trustAnchors, certStore, crlCache);

    try {
      return pathValidator.validateCertificatePath();
    }
    catch (ExtendedCertPathValidatorException ex) {
      Throwable cause = ex.getCause();
      if (cause instanceof CertPathBuilderException) {
        throw (CertPathBuilderException) cause;
      }
      throw ex;
    }
  }

  @Override
  public AbstractPathValidator getPathValidator(X509Certificate targetCert, List<X509Certificate> chain,
      List<TrustAnchor> trustAnchors, CertStore certStore, CRLCache crlCache) {
    CertificatePathValidator pathValidator = new CertificatePathValidator(targetCert, chain, trustAnchors, certStore, crlCache);
    pathValidator.setSingleThreaded(singleThreaded);
    return pathValidator;
  }

  @Override
  public boolean isRevocationCheckingActive() {
    return true;
  }

  @Override
  public List<X509Certificate> getDefaultTrustAnchors() {
    return defaultTrustAnchors;
  }
}
