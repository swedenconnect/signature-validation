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

package se.swedenconnect.sigval.cert.chain;

import lombok.Getter;
import se.swedenconnect.sigval.cert.validity.ValidationStatus;

import org.bouncycastle.jcajce.provider.asymmetric.x509.CertificateFactory;

import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Extended path validator exception providing detailed path validation result data
 *
 * <p>Note that several reasons for path building failure is not specified in the Reason result. To get these reasons you have to
 * parse through the throwable to find out why path validation failed.</p>
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class ExtendedCertPathValidatorException extends CertPathValidatorException {

  /** For serialization  */
  private static final long serialVersionUID = 4401265197086994174L;
  
  @Getter private PathValidationResult pathValidationResult;

  /**
   * Constructor
   *
   * @param msg message
   * @param cause Exception that was the underlying cause of this exception
   * @param pathValidationResult the path validation result obtained when path validation failed
   */
  public ExtendedCertPathValidatorException(String msg, Throwable cause, PathValidationResult pathValidationResult) {
    super(msg, cause, getPath(pathValidationResult), getIndex(pathValidationResult), getFailure(pathValidationResult));
    this.pathValidationResult = pathValidationResult;
  }

  /**
   * Constructor
   *
   * @param cause Exception that was the underlying cause of this exception
   * @param pathValidationResult the path validation result obtained when path validation failed
   */
  public ExtendedCertPathValidatorException(Throwable cause, PathValidationResult pathValidationResult) {
    super(cause.getMessage(), cause, getPath(pathValidationResult), getIndex(pathValidationResult), getFailure(pathValidationResult));
    this.pathValidationResult = pathValidationResult;
  }

  /**
   * Constructor
   * @param cause exception that caused path validation to fail
   */
  public ExtendedCertPathValidatorException(Throwable cause) {
    this(cause, PathValidationResult.builder().build());
  }

  private static Reason getFailure(PathValidationResult pathValidationResult) {
    PKIXCertPathBuilderResult pkixCertPathBuilderResult = pathValidationResult.getPkixCertPathBuilderResult();
    if (pkixCertPathBuilderResult == null) {
      return BasicReason.UNSPECIFIED;
    }
    List<ValidationStatus> validationStatusList = pathValidationResult.getValidationStatusList();
    for (int i = validationStatusList.size() - 1; i >= 0; i--) {
      switch (validationStatusList.get(i).getValidity()) {
      case REVOKED:
        return BasicReason.REVOKED;
      case INVALID:
      case UNKNOWN:
        return BasicReason.UNDETERMINED_REVOCATION_STATUS;
      default:
        break;
      }
    }
    return BasicReason.UNSPECIFIED;
  }

  private static int getIndex(PathValidationResult pathValidationResult) {
    PKIXCertPathBuilderResult pkixCertPathBuilderResult = pathValidationResult.getPkixCertPathBuilderResult();
    if (pkixCertPathBuilderResult == null) {
      return -1;
    }
    List<ValidationStatus> validationStatusList = pathValidationResult.getValidationStatusList();
    for (int i = validationStatusList.size() - 1; i >= 0; i--) {
      if (validationStatusList.get(i).getValidity() != ValidationStatus.CertificateValidity.VALID){
        return i;
      }
    }
    return -1;
  }

  private static CertPath getPath(PathValidationResult pathValidationResult) {
    List<X509Certificate> validatedCertificatePath = pathValidationResult.getValidatedCertificatePath();
    if (validatedCertificatePath == null) validatedCertificatePath = new ArrayList<>();
    try {
      CertificateFactory cf = new CertificateFactory();
      return cf.engineGenerateCertPath(validatedCertificatePath);
    }
    catch (Exception e) {
      return null;
    }
  }
}
