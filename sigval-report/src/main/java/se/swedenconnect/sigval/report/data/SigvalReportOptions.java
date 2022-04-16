/*
 * Copyright (c) 2022. IDsec Solutions AB
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

package se.swedenconnect.sigval.report.data;

import lombok.AllArgsConstructor;
import lombok.Data;

/**
 * Description
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
@AllArgsConstructor
public class SigvalReportOptions {

  private boolean includeTimeStampCertRefs;
  private boolean includeSignatureCertChainRefs;
  private SignedDataRepresentation signedDataRepresentation;

  public SigvalReportOptions(SignedDataRepresentation signedDataRepresentation) {
    this.signedDataRepresentation = signedDataRepresentation;
    this.includeTimeStampCertRefs = false;
    this.includeSignatureCertChainRefs = false;
  }

  public SigvalReportOptions(boolean includeSignatureCertChainRefs,
    SignedDataRepresentation signedDataRepresentation) {
    this.includeSignatureCertChainRefs = includeSignatureCertChainRefs;
    this.signedDataRepresentation = signedDataRepresentation;
    this.includeTimeStampCertRefs = false;
  }

  public SigvalReportOptions() {
    this.signedDataRepresentation = SignedDataRepresentation.DIGEST;
    this.includeTimeStampCertRefs = false;
    this.includeSignatureCertChainRefs = false;
  }
}
