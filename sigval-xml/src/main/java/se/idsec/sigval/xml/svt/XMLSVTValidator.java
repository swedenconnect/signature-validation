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

package se.idsec.sigval.xml.svt;

import se.idsec.sigval.svt.validation.SVTValidator;
import se.idsec.sigval.svt.validation.SignatureSVTData;

import java.util.List;

public class XMLSVTValidator extends SVTValidator {

  /** {@inheritDoc} */
  @Override protected List<SignatureSVTData> getSignatureSVTData(byte[] signedDocument) throws Exception {
    return null;
  }
}
