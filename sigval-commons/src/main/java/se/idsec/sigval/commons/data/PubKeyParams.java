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

package se.idsec.sigval.commons.data;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import se.idsec.sigval.commons.algorithms.NamedCurve;
import se.idsec.sigval.commons.algorithms.PublicKeyType;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PubKeyParams {

  /** Public key type **/
  private PublicKeyType pkType;
  /** The ECC curve if the signature is signed with ECDSA **/
  private NamedCurve namedEcCurve;
  /** Length of the signature key used for the  sig algorithm **/
  private int keyLength;

}
