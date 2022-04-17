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

package se.swedenconnect.sigval.jose.data;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.UnprotectedHeader;
import lombok.Data;
import se.swedenconnect.sigval.commons.data.ExtendedSigValResult;

/**
 * Extended signature validation result for JSON signatures
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@Data
public class ExtendedJOSESigvalResult extends ExtendedSigValResult {

  /** Signature value of the JOSE signature */
  private byte[] signatureValue;
  /** The JWS header of the signature */
  private JWSHeader header;
  /** The unprotected header of the signature if present */
  private UnprotectedHeader unprotectedHeader;
  /** The payload of the signature (embedded or detached) */
  private Payload payload;

}
