/*
 * Copyright (c) 2021. Sweden Connect
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

package se.swedenconnect.sigval.cert.validity.ocsp;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;

import java.io.IOException;

public interface OCSPDataLoader {

  /**
   * Get an OCSP response from the
   * @param url OCSP request URL
   * @param ocspReq OCSP request to send to the OCSP responder
   * @param connectTimeout max time in milliseconds allowed for an HTTP connect
   * @param readTimeout max time in milliseconds allowed for reading the referenced data object
   * @return OCSP Response
   * @throws IOException Error sending or receiving data
   */
  OCSPResp requestOCSPResponse(String url, OCSPReq ocspReq, int connectTimeout, int readTimeout) throws IOException;
}
