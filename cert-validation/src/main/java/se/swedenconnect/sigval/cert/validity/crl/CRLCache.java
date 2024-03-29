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

package se.swedenconnect.sigval.cert.validity.crl;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.asn1.x509.CRLDistPoint;

/**
 * CRL Cache interface
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public interface CRLCache {

  String LDAP_CONNECT_TIMEOUT = "com.sun.jndi.ldap.connect.timeout";
  String LDAP_READ_TIMEOUT = "com.sun.jndi.ldap.read.timeout";
  String LDAP_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
  int DEFAULT_CONNECT_TIMEOUT = 1000;
  int DEFAULT_READ_TIMEOUT = 7000;

  /**
   * Obtains the current CRL indicated by a CRL distribution point extension and add this CRL to the active cache.
   *
   * @param crlDistributionPointExt CRL Distribution point extension
   * @return CRL
   * @throws IOException On error obtaining a CRL based on this extension
   */
  CRLInfo getCRL(CRLDistPoint crlDistributionPointExt) throws IOException;

  /**
   * Obtains the current CRL specified by a CRL access URL
   * @param url CRL access URL
   * @return {@link CRLInfo} object if a CRL could be obtained
   * @throws IOException On error obtaining a CRL based on this URL
   */
  CRLInfo getCRL(String url) throws IOException;

  /**
   * Update the current cache. Implementations of this function must be thread safe, allowing use of the CRL cache while it is being updated.
   */
  void recache();

  List<CRLCacheRecord> getCrlCacheRecords();

}
