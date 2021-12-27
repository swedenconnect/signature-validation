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

package se.swedenconnect.cert.extensions.data;

import com.sun.xml.bind.marshaller.NamespacePrefixMapper;

import java.util.HashMap;
import java.util.Map;

/**
 * Prefix mapper for producing XML output of the AuthnContext extension data
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AuthnContextPrefixMapper extends NamespacePrefixMapper {

  /** Map holding XML name space prefixes */
  private static final Map<String, String> prefixMap = new HashMap<String, String>();

  static {
    prefixMap.put("http://www.w3.org/2000/09/xmldsig#", "ds");
    prefixMap.put("http://www.w3.org/2001/04/xmlenc#", "xenc");
    prefixMap.put("urn:oasis:names:tc:SAML:2.0:assertion", "saml");
    prefixMap.put("http://www.w3.org/2001/XMLSchema", "xs");
    prefixMap.put("http://www.w3.org/2001/XMLSchema-instance", "xsi");
    prefixMap.put("http://id.elegnamnden.se/auth-cont/1.0/saml", "saci");
  }

  /** {@inheritDoc} */
  @Override public String getPreferredPrefix(String namespaceUri, String suggestion, boolean requirePrefix) {
    if (prefixMap.containsKey(namespaceUri)){
      return prefixMap.get(namespaceUri);
    }
    return suggestion;
  }
}
