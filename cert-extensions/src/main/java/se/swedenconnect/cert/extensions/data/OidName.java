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
package se.swedenconnect.cert.extensions.data;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.bouncycastle.asn1.x509.AccessDescription;

/**
 * Enumeration of relevant Object Identifiers
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@AllArgsConstructor
@Getter
public enum OidName {
    cp_anyPolicy("anyPolicy", "2.5.29.32.0"),
    cp_etsiQcPubSscd("ETSI QC Public with SSCD (0.4.0.1456.1.1)", "0.4.0.1456.1.1"),
    cp_etsiQcPub("ETSI QC Public (0.4.0.1456.1.2)", "0.4.0.1456.1.2"),
    cpsQualifier("CPS Qualifier", "1.3.6.1.5.5.7.2.1"),
    usernoticeQualifier("User notice Qualifier", "1.3.6.1.5.5.7.2.2"),
    serverAuth("Server Auth", "1.3.6.1.5.5.7.3.1"),
    clientAuth("Client Auth", "1.3.6.1.5.5.7.3.2"),
    codeSigning("Code Signing", "1.3.6.1.5.5.7.3.3"),
    emailProtection("Email Protection", "1.3.6.1.5.5.7.3.4"),
    timeStamping("Time Stamping", "1.3.6.1.5.5.7.3.8"),
    OCSPSigning("OCSP Signing", "1.3.6.1.5.5.7.3.9"),
    smartCardLogon("SmartCard Logon","1.3.6.1.4.1.311.20.2.2"),
    certRequestEnrollment("Cert Request Enrollment","1.3.6.1.4.1.311.20.2.1"),
    rootListSigning("Root List Signing","1.3.6.1.4.1.311.10.3.9"),
    etsiSemanticsID_Natural("id-etsi-qcs-semanticsId-Natural","0.4.0.194121.1.1"),
    etsiSemanticsID_Legal("id-etsi-qcs-semanticsId-Legal","0.4.0.194121.1.2"),
    eIDASSemanticsID_Natural("id-etsi-qcs-semanticsId-eIDASNatural","0.4.0.194121.1.3"),
    eIDASSemanticsID_Legal("id-etsi-qcs-semanticsId-eIDASLegal","0.4.0.194121.1.4"),
    entrVersionExt("Entrust Version Extension", "1.2.840.113533.7.65.0"),
    netscapeCertType("Netscape Certificate Type", "2.16.840.1.113730.1.1"),
    id_pkix_ad_caRepository("caRepository","1.3.6.1.5.5.7.48.5"),
    id_pkix_ad_timestamping("timeStamping","1.3.6.1.5.5.7.48.3"),
    id_pkix_ad_caIssuers("caIssuers", AccessDescription.id_ad_caIssuers.getId()),
    id_pkix_ad_ocsp("ocsp", AccessDescription.id_ad_ocsp.getId()),
    id_pkix_ocsp_nocheck("OCSP No Check Extension", "1.3.6.1.5.5.7.48.1.5");

    /** Friendly name of the OID */
    private String name;
    /** Object Identifier String */
    private String oid;
}
