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

package se.idsec.sigval.cert.extensions.missing;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;

/**
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class OCSPNoCheck extends ASN1Object {

    public static final ASN1ObjectIdentifier OID = OCSPObjectIdentifiers.id_pkix_ocsp_nocheck;


    public static OCSPNoCheck getInstance() {
            return new OCSPNoCheck();
    }


    public OCSPNoCheck() {
    }


    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * InhibitAnyPolicy ::= SkipCerts
     * 
     * SkipCerts ::= INTEGER (0..MAX)
     * </pre>
     *
     * @return
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        return DERNull.INSTANCE;
    }

    @Override
    public String toString() {
        return "OCSP Nocheck";
    }
}
