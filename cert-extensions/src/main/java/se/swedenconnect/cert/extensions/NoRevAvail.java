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

package se.swedenconnect.cert.extensions;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;

/**
 * noRevAvail X.509 extension RFC 9608 implementation for extending Bouncycastle
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class NoRevAvail extends ASN1Object {

    public static final ASN1ObjectIdentifier OID = Extension.noRevAvail;

    /**
     * Creates an instance of the OCSPNoCheck extension
     *
     * @return OCSPNoCheck extension
     */
    public static NoRevAvail getInstance() {
            return new NoRevAvail();
    }

    /**
     * Constructor
     */
    private NoRevAvail() {
    }


    /**
     * Produce an object suitable for an ASN1OutputStream.
     * @return ASN.1 object of the extension
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        return DERNull.INSTANCE;
    }

    /** {@inheritDoc} */
    @Override
    public String toString() {
        return "noRevAvail";
    }
}
