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

package se.idsec.x509cert.extensions;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import java.math.BigInteger;

/**
 * InhibitAnyPolicy X.509 extension implementation for extending Bouncycastle
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class InhibitAnyPolicy extends ASN1Object {

    public static final ASN1ObjectIdentifier OID = Extension.inhibitAnyPolicy;
    BigInteger skipCerts;

    public static InhibitAnyPolicy getInstance(Object obj) {
        if (obj instanceof InhibitAnyPolicy) {
            return (InhibitAnyPolicy) obj;
        }
        if (obj != null) {
            return new InhibitAnyPolicy(ASN1Integer.getInstance(obj));
        }
        return null;
    }

    public static InhibitAnyPolicy fromExtensions(Extensions extensions) {
        return InhibitAnyPolicy.getInstance(extensions.getExtensionParsedValue(OID));
    }

    /**
     * Parse the content of ASN1 sequence to populate set values
     *
     * @param skipCerts
     */
    private InhibitAnyPolicy(ASN1Integer skipCerts) {
        try {
            this.skipCerts = skipCerts.getPositiveValue();
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad extension content");
        }
    }

    public InhibitAnyPolicy(int skipcerts) {
        this.skipCerts = BigInteger.valueOf(skipcerts);
    }

    public BigInteger getSkipCerts() {
        return skipCerts;
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
        return new ASN1Integer(skipCerts);
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        b.append("Skip certs: ").append(skipCerts).append("\n");
        return b.toString();
    }
}
