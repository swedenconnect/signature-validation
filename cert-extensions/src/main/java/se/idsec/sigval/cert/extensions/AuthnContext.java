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

package se.idsec.sigval.cert.extensions;

import org.apache.xmlbeans.XmlException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.X509Extension;
import se.elegnamnden.id.authCont.x10.saci.SAMLAuthContextDocument;
import se.idsec.sigval.cert.utils.XmlBeansUtil;

import java.io.ByteArrayInputStream;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Logger;

/**
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class AuthnContext extends ASN1Object {

    public static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.2.752.201.5.1");
    public static final String CONTENT_TYPE = "http://id.elegnamnden.se/auth-cont/1.0/saci";
    List<SAMLAuthContextDocument> statementInfoList = new ArrayList<>();

    public static AuthnContext getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static AuthnContext getInstance(Object obj) {
        if (obj instanceof AuthnContext) {
            return (AuthnContext) obj;
        }
        if (obj instanceof X509Extension) {
            return getInstance(X509Extension.convertValueToObject((X509Extension) obj));
        }
        if (obj != null) {
            return new AuthnContext(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static AuthnContext fromExtensions(Extensions extensions) {
        return AuthnContext.getInstance(extensions.getExtensionParsedValue(OID));
    }

    /**
     * Parse the content of ASN1 sequence to populate set values
     *
     * @param seq
     */
    private AuthnContext(ASN1Sequence seq) {
        this.statementInfoList = new ArrayList<>();
        try {
            for (int i = 0; i < seq.size(); i++) {
                ASN1Sequence contSeq = ASN1Sequence.getInstance(seq.getObjectAt(i));
                DERUTF8String contextType = DERUTF8String.getInstance(contSeq.getObjectAt(0));
                DERUTF8String contextInfo = DERUTF8String.getInstance(contSeq.getObjectAt(1));
                SAMLAuthContextDocument authnContxtDoc = SAMLAuthContextDocument.Factory.parse(new ByteArrayInputStream(contextInfo.getString().getBytes(
                  Charset.forName("UTF-8"))));
                if (contextType.getString().equalsIgnoreCase(CONTENT_TYPE)) {
                    statementInfoList.add(authnContxtDoc);
                }
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad extension content");
        }
    }

    public AuthnContext(List<SAMLAuthContextDocument> statementInfoList) {
        this.statementInfoList = statementInfoList;
    }

    public List<SAMLAuthContextDocument> getStatementInfoList() {
        return statementInfoList;
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * AuthenticationContexts ::= SEQUENCE SIZE (1..MAX) OF
     *                            AuthenticationContext
     *
     * AuthenticationContext ::= SEQUENCE {
     *     contextType     UTF8String,
     *     contextInfo     UTF8String OPTIONAL
     * }
     * </pre>
     *
     * @return
     */
    @Override
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector authnConexts = new ASN1EncodableVector();

        for (SAMLAuthContextDocument statementInfo : statementInfoList) {
            ASN1EncodableVector authnConext = new ASN1EncodableVector();
            try {
                authnConext.add(new DERUTF8String(CONTENT_TYPE));
                SAMLAuthContextDocument strippedContextInfo = SAMLAuthContextDocument.Factory.parse(statementInfo.getDomNode(), XmlBeansUtil.stripWhiteSPcae);
                String contextXML = new String(XmlBeansUtil.getBytes(strippedContextInfo, false), Charset.forName("UTF-8"));
                authnConext.add(new DERUTF8String(contextXML));
                authnConexts.add(new DERSequence(authnConext));
            } catch (XmlException ex) {
                Logger.getLogger(AuthnContext.class.getName()).warning(ex.getMessage());
            }
        }
        return new DERSequence(authnConexts);
    }

    @Override
    public String toString() {
        StringBuilder b = new StringBuilder();
        //b.append("AuthenticationContext [\n");
        for (SAMLAuthContextDocument statementInfo : statementInfoList) {
            b.append(" SAML Authentication Context Info (http://id.elegnamnden.se/auth-cont/1.0/saci):\n");
            b.append(new String(XmlBeansUtil.getStyledBytes(statementInfo, false), Charset.forName("UTF-8"))).append("\n");
        }
        //b.append("]\n");
        return b.toString();
    }
}
