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

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.qualified.QCStatement;
import se.idsec.sigval.cert.utils.CertUtils;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
public class QCStatementsExt extends ASN1Object {

    public static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3");
    public static final ASN1ObjectIdentifier PKIX_SYNTAX_V1 = QCStatement.id_qcs_pkixQCSyntax_v1;
    public static final ASN1ObjectIdentifier PKIX_SYNTAX_V2 = QCStatement.id_qcs_pkixQCSyntax_v2;
    public static final ASN1ObjectIdentifier QC_COMPLIANCE = QCStatement.id_etsi_qcs_QcCompliance;
    public static final ASN1ObjectIdentifier QC_SSCD = QCStatement.id_etsi_qcs_QcSSCD;
    public static final ASN1ObjectIdentifier QC_TYPE = new ASN1ObjectIdentifier("0.4.0.1862.1.6");
    public static final ASN1ObjectIdentifier QC_TYPE_ELECTRONIC_SIGNATURE = new ASN1ObjectIdentifier("0.4.0.1862.1.6.1");
    public static final ASN1ObjectIdentifier QC_TYPE_ELECTRONIC_SEAL = new ASN1ObjectIdentifier("0.4.0.1862.1.6.2");
    public static final ASN1ObjectIdentifier QC_TYPE_WEBSITE_AUTH = new ASN1ObjectIdentifier("0.4.0.1862.1.6.3");
    public static final ASN1ObjectIdentifier LIMITVAL = QCStatement.id_etsi_qcs_LimiteValue;
    public static final ASN1ObjectIdentifier RETENTION_PERIOD = QCStatement.id_etsi_qcs_RetentionPeriod;
    public static final ASN1ObjectIdentifier PKI_DISCLOSURE = new ASN1ObjectIdentifier("0.4.0.1862.1.5");

    boolean pkixSyntaxV1;
    boolean pkixSyntaxV2;
    boolean qcCompliance;
    boolean pdsStatement;
    boolean qcSscd;
    boolean qcType;
    boolean retentionPeriod;
    boolean limitValue;
    MonetaryValue monetaryValue;
    List<ASN1ObjectIdentifier> qcTypeIdList = new ArrayList<>();
    BigInteger retentionPeriodVal;
    List<PDSLocation> locationList = new ArrayList<>();
    SemanticsInformation semanticsInfo;

    public static QCStatementsExt getInstance(ASN1TaggedObject obj, boolean explicit) {
        return getInstance(ASN1Sequence.getInstance(obj, explicit));
    }

    public static QCStatementsExt getInstance(Object obj) {
        if (obj instanceof QCStatementsExt) {
            return (QCStatementsExt) obj;
        }
        if (obj instanceof X509Extension) {
            return getInstance(X509Extension.convertValueToObject((X509Extension) obj));
        }
        if (obj != null) {
            return new QCStatementsExt(ASN1Sequence.getInstance(obj));
        }

        return null;
    }

    public static QCStatementsExt fromExtensions(Extensions extensions) {
        return QCStatementsExt.getInstance(extensions.getExtensionParsedValue(OID));
    }

    public boolean isPkixSyntaxV1() {
        return pkixSyntaxV1;
    }

    public void setPkixSyntaxV1(boolean pkixSyntaxV1) {
        this.pkixSyntaxV1 = pkixSyntaxV1;
    }

    public boolean isPkixSyntaxV2() {
        return pkixSyntaxV2;
    }

    public void setPkixSyntaxV2(boolean pkixSyntaxV2) {
        this.pkixSyntaxV2 = pkixSyntaxV2;
    }

    public boolean isQcCompliance() {
        return qcCompliance;
    }

    public void setQcCompliance(boolean qcCompliance) {
        this.qcCompliance = qcCompliance;
    }

    public boolean isPdsStatement() {
        return pdsStatement;
    }

    public void setPdsStatement(boolean pdsStatement) {
        this.pdsStatement = pdsStatement;
    }

    public boolean isQcSscd() {
        return qcSscd;
    }

    public void setQcSscd(boolean qcSscd) {
        this.qcSscd = qcSscd;
    }

    public boolean isQcType() {
        return qcType;
    }

    public void setQcType(boolean qcType) {
        this.qcType = qcType;
    }

    public boolean isRetentionPeriod() {
        return retentionPeriod;
    }

    public void setRetentionPeriod(boolean retentionPeriod) {
        this.retentionPeriod = retentionPeriod;
    }

    public boolean isLimitValue() {
        return limitValue;
    }

    public void setLimitValue(boolean limitValue) {
        this.limitValue = limitValue;
    }

    public MonetaryValue getMonetaryValue() {
        return monetaryValue;
    }

    public void setMonetaryValue(MonetaryValue monetaryValue) {
        this.monetaryValue = monetaryValue;
    }

    public List<ASN1ObjectIdentifier> getQcTypeIdList() {
        return qcTypeIdList;
    }

    public void setQcTypeIdList(List<ASN1ObjectIdentifier> qcTypeIdList) {
        this.qcTypeIdList = qcTypeIdList;
    }

    public BigInteger getRetentionPeriodVal() {
        return retentionPeriodVal;
    }

    public void setRetentionPeriodVal(BigInteger retentionPeriodVal) {
        this.retentionPeriodVal = retentionPeriodVal;
    }

    public List<PDSLocation> getLocationList() {
        return locationList;
    }

    public void setLocationList(List<PDSLocation> locationList) {
        this.locationList = locationList;
    }

    public SemanticsInformation getSemanticsInfo() {
        return semanticsInfo;
    }

    public void setSemanticsInfo(SemanticsInformation semanticsInfo) {
        this.semanticsInfo = semanticsInfo;
    }

    /**
     * Parse the content of ASN1 sequence to populate set values
     *
     * @param seq
     */
    private QCStatementsExt(ASN1Sequence seq) {

        try {
            for (int i = 0; i < seq.size(); i++) {
                ASN1Sequence statementSeq = ASN1Sequence.getInstance(seq.getObjectAt(i));
                setStatementVals(statementSeq);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Bad extension content");
        }
    }

    public QCStatementsExt() {
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
        ASN1EncodableVector qcStatements = new ASN1EncodableVector();

        if (pkixSyntaxV1) {
            setSemanticsInfo(qcStatements, PKIX_SYNTAX_V1);
        }
        if (pkixSyntaxV2) {
            setSemanticsInfo(qcStatements, PKIX_SYNTAX_V2);
        }
        if (qcCompliance) {
            setStatementVal(qcStatements, QC_COMPLIANCE);
        }
        if (qcSscd) {
            setStatementVal(qcStatements, QC_SSCD);
        }
        if (qcType) {
            ASN1EncodableVector typeSeq = new ASN1EncodableVector();
            for (ASN1ObjectIdentifier type : qcTypeIdList) {
                typeSeq.add(type);
            }
            setStatementVal(qcStatements, QC_TYPE, new DERSequence(typeSeq));
        }
        if (limitValue) {
            ASN1EncodableVector limitSeq = new ASN1EncodableVector();
            limitSeq.add(new DERPrintableString(monetaryValue.getCurrency()));
            limitSeq.add(new ASN1Integer(monetaryValue.getAmount()));
            limitSeq.add(new ASN1Integer(monetaryValue.getExponent()));
            setStatementVal(qcStatements, LIMITVAL, new DERSequence(limitSeq));
        }
        if (retentionPeriod) {
            setStatementVal(qcStatements, RETENTION_PERIOD, new ASN1Integer(retentionPeriodVal));
        }
        if (pdsStatement) {
            ASN1EncodableVector pdsSeq = new ASN1EncodableVector();
            for (PDSLocation pdsLoc : locationList) {
                ASN1EncodableVector pdsLocSeq = new ASN1EncodableVector();
                pdsLocSeq.add(new DERIA5String(pdsLoc.getUrl()));
                pdsLocSeq.add(new DERPrintableString(pdsLoc.getLang()));
                pdsSeq.add(new DERSequence(pdsLocSeq));
            }
            setStatementVal(qcStatements, PKI_DISCLOSURE, new DERSequence(pdsSeq));
        }

        return new DERSequence(qcStatements);
    }

    public String toString() {
        StringBuilder b = new StringBuilder();
        //b.append("QCStatements [\n");
        if (pkixSyntaxV1) {
            b.append("  QC Syntax V1\n");
        }
        if (pkixSyntaxV2) {
            b.append("  QC Syntax V2\n");
        }
        if (pkixSyntaxV1 || pkixSyntaxV2) {
            if (semanticsInfo != null) {
                if (semanticsInfo.getSemanticsIdentifier() != null) {
                    b.append("    - SemanticsID: ").append(semanticsInfo.getSemanticsIdentifier().getId()).append("\n");
                }
                if (!semanticsInfo.getNameRegistrationAuthorityList().isEmpty()) {
                    semanticsInfo.getNameRegistrationAuthorityList().forEach((name) -> {
                        b.append("    - NameRegistrationAuthority: ").append(CertUtils.getGeneralNameStr(name)).append("\n");
                    });
                }
            }
        }

        if (qcCompliance) {
            b.append("  QC Compliance\n");
        }
        if (qcSscd) {
            b.append("  QC SSCD\n");
        }
        if (qcType) {
            b.append("  QC Types\n");
            for (ASN1ObjectIdentifier type : qcTypeIdList) {
                if (type.getId().equalsIgnoreCase(QC_TYPE_ELECTRONIC_SIGNATURE.getId())) {
                    b.append("    - Electronic Signature\n");
                }
                if (type.getId().equalsIgnoreCase(QC_TYPE_ELECTRONIC_SEAL.getId())) {
                    b.append("    - Electronic Seal\n");
                }
                if (type.getId().equalsIgnoreCase(QC_TYPE_WEBSITE_AUTH.getId())) {
                    b.append("    - Website Authentication\n");
                }
            }
        }
        if (limitValue) {
            b.append("  Reliance Limit\n");
            b.append("    - Currency: ").append(monetaryValue.getCurrency()).append("\n");
            b.append("    - Amount: ").append(monetaryValue.getAmount()).append("\n");
            b.append("    - Exponent: ").append(monetaryValue.getExponent()).append("\n");
        }
        if (retentionPeriod) {
            b.append("  Retention Period\n");
            b.append("    - Years after cert expiry: ").append(retentionPeriodVal).append("\n");
        }
        if (pdsStatement) {
            b.append("  PKI Disclosure Statements\n");
            for (PDSLocation pdsLoc : locationList) {
                b.append("    Location\n");
                b.append("     - URL: ").append(pdsLoc.getUrl()).append("\n");
                b.append("     - Lang: ").append(pdsLoc.getLang()).append("\n");
            }
        }
        //b.append("]\n");

        return b.toString();
    }

    private void clearAll() {
        setPkixSyntaxV1(false);
        setPkixSyntaxV2(false);
        setQcCompliance(false);
        setQcSscd(false);
        setQcType(false);
        setLimitValue(false);
        setRetentionPeriod(false);
        setPdsStatement(false);

    }

    private void setStatementVals(ASN1Sequence statementSeq) {
        try {
            String statementIdStr = ASN1ObjectIdentifier.getInstance(statementSeq.getObjectAt(0)).getId();
            if (statementIdStr.equals(PKIX_SYNTAX_V1.getId())) {
                setPkixSyntaxV1(true);
            }
            if (statementIdStr.equals(PKIX_SYNTAX_V2.getId())) {
                setPkixSyntaxV2(true);
            }
            if (statementIdStr.equals(PKIX_SYNTAX_V2.getId()) || statementIdStr.equals(PKIX_SYNTAX_V1.getId())) {
                if (statementSeq.size() > 1) {
                    ASN1Sequence siSeq = ASN1Sequence.getInstance(statementSeq.getObjectAt(1));
                    semanticsInfo = new SemanticsInformation();
                    for (int i = 0; i < siSeq.size(); i++) {
                        getSemanticsInfoVals(siSeq.getObjectAt(i));
                    }
                }
            }
            if (statementIdStr.equals(QC_COMPLIANCE.getId())) {
                setQcCompliance(true);
            }
            if (statementIdStr.equals(QC_SSCD.getId())) {
                setQcSscd(true);
            }
            if (statementIdStr.equals(QC_TYPE.getId())) {
                setQcType(true);
                ASN1Sequence qcTypeSequence = ASN1Sequence.getInstance(statementSeq.getObjectAt(1));
                qcTypeIdList = new ArrayList<>();
                for (int i = 0; i < qcTypeSequence.size(); i++) {
                    ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(qcTypeSequence.getObjectAt(i));
                    qcTypeIdList.add(type);
                }
            }
            if (statementIdStr.equals(LIMITVAL.getId())) {
                setLimitValue(true);
                ASN1Sequence lvSequence = ASN1Sequence.getInstance(statementSeq.getObjectAt(1));
                ASN1Encodable currencyEnc = lvSequence.getObjectAt(0);
                String currency = currencyEnc instanceof DERPrintableString ? DERPrintableString.getInstance(currencyEnc).getString() : ASN1Integer
                  .getInstance(currencyEnc).getValue().toString();
                BigInteger amount = ASN1Integer.getInstance(lvSequence.getObjectAt(1)).getValue();
                BigInteger exp = ASN1Integer.getInstance(lvSequence.getObjectAt(2)).getValue();
                monetaryValue = new MonetaryValue(currency, amount, exp);
            }
            if (statementIdStr.equals(RETENTION_PERIOD.getId())) {
                setRetentionPeriod(true);
                retentionPeriodVal = ASN1Integer.getInstance(statementSeq.getObjectAt(1)).getValue();
            }
            if (statementIdStr.equals(PKI_DISCLOSURE.getId())) {
                setPdsStatement(true);
                ASN1Sequence pdsSequence = ASN1Sequence.getInstance(statementSeq.getObjectAt(1));
                locationList = new ArrayList<>();
                for (int i = 0; i < pdsSequence.size(); i++) {
                    ASN1Sequence locationSeq = ASN1Sequence.getInstance(pdsSequence.getObjectAt(i));
                    String url = DERIA5String.getInstance(locationSeq.getObjectAt(0)).getString();
                    String lang = DERPrintableString.getInstance(locationSeq.getObjectAt(1)).getString();
                    locationList.add(new PDSLocation(lang, url));
                }
            }

        } catch (Exception e) {
        }
    }

    private void setStatementVal(ASN1EncodableVector qcStatementsSeq, ASN1ObjectIdentifier statementId) {
        setStatementVal(qcStatementsSeq, statementId, null);
    }

    private void setStatementVal(ASN1EncodableVector qcStatementsSeq, ASN1ObjectIdentifier statementId, ASN1Encodable value) {
        ASN1EncodableVector statement = new ASN1EncodableVector();
        statement.add(statementId);
        if (value != null) {
            statement.add(value);
        }
        qcStatementsSeq.add(new DERSequence(statement));
    }

    private void setSemanticsInfo(ASN1EncodableVector qcStatements, ASN1ObjectIdentifier syntaxVersion) {
        if (semanticsInfo == null) {
            setStatementVal(qcStatements, syntaxVersion);
            return;
        }
        ASN1EncodableVector siSeq = new ASN1EncodableVector();
        if (semanticsInfo.getSemanticsIdentifier() != null) {
            siSeq.add(semanticsInfo.getSemanticsIdentifier());
        }
        List<GeneralName> nameRegistrationAuthorityList = semanticsInfo.getNameRegistrationAuthorityList();
        if (!nameRegistrationAuthorityList.isEmpty()) {
            ASN1EncodableVector nraSeq = new ASN1EncodableVector();
            nameRegistrationAuthorityList.forEach((name) -> {
                nraSeq.add(name);
            });
            siSeq.add(new DERSequence(nraSeq));
        }
        setStatementVal(qcStatements, syntaxVersion, new DERSequence(siSeq));
    }

    private void getSemanticsInfoVals(ASN1Encodable siObject) {
        if (siObject instanceof ASN1ObjectIdentifier) {
            semanticsInfo.setSemanticsIdentifier((ASN1ObjectIdentifier.getInstance(siObject)));
        }
        if (siObject instanceof ASN1Sequence) {
            ASN1Sequence nraSeq = ASN1Sequence.getInstance(siObject);
            List<GeneralName> nameList = new ArrayList<>();
            for (int i = 0; i < nraSeq.size(); i++) {
                try {
                    nameList.add(GeneralName.getInstance(nraSeq.getObjectAt(i)));
                } catch (Exception e) {
                }
            }
            semanticsInfo.setNameRegistrationAuthorityList(nameList);
        }
    }
}
