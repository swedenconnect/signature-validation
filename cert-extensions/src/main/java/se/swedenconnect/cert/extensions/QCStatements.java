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

package se.swedenconnect.cert.extensions;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1IA5String;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1PrintableString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.qualified.QCStatement;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import se.swedenconnect.cert.extensions.data.MonetaryValue;
import se.swedenconnect.cert.extensions.data.PDSLocation;
import se.swedenconnect.cert.extensions.data.SemanticsInformation;
import se.swedenconnect.cert.extensions.utils.ExtensionUtils;

/**
 * QCStatements X.509 extension implementation for extending Bouncycastle.
 *
 * @author Martin Lindström (martin@idsec.se)
 * @author Stefan Santesson (stefan@idsec.se)
 */
@NoArgsConstructor
@Slf4j
public class QCStatements extends ASN1Object {

  public static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.3");
  public static final ASN1ObjectIdentifier PKIX_SYNTAX_V1 = QCStatement.id_qcs_pkixQCSyntax_v1;
  public static final ASN1ObjectIdentifier PKIX_SYNTAX_V2 = QCStatement.id_qcs_pkixQCSyntax_v2;
  public static final ASN1ObjectIdentifier QC_COMPLIANCE = QCStatement.id_etsi_qcs_QcCompliance;
  public static final ASN1ObjectIdentifier QC_SSCD = QCStatement.id_etsi_qcs_QcSSCD;
  public static final ASN1ObjectIdentifier LIMITVAL = QCStatement.id_etsi_qcs_LimiteValue;
  public static final ASN1ObjectIdentifier RETENTION_PERIOD = QCStatement.id_etsi_qcs_RetentionPeriod;
  public static final ASN1ObjectIdentifier PKI_DISCLOSURE = new ASN1ObjectIdentifier("0.4.0.1862.1.5");
  public static final ASN1ObjectIdentifier QC_TYPE = new ASN1ObjectIdentifier("0.4.0.1862.1.6");
  public static final ASN1ObjectIdentifier QC_TYPE_ELECTRONIC_SIGNATURE = new ASN1ObjectIdentifier("0.4.0.1862.1.6.1");
  public static final ASN1ObjectIdentifier QC_TYPE_ELECTRONIC_SEAL = new ASN1ObjectIdentifier("0.4.0.1862.1.6.2");
  public static final ASN1ObjectIdentifier QC_TYPE_WEBSITE_AUTH = new ASN1ObjectIdentifier("0.4.0.1862.1.6.3");
  public static final ASN1ObjectIdentifier QC_CC_LEGISLATION = new ASN1ObjectIdentifier("0.4.0.1862.1.7");
  public static final ASN1ObjectIdentifier ETSI_SEMANTICS_NATURAL = new ASN1ObjectIdentifier("0.4.0.194121.1.1");
  public static final ASN1ObjectIdentifier ETSI_SEMANTICS_LEGAL = new ASN1ObjectIdentifier("0.4.0.194121.1.2");
  public static final ASN1ObjectIdentifier ETSI_SEMANTICS_EIDAS_NATURAL = new ASN1ObjectIdentifier("0.4.0.194121.1.3");
  public static final ASN1ObjectIdentifier ETSI_SEMANTICS_EIDAS_LEGAL = new ASN1ObjectIdentifier("0.4.0.194121.1.4");

  @Getter
  @Setter
  private boolean pkixSyntaxV1;

  @Getter
  @Setter
  private boolean pkixSyntaxV2;

  @Getter
  @Setter
  private boolean qcCompliance;

  @Getter
  @Setter
  private boolean pdsStatement;

  @Getter
  @Setter
  private boolean qcSscd;

  @Getter
  @Setter
  private boolean qcType;

  @Getter
  @Setter
  private boolean retentionPeriod;

  @Getter
  @Setter
  private boolean limitValue;

  @Getter
  @Setter
  private boolean qcCClegislation;

  @Getter
  @Setter
  private MonetaryValue monetaryValue;

  @Getter
  @Setter
  private List<ASN1ObjectIdentifier> qcTypeIdList = new ArrayList<>();

  @Getter
  @Setter
  private BigInteger retentionPeriodVal;

  @Getter
  @Setter
  private List<PDSLocation> locationList = new ArrayList<>();

  @Getter
  @Setter
  private SemanticsInformation semanticsInfo;

  @Getter
  @Setter
  private List<String> legislationCountryList;

  public static QCStatements getInstance(final ASN1TaggedObject obj, final boolean explicit) {
    return getInstance(ASN1Sequence.getInstance(obj, explicit));
  }

  /**
   * Creates an instance of the QCStatements extension object
   *
   * @param obj
   *          a representation of the extension
   * @return QCStatements extension or null if no extension could be created from the provided object
   */
  public static QCStatements getInstance(final Object obj) {
    if (obj instanceof QCStatements) {
      return (QCStatements) obj;
    }
    if (obj != null) {
      return new QCStatements(ASN1Sequence.getInstance(obj));
    }
    log.error("A null object was provided");
    return null;
  }

  /**
   * Creates an instance of the QCStatements extension object
   *
   * @param extensions
   *          Extension
   * @return QCStatemnts extension
   */
  public static QCStatements fromExtensions(final Extensions extensions) {
    return QCStatements.getInstance(extensions.getExtensionParsedValue(OID));
  }

  /**
   * Internal constructor
   *
   * Parse the content of ASN1 sequence to populate set values
   *
   * @param seq
   */
  private QCStatements(final ASN1Sequence seq) {

    try {
      for (int i = 0; i < seq.size(); i++) {
        final ASN1Sequence statementSeq = ASN1Sequence.getInstance(seq.getObjectAt(i));
        this.setStatementVals(statementSeq);
      }
    }
    catch (final Exception e) {
      throw new IllegalArgumentException("Bad extension content");
    }
  }

  /**
   * Produce an object suitable for an ASN1OutputStream.
   *
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
   * @return ASN.1 object of the extension
   */
  @Override
  public ASN1Primitive toASN1Primitive() {
    final ASN1EncodableVector qcStatements = new ASN1EncodableVector();

    if (this.pkixSyntaxV1) {
      this.setSemanticsInfo(qcStatements, PKIX_SYNTAX_V1);
    }
    if (this.pkixSyntaxV2) {
      this.setSemanticsInfo(qcStatements, PKIX_SYNTAX_V2);
    }
    if (this.qcCompliance) {
      this.setStatementVal(qcStatements, QC_COMPLIANCE);
    }
    if (this.qcSscd) {
      this.setStatementVal(qcStatements, QC_SSCD);
    }
    if (this.qcType) {
      final ASN1EncodableVector typeSeq = new ASN1EncodableVector();
      for (final ASN1ObjectIdentifier type : this.qcTypeIdList) {
        typeSeq.add(type);
      }
      this.setStatementVal(qcStatements, QC_TYPE, new DERSequence(typeSeq));
    }
    if (this.limitValue) {
      final ASN1EncodableVector limitSeq = new ASN1EncodableVector();
      limitSeq.add(new DERPrintableString(this.monetaryValue.getCurrency()));
      limitSeq.add(new ASN1Integer(this.monetaryValue.getAmount()));
      limitSeq.add(new ASN1Integer(this.monetaryValue.getExponent()));
      this.setStatementVal(qcStatements, LIMITVAL, new DERSequence(limitSeq));
    }
    if (this.retentionPeriod) {
      this.setStatementVal(qcStatements, RETENTION_PERIOD, new ASN1Integer(this.retentionPeriodVal));
    }
    if (this.pdsStatement) {
      final ASN1EncodableVector pdsSeq = new ASN1EncodableVector();
      for (final PDSLocation pdsLoc : this.locationList) {
        final ASN1EncodableVector pdsLocSeq = new ASN1EncodableVector();
        pdsLocSeq.add(new DERIA5String(pdsLoc.getUrl()));
        pdsLocSeq.add(new DERPrintableString(pdsLoc.getLang()));
        pdsSeq.add(new DERSequence(pdsLocSeq));
      }
      this.setStatementVal(qcStatements, PKI_DISCLOSURE, new DERSequence(pdsSeq));
    }
    if (this.qcCClegislation) {
      final ASN1EncodableVector countrySequence = new ASN1EncodableVector();
      for (final String country : this.legislationCountryList) {
        countrySequence.add(new DERPrintableString(country));
      }
      this.setStatementVal(qcStatements, QC_CC_LEGISLATION, new DERSequence(countrySequence));
    }

    return new DERSequence(qcStatements);
  }

  /** {@inheritDoc} */
  @Override
  public String toString() {
    final StringBuilder b = new StringBuilder();
    if (this.pkixSyntaxV1) {
      b.append("  QC Syntax V1").append(System.lineSeparator());
    }
    if (this.pkixSyntaxV2) {
      b.append("  QC Syntax V2").append(System.lineSeparator());
    }
    if (this.pkixSyntaxV1 || this.pkixSyntaxV2) {
      if (this.semanticsInfo != null) {
        if (this.semanticsInfo.getSemanticsIdentifier() != null) {
          b.append("    - SemanticsID: ")
            .append(this.semanticsInfo.getSemanticsIdentifier().getId()).append(System.lineSeparator());
        }
        if (!this.semanticsInfo.getNameRegistrationAuthorityList().isEmpty()) {
          this.semanticsInfo.getNameRegistrationAuthorityList().forEach((name) -> {
            b.append("    - NameRegistrationAuthority: ")
              .append(ExtensionUtils.getGeneralNameStr(name)).append(System.lineSeparator());
          });
        }
      }
    }

    if (this.qcCompliance) {
      b.append("  QC Compliance").append(System.lineSeparator());
    }
    if (this.qcSscd) {
      b.append("  QC SSCD").append(System.lineSeparator());
    }
    if (this.qcType) {
      b.append("  QC Types").append(System.lineSeparator());
      for (final ASN1ObjectIdentifier type : this.qcTypeIdList) {
        if (type.getId().equalsIgnoreCase(QC_TYPE_ELECTRONIC_SIGNATURE.getId())) {
          b.append("    - Electronic Signature").append(System.lineSeparator());
        }
        if (type.getId().equalsIgnoreCase(QC_TYPE_ELECTRONIC_SEAL.getId())) {
          b.append("    - Electronic Seal").append(System.lineSeparator());
        }
        if (type.getId().equalsIgnoreCase(QC_TYPE_WEBSITE_AUTH.getId())) {
          b.append("    - Website Authentication").append(System.lineSeparator());
        }
      }
    }
    if (this.limitValue) {
      b.append("  Reliance Limit\n");
      b.append("    - Currency: ").append(this.monetaryValue.getCurrency()).append(System.lineSeparator());
      b.append("    - Amount: ").append(this.monetaryValue.getAmount()).append(System.lineSeparator());
      b.append("    - Exponent: ").append(this.monetaryValue.getExponent()).append(System.lineSeparator());
    }
    if (this.retentionPeriod) {
      b.append("  Retention Period").append(System.lineSeparator());
      b.append("    - Years after cert expiry: ").append(this.retentionPeriodVal).append(System.lineSeparator());
    }
    if (this.pdsStatement) {
      b.append("  PKI Disclosure Statements").append(System.lineSeparator());
      for (final PDSLocation pdsLoc : this.locationList) {
        b.append("    Location").append(System.lineSeparator());
        b.append("     - URL: ").append(pdsLoc.getUrl()).append(System.lineSeparator());
        b.append("     - Lang: ").append(pdsLoc.getLang()).append(System.lineSeparator());
      }
    }
    if (this.qcCClegislation) {
      b.append("  QC Legislation Countries\n");
      for (final String country : this.legislationCountryList) {
        b.append("    ").append(country).append(System.lineSeparator());
      }
    }

    return b.toString();
  }

  /**
   * Clear all values
   */
  @SuppressWarnings("unused")
  private void clearAll() {
    this.setPkixSyntaxV1(false);
    this.setPkixSyntaxV2(false);
    this.setQcCompliance(false);
    this.setQcSscd(false);
    this.setQcType(false);
    this.setLimitValue(false);
    this.setRetentionPeriod(false);
    this.setPdsStatement(false);
  }

  private void setStatementVals(final ASN1Sequence statementSeq) {
    try {
      final String statementIdStr = ASN1ObjectIdentifier.getInstance(statementSeq.getObjectAt(0)).getId();
      if (statementIdStr.equals(PKIX_SYNTAX_V1.getId())) {
        this.setPkixSyntaxV1(true);
      }
      if (statementIdStr.equals(PKIX_SYNTAX_V2.getId())) {
        this.setPkixSyntaxV2(true);
      }
      if (statementIdStr.equals(PKIX_SYNTAX_V2.getId()) || statementIdStr.equals(PKIX_SYNTAX_V1.getId())) {
        if (statementSeq.size() > 1) {
          final ASN1Sequence siSeq = ASN1Sequence.getInstance(statementSeq.getObjectAt(1));
          this.semanticsInfo = new SemanticsInformation();
          for (int i = 0; i < siSeq.size(); i++) {
            this.getSemanticsInfoVals(siSeq.getObjectAt(i));
          }
        }
      }
      if (statementIdStr.equals(QC_COMPLIANCE.getId())) {
        this.setQcCompliance(true);
      }
      if (statementIdStr.equals(QC_SSCD.getId())) {
        this.setQcSscd(true);
      }
      if (statementIdStr.equals(QC_TYPE.getId())) {
        this.setQcType(true);
        final ASN1Sequence qcTypeSequence = ASN1Sequence.getInstance(statementSeq.getObjectAt(1));
        this.qcTypeIdList = new ArrayList<>();
        for (int i = 0; i < qcTypeSequence.size(); i++) {
          final ASN1ObjectIdentifier type = ASN1ObjectIdentifier.getInstance(qcTypeSequence.getObjectAt(i));
          this.qcTypeIdList.add(type);
        }
      }
      if (statementIdStr.equals(LIMITVAL.getId())) {
        this.setLimitValue(true);
        final ASN1Sequence lvSequence = ASN1Sequence.getInstance(statementSeq.getObjectAt(1));
        final ASN1Encodable currencyEnc = lvSequence.getObjectAt(0);

        final String currency = currencyEnc instanceof ASN1PrintableString
            ? ASN1PrintableString.getInstance(currencyEnc).getString()
            : ASN1Integer.getInstance(currencyEnc).getValue().toString();
        final BigInteger amount = ASN1Integer.getInstance(lvSequence.getObjectAt(1)).getValue();
        final BigInteger exp = ASN1Integer.getInstance(lvSequence.getObjectAt(2)).getValue();
        this.monetaryValue = new MonetaryValue(currency, amount, exp);
      }
      if (statementIdStr.equals(RETENTION_PERIOD.getId())) {
        this.setRetentionPeriod(true);
        this.retentionPeriodVal = ASN1Integer.getInstance(statementSeq.getObjectAt(1)).getValue();
      }
      if (statementIdStr.equals(PKI_DISCLOSURE.getId())) {
        this.setPdsStatement(true);
        final ASN1Sequence pdsSequence = ASN1Sequence.getInstance(statementSeq.getObjectAt(1));
        this.locationList = new ArrayList<>();
        for (int i = 0; i < pdsSequence.size(); i++) {
          final ASN1Sequence locationSeq = ASN1Sequence.getInstance(pdsSequence.getObjectAt(i));
          final String url = ASN1IA5String.getInstance(locationSeq.getObjectAt(0)).getString();
          final String lang = ASN1IA5String.getInstance(locationSeq.getObjectAt(1)).getString();
          this.locationList.add(new PDSLocation(lang, url));
        }
      }
      if (statementIdStr.equals(QC_CC_LEGISLATION.getId())) {
        this.setQcCClegislation(true);
        final ASN1Sequence qcLegislationSeq = ASN1Sequence.getInstance(statementSeq.getObjectAt(1));
        this.legislationCountryList = new ArrayList<>();
        for (int i = 0; i < qcLegislationSeq.size(); i++) {
          final String country = ASN1PrintableString.getInstance(qcLegislationSeq.getObjectAt(i)).getString();
          this.legislationCountryList.add(country);
        }
      }

    }
    catch (final Exception e) {
    }
  }

  private void setStatementVal(final ASN1EncodableVector qcStatementsSeq, final ASN1ObjectIdentifier statementId) {
    this.setStatementVal(qcStatementsSeq, statementId, null);
  }

  private void setStatementVal(final ASN1EncodableVector qcStatementsSeq, final ASN1ObjectIdentifier statementId,
      final ASN1Encodable value) {
    final ASN1EncodableVector statement = new ASN1EncodableVector();
    statement.add(statementId);
    if (value != null) {
      statement.add(value);
    }
    qcStatementsSeq.add(new DERSequence(statement));
  }

  private void setSemanticsInfo(final ASN1EncodableVector qcStatements, final ASN1ObjectIdentifier syntaxVersion) {
    if (this.semanticsInfo == null) {
      this.setStatementVal(qcStatements, syntaxVersion);
      return;
    }
    final ASN1EncodableVector siSeq = new ASN1EncodableVector();
    if (this.semanticsInfo.getSemanticsIdentifier() != null) {
      siSeq.add(this.semanticsInfo.getSemanticsIdentifier());
    }
    final List<GeneralName> nameRegistrationAuthorityList = this.semanticsInfo.getNameRegistrationAuthorityList();
    if (!nameRegistrationAuthorityList.isEmpty()) {
      final ASN1EncodableVector nraSeq = new ASN1EncodableVector();
      nameRegistrationAuthorityList.forEach((name) -> {
        nraSeq.add(name);
      });
      siSeq.add(new DERSequence(nraSeq));
    }
    this.setStatementVal(qcStatements, syntaxVersion, new DERSequence(siSeq));
  }

  private void getSemanticsInfoVals(final ASN1Encodable siObject) {
    if (siObject instanceof ASN1ObjectIdentifier) {
      this.semanticsInfo.setSemanticsIdentifier(ASN1ObjectIdentifier.getInstance(siObject));
    }
    if (siObject instanceof ASN1Sequence) {
      final ASN1Sequence nraSeq = ASN1Sequence.getInstance(siObject);
      final List<GeneralName> nameList = new ArrayList<>();
      for (int i = 0; i < nraSeq.size(); i++) {
        try {
          nameList.add(GeneralName.getInstance(nraSeq.getObjectAt(i)));
        }
        catch (final Exception e) {
        }
      }
      this.semanticsInfo.setNameRegistrationAuthorityList(nameList);
    }
  }
}
