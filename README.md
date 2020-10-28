![Logo](https://github.com/idsec-solutions/idsec-solutions.github.io/blob/master/img/idsec.png)

# SVT enhanced Signature Validation

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Core components for validating electronis signatures and to extend signed documents with Signature Validation Tokens (SVT). This includes the following independent modules:

Module | Description | Depends on
---|--- | ---
cert-extensions |  Extensions to Bouncycastle to create and process some X.509 certificate extensions | ---
cert-validatioin  | Functions to support certificate validation with certificate path building and certificate revocation checking  | cert-extensions
sigval-commons  | Common functions to support signature validation and SVT creation independent of signed document format |  cert-validation
sigval-pdf  | Signature validation and SVT creation for PDF documents  | sigval-commons
sigval-xml  | Signature validation and SVT creation for XML documents  | sigval-commons

The signature validation modules builds upon the Signservice Commons library available from [signservice-commons on GitHub](https://github.com/idsec-solutions/signservice-commons).

---

# cert-extensions module

### Maven

This project is currently not deployed at maven central. The source code must be built locally and then imported to your project as:

```
<dependency>
    <groupId>se.idsec.sigval.base</groupId>
    <artifactId>cert-extensions</artifactId>
    <version>${cert-extensions.version}</version>
</dependency>

```

##### API documentation

Java API documentation for [**se.idsec.sigval.base:cert-extensions**](https://idsec-solutions.github.io/sig-validation-base/javadoc/cert-extensions).

# cert-validation module

### Maven

This project is currently not deployed at maven central. The source code must be built locally and then imported to your project as:

```
<dependency>
    <groupId>se.idsec.sigval.base</groupId>
    <artifactId>cert-validation</artifactId>
    <version>${cert-validation.version}</version>
</dependency>

```

#### API documentation

Java API documentation for [**se.idsec.sigval.base:cert-validation**](https://idsec-solutions.github.io/sig-validation-base/javadoc/cert-validation).

### Usage
The main feature provided by this module is the certificate validity checker implementation and its supporting implementation of certificate path building and certificate status checking

#### CRL cache
The CRLCache is an intefrace which provides the basic functions to locate a CRL based on URL or a CRLDistributionPoint extension from an X.509 certificate as well as a function to update cached CRL data.

The default implementation CRLCacheImpl implements a cache where downloaded CRL:s are cached and stored in a specified location.

The following code demonstrate creation of a CRL cache.

```
CRLCache crlCache(File cacheFolder, long recacheGracePeiod) {
  return new CRLCacheImpl(cacheFolderFile, recacheGracePeiod);
}

```

The recacheGracePeiod parameter indicates the time in ms before a recently cached CRL is allowed to be recached. If the time since last recache is less than this time, no recache is performed even if the recache function is called.

#### Validity checker
The StatusCheckingCertificateValidatorImpl class implements the CertificateValidator intefrace to provide certificate validatioin based on CRL and OCSP certificate status checking as well as PKIX path validation.

The following code demonstrate creation of a certificate validator:

```
CertificateValidator certificateValidator(
  CRLCache crlCache,
  CertStore certStore,
  X509Certificate[] defaultTrustAnchors) {
  return new StatusCheckingCertificateValidatorImpl(crlCache, certStore, defaultTrustAnchors);
}
```

The crlCache is a CRLCache according the the example above. The certStore is a java.security.cert.CertStore holding any intermediary certificates available to the certificate path builder and the defaultTrustAnchors provides default trust anchor certificates for the path validator. These certificates are allways available/trusted by the certificate validator in addition to any certificates specified at functioin calls to the validator.

# sigval-commons module

### Maven

This project is currently not deployed at maven central. The source code must be built locally and then imported to your project as:

```
<dependency>
    <groupId>se.idsec.sigval.base</groupId>
    <artifactId>sigval-commons</artifactId>
    <version>${sigval-commons.version}</version>
</dependency>

```

##### API documentation

Java API documentation for [**se.idsec.sigval.base:sigval-commons**](https://idsec-solutions.github.io/sig-validation-base/javadoc/sigval-commons).



# sigval-pdf module

### Maven

This project is currently not deployed at maven central. The source code must be built locally and then imported to your project as:

```
<dependency>
    <groupId>se.idsec.sigval.base</groupId>
    <artifactId>sigval-pdf</artifactId>
    <version>${sigval-pdf.version}</version>
</dependency>

```

##### API documentation

Java API documentation for [**se.idsec.sigval.base:sigval-pdf**](https://idsec-solutions.github.io/sig-validation-base/javadoc/sigval-pdf).

### Usage

The PDF module provides the functionality to validate PDF signatures and to issue SVT tokens to signed PDF documents.

#### PDF signature validation

The following code example creates a PDF signature validator:

```
ExtendedPDFSignatureValidator pdfSignatureValidator(
  CertificateValidator certificateValidator) {

  TimeStampPolicyVerifier timeStampPolicyVerifier =
    new BasicTimstampPolicyVerifier(certificateValidator)
  PDFSignaturePolicyValidator signaturePolicyValidator = new PkixPdfSignaturePolicyValidator();
  PDFSingleSignatureValidator pdfSignatureVerifier = new PDFSingleSignatureValidatorImpl(
    certificateValidator, signaturePolicyValidator,
    timeStampPolicyVerifier);

  // Setup SVT validator
  PDFSVTValidator pdfsvtValidator = new PDFSVTValidator(
    certificateValidator, timeStampPolicyVerifier);

  // Get the pdf validator
  return new SVTenabledPDFDocumentSigVerifier(
    pdfSignatureVerifier, pdfsvtValidator, DefaultPDFSignatureContextFactory());
}
```

The following replaceable components are used to construct the signature verifier:

Component | Description
--- | ---
`TimeStampPolicyVerifier`  |  A verifier capable of validating timestamps against a defined validation policy
`PDFSignaturePolicyValidator`  |  This is a policy validator which examines the signature validation results and applies a validation policy to determine the signature validity.
`PDFSingleSignatureValidator`  |  This is the main PDF signature validator performing signature validation of individual PDF signatures
`PDFSVTValidator`  |  This is a PDF SVT validator capable of validating a PDF signature based on an existing SVT token. If no `PDFSVTValidator` is provided, no SVT validation is performed.

#### PDF SVT issuance

The PDF SVT token is created by the SVT claims issuer. This component issues the SVT token which reflects the validation of the PDF signature. The following code example creates the PDF claims issuer:

```
PDFSVTSigValClaimsIssuer pdfsvtSigValClaimsIssuer(
    JWSAlgorithm svtJWSAlgorithm, PrivateKey privateKey, List<X509Certificate> certificates,
    ExtendedPDFSignatureValidator pdfSignatureValidator){
  return new PDFSVTSigValClaimsIssuer(
    svtJWSAlgorithm, privateKey, certificates, pdfSignatureValidator);
}
```

Finally the signed PDF is extended with a document timestamp which includes the PDF SVT token. This requires a document timestamp signer that can be created according to the following example:

```
DefaultPDFDocTimestampSignatureInterface timeStampSigner(
    PrivateKey privateKey, List<X509Certificate> certificates, String sigAlgoUri){
  return new DefaultPDFDocTimestampSignatureInterface(
    privateKey,
    certificates,
    sigAlgoUri);
}
```

The private key, certificates and algorithm declarations provided to the creation of both SVT issuer and timestamp signer is the private key used to sign and the certificate used to validate the respective token/timestamp as well as the algorithm used to sign them.

NOTE that it is recommended to use a complete path to support timestamp token siging, while an SVT normally is issued directly from a trust anchor cert in order to avoid path validation of SVT tokens.

The following code example then issues an SVT token and extends the PDF document with this token based on the SVT issuer and the timestamp signer:

```
byte[] extendPDFwithSVT(
  byte[] signedDoc,
  SVTModel svtModel,
  PDFSVTSigValClaimsIssuer pdfsvtSigValClaimsIssuer,
  DefaultPDFDocTimestampSignatureInterface timeStampSigner) {

  // Create SVT token
  SignedJWT signedSvtJWT = pdfsvtSigValClaimsIssuer.getSignedSvtJWT(signedDoc, svtModel);

  // Extend PDF document
  return PDFDocTimstampProcessor.createSVTSealedPDF(
    signedDoc,
    signedSvtJWT.serialize(),
    timeStampSigner).getDocument();
}
```



# sigval-xml module

### Maven

This project is currently not deployed at maven central. The source code must be built locally and then imported to your project as:

```
<dependency>
    <groupId>se.idsec.sigval.base</groupId>
    <artifactId>sigval-xml</artifactId>
    <version>${sigval-xml.version}</version>
</dependency>
```

##### API documentation

Java API documentation for [**se.idsec.sigval.base:sigval-xml**](https://idsec-solutions.github.io/sig-validation-base/javadoc/sigval-xml).

---

### Usage

The XML module provides the functionality to validate XML signatures and to issue SVT tokens to signed XML documents.

#### XML signature validatioin

The following code example creates an XML signature validator:

```
ExtendedXMLSignedDocumentValidator xmlSignedDocumentValidator() {
  return new XMLSignedDocumentValidator(xmlSignatureElementValidator);
}

XMLSignatureElementValidator xmlSignatureElementValidator(
  CertificateValidator certificateValidator){

  TimeStampPolicyVerifier timeStampPolicyVerifier =
     new BasicTimstampPolicyVerifier(certificateValidator)
  XMLSignaturePolicyValidator xmlSignaturePolicyValidator =
     new PkixXmlSignaturePolicyValidator();

  // Setup SVT validator
  XMLSVTValidator xmlSvtValidator = new XMLSVTValidator(certificateValidator, null);

  return new XMLSignatureElementValidatorImpl(
    certificateValidator,
    xmlSignaturePolicyValidator,
    timeStampPolicyVerifier,
    xmlSvtValidator
  );
}
```


The following replaceable components are used to construct the signature verifier:

Component | Description
--- | ---
`TimeStampPolicyVerifier` | A verifier capable of validating timestamps against a defined validation policy
`XMLSignaturePolicyValidator` | This is a policy validator which examines the signature validation results and applies a validation policy to determine the signature validity.
`XMLSignatureElementValidator` | This is the main XML signature validator performing signature validation of individual XML signatures
`XMLSVTValidator` | This is a XML SVT validator capable of validating a PDF signature based on an existing SVT token. If no `XMLSVTValidator` is provided, no SVT validation is performed.

#### XML SVT issuance

The XML SVT token is created by the SVT claims issuer. This component issues the SVT token which reflects the validation of the PDF signature. The following code example creates the PDF claims issuer:

```
XMLSVTSigValClaimsIssuer claimsIssuer(
  JWSAlgorithm svtJWSAlgorithm, PrivateKey privateKey, List<X509Certificate> certificates,
  XMLSignatureElementValidator xmlSignatureElementValidator
  ) {
  return new XMLSVTSigValClaimsIssuer(
    svtJWSAlgorithm,
    privateKey,
    certificates,
    xmlSignatureElementValidator);
}
```

Finally the signed XML document signatures are extended with SVT tokens. This requires an XML document SVT issuer that can be created according to the following example:

```
XMLDocumentSVTIssuer xmlDocumentSVTIssuer(XMLSVTSigValClaimsIssuer claimsIssuer) {
  return new XMLDocumentSVTIssuer(claimsIssuer);
}
```

The private key, certificates and algorithm declarations provided to the creation of the SVT issueris the private key used to sign and the certificate used to validate the SVT tokenand the algorithm used to sign it.

NOTE that it is recommended to issue an SVT directly from a trust anchor cert in order to avoid path validation of SVT tokens.

The following code example then issues an SVT token and extends the XML document with SVT tokens based on the SVT issuer:

```
byte[] extendXMLwithSVT(
  Document signedXmlDocument,
  SVTModel svtModel,
  XMLDocumentSVTIssuer xmlDocumentSVTIssuer) {

  // Extend XML document
  return xmlDocumentSVTIssuer.issueSvt(
    signedXmlDocument,
    svtModel,
    XMLDocumentSVTMethod.EXTEND);
}
```

The XMLDocumentSVTMethod parameter instructs the SVT issuer what to do if a current SVT is already present in the XML signature. a value of `XMLDocumentSVTMethod.REPLACE` will replace the existing SVT while the value `XMLDocumentSVTMethod.EXTEND` as shown in the example will simply add the new SVT after the old one.

---

Copyright &copy; 2019-2020, [IDsec Solutions AB](http://www.idsec.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
