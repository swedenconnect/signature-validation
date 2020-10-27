![Logo](https://github.com/idsec-solutions/idsec-solutions.github.io/blob/master/img/idsec.png)

# SVT enhanced Signature Validation Base

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

Core components for validating electronis signatures and to extend signed documents with Signature Validation Tokens. This includes the following independent modules:

Module | Description | Depends on
---|--- | ---
cert-extensions |  Extensions to Bouncycastle to create and process some X.509 certificate extensions | ---
cert-validatioin  | Functions to support certificate validation with certificate path building and certificate revocation checking  | cert-extensions
sigval-commons  | Common functions to support signature validation and SVT creation independent of signed document format |  cert-validation
sigval-pdf  | Signature validation and SVT creation for PDF documents  | sigval-commons
sigval-xml  | Signature validation and SVT creation for XML documents  | sigval-commons

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

##### API documentation

Java API documentation for [**se.idsec.sigval.base:cert-validation**](https://idsec-solutions.github.io/sig-validation-base/javadoc/cert-validation).

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

Copyright &copy; 2019-2020, [IDsec Solutions AB](http://www.idsec.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
