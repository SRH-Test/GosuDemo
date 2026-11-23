# Gosu Vulnerable Insurance Portal Demo (`gosu-vuln-demo`)

> **Warning:** This repository contains **intentionally vulnerable** [Gosu](https://gosu-lang.github.io/) (`.gs`, `.gsx`, `.gst`, `.gsp`) source code, vulnerable JVM dependencies, and dummy secrets strictly for **SAST, AI SAST, SCA, and Secret Scanner** validation. Do not deploy or use in any real environment.

## Overview

Gosu is a statically typed JVM programming language widely used in Guidewire InsuranceSuite (ClaimCenter, PolicyCenter, BillingCenter). This project simulates a Guidewire-style claims & ACORD integration service across all four Gosu file types alongside Maven (`pom.xml`) and Gradle (`build.gradle`) manifests.

## Intentional Findings Matrix

### 1. Gosu Static Analysis (SAST) Findings

| File | Type | Intentional Vulnerabilities |
| :--- | :--- | :--- |
| `src/main/gosu/gw/demo/claims/ClaimSearchServlet.gs` | Gosu Class (`.gs`) | **SQL Injection** (`CWE-89`), **Reflected XSS** (`CWE-79`), **Open Redirect** (`CWE-601`), **LDAP Injection** (`CWE-90`) |
| `src/main/gosu/gw/demo/integration/AcordIntegrationService.gs` | Gosu Class (`.gs`) | **XML External Entity / XXE** (`CWE-611`), **OS Command Injection** (`CWE-78`), **Server-Side Request Forgery / SSRF** (`CWE-918`), **Path Traversal** (`CWE-22`), **Insecure Deserialization** (`CWE-502`) |
| `src/main/gosu/gw/demo/security/CryptoAndAuthUtil.gs` | Gosu Class (`.gs`) | **Hardcoded Credentials** (`CWE-798`), **Weak Hashing MD5/SHA-1** (`CWE-328`), **Broken Cipher DES-ECB** (`CWE-327`), **Insecure Randomness** (`CWE-330`), **Disabled TLS Certificate Validation** (`CWE-295`) |
| `src/main/gosu/gw/demo/enhancements/StringQueryEnhancement.gsx` | Gosu Enhancement (`.gsx`) | **SQL Injection** (`CWE-89`), **OS Command Injection** (`CWE-78`), **Script Engine Code Injection** (`CWE-94`), **Path Traversal** (`CWE-22`) |
| `src/main/gosu/gw/demo/templates/ClaimSummaryTemplate.gst` | Gosu Template (`.gst`) | **Cross-Site Scripting / XSS** (`CWE-79`), **DOM Open Redirect** (`CWE-601`) |
| `src/main/gosu/gw/demo/templates/PolicyExportXmlTemplate.gst` | Gosu Template (`.gst`) | **XML Injection** (`CWE-91`), **Sensitive Credential Exposure in XML** (`CWE-200`) |
| `src/main/gosu/gw/demo/batch/NightlyClaimExport.gsp` | Gosu Program (`.gsp`) | **SQL Injection** (`CWE-89`), **OS Command Injection** (`CWE-78`), **Cleartext Logging of Sensitive Data** (`CWE-532`) |

### 2. Vulnerable Dependencies (SCA)

Declared in both `pom.xml` and `build.gradle`:
- `org.apache.logging.log4j:log4j-core:2.14.1` (**CVE-2021-44228** — Log4Shell)
- `org.apache.commons:commons-text:1.9` (**CVE-2022-42889** — Text4Shell)
- `com.fasterxml.jackson.core:jackson-databind:2.9.8` (**CVE-2019-12384**, etc.)
- `org.yaml:snakeyaml:1.30` (**CVE-2022-1471**)
- `commons-collections:commons-collections:3.2.1` (**CVE-2015-6420**)
- `org.springframework:spring-webmvc:5.3.17` (**CVE-2022-22965** — Spring4Shell)

### 3. Dummy Secrets (Secret Scanning)

Embedded in `src/main/gosu/gw/demo/security/CryptoAndAuthUtil.gs`, `src/main/resources/claimcenter-config.properties`, and `src/main/resources/certs/acord-signing.key`:
- Synthetic AWS Access Key ID & Secret Access Key
- Throwaway 2048-bit RSA Private Key (`acord-signing.key`)
- PostgreSQL, MongoDB, and RabbitMQ AMQP connection URIs with embedded passwords
- Hardcoded JWT HS256 signing secret & static Bearer JWT token
