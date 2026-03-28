## Intelligent Automated Security Analysis System
---

## 0. Overall system flow (one diagram)


```mermaid
flowchart LR
    A[User enters URL] --> B{UI choice}
    B --> C[Flask web UI]
    B --> D[Streamlit UI]
    C --> E[validate_url]
    D --> E
    E --> F{URL valid?}
    F -->|no| G[Show error]
    F -->|yes| H[VulnerabilityScanner]
    H --> I[Thread pool: run enabled modules]
    I --> J[Merge results and summary]
    J --> K[Risk level from counts]
    K --> L[Report and dashboard]
```

### Deep explanation (overall)

The only mandatory path is: **capture URL → validate → orchestrate scans → merge → risk label → present**. Flask may additionally validate an API key when the user picks an API-style scan. Streamlit may call helpers such as web scraping or AI analysis in parallel with or after scans; those paths are optional overlays on the same core.

---

## 1. Large-scale system architecture (layered)

```mermaid
flowchart TB
    subgraph CLIENT["Client / operator"]
        U["User / security analyst"]
    end

    subgraph PRES["Presentation layer - two UIs"]
        F["Flask web app: app.py and templates\nforms, REST-style hooks, sessions"]
        ST["Streamlit dashboard: wolf.py\ncharts and multi-step workflows"]
    end

    subgraph CROSS["Cross-cutting input control"]
        V["URL and target validation: utils/validator.py\nreject malformed URLs early"]
        AKM["API key lifecycle Flask path: ApiKeyManager and api_keys.json\ngenerate, validate, revoke"]
    end

    subgraph ORCH["Orchestration - single coordinator"]
        VS["VulnerabilityScanner in modules/scanner.py\nbuilds all scanner objects, merges results and summary"]
    end

    subgraph MODS["Scanning layer - modular DAST-style probes"]
        direction TB
        M_WEB["Web attack surface: XSS, SQLi, paths, misconfig, CSRF, IDOR"]
        M_PROTO["Protocol and transport: SSL/TLS, ports, API surface"]
        M_ADV["Advanced: XXE, SSRF, RCE, JWT, bruteforce heuristics"]
    end

    subgraph AUX["Auxiliary analysis optional paths"]
        WS["web_scraper.py: crawl and context"]
        NS["network_scanner.py and subdomain_finder.py\nDNS and network context"]
        AI["wolf_api.py and security_analyzer.py\nLLM or API-assisted narration"]
    end

    subgraph OUT["Outputs"]
        RG["report_generator.py and utils/reporter.py\nHTML and structured report"]
        UI_OUT["Rendered UI: results.html or Streamlit views"]
    end

    U --> F
    U --> ST
    F --> V
    ST --> V
    F --> AKM
    AKM -.->|if API scan mode| VS
    V -->|valid URL, timeout, api_key| VS
    ST --> VS

    VS --> M_WEB
    VS --> M_PROTO
    VS --> M_ADV

    ST -.-> WS
    ST -.-> NS
    ST -.-> AI

    VS --> RG
    RG --> UI_OUT
    F --> UI_OUT
    ST --> UI_OUT
```

### Deep explanation (architecture)

1. **Dual UI:** Flask suits classic multi-page flows; Streamlit suits dashboards. Both should pass the same backend contract: normalized URL, optional module flags, timeout.
2. **Validation first** avoids useless traffic; invalid URLs raise before ThreadPoolExecutor work (`validate_url` in scanner constructor).
3. **Modular scanners** live under `modules/` as separate concerns, similar to rule packs in commercial DAST tools.
4. **AI and scraping** augment output; they do not replace module findings.

---

## 2. End-to-end operational lifecycle (from click to risk label)

```mermaid
flowchart TD
    START([User submits target URL]) --> CHOOSE{Which surface?}

    CHOOSE -->|Flask POST /scan| F1[Read url, scan_type, optional api_key]
    CHOOSE -->|Streamlit action| S1[Read widget state:\nURL, toggles, timeouts]

    F1 --> FAPI{scan_type is api?}
    FAPI -->|yes| VALKEY[Validate key via ApiKeyManager]
    FAPI -->|no| BUILD
    VALKEY -->|invalid| ERR1[Flash error / stop]
    VALKEY -->|valid| BUILD[Build options dict:\nwhich modules run]

    S1 --> BUILD

    BUILD --> VALURL[Call validate_url]
    VALURL -->|fail| ERR2[Show error:\ninvalid URL format]
    VALURL -->|pass| CONS[Construct VulnerabilityScanner:\nurl, timeout, api_key\n13 scanner instances]

    CONS --> RUN[run_all_scans options]
    RUN --> POOL[ThreadPoolExecutor max_workers 8\nsubmit one future per enabled module]

    POOL --> WAIT[as_completed futures\nstream results as threads finish]
    WAIT --> EACH{Per future:\nfuture.result with timeout}

    EACH -->|success| STORE[results module list\nsummary module count]
    EACH -->|exception| SAFE[Log error\nempty list and count 0]

    STORE --> MORE{More futures?}
    SAFE --> MORE
    MORE -->|yes| WAIT
    MORE -->|no| TOT[total_vulnerabilities sum of summary counts]

    TOT --> RISK{Apply threshold rules\nsee scanner.py}
    RISK -->|total equals 0| RL0[MINIMAL]
    RISK -->|1 to 2| RL1[LOW]
    RISK -->|3 to 5| RL2[MEDIUM]
    RISK -->|6 to 10| RL3[HIGH]
    RISK -->|greater than 10| RL4[CRITICAL]

    RL0 --> PACK
    RL1 --> PACK
    RL2 --> PACK
    RL3 --> PACK
    RL4 --> PACK
    PACK[Attach risk_level and total_vulnerabilities\nto results summary]
    PACK --> REP[Flask: generate_report and template\nStreamlit: dataframes and charts]
    REP --> END([User reviews / exports])

    RUN -.->|KeyboardInterrupt| KI[Return partial results]
    KI --> END
```

### Deep explanation (lifecycle)

1. **`options`:** If omitted, all modules run; otherwise only keys set true run.
2. **Pool size 8:** Caps concurrent module work.
3. **Per-module errors:** One failing module does not clear others.
4. **Risk label:** Count-derived heuristic, not CVSS.

### Alternate view: sequence diagram (Flask path)

```mermaid
sequenceDiagram
    autonumber
    participant U as User browser
    participant F as Flask app
    participant V as validate_url
    participant K as ApiKeyManager
    participant C as VulnerabilityScanner
    participant E as ThreadPoolExecutor
    participant X as Module workers
    participant T as Target web app
    participant R as Report template

    U->>F: POST /scan url scan_type optional api_key
    alt scan_type is api
        F->>K: validate_key api_key
        K-->>F: ok or reject
    end
    F->>V: validate_url url
    V-->>F: valid or invalid
    F->>C: new VulnerabilityScanner
    F->>C: run_all_scans options
    C->>E: submit N futures max 8 active
    loop Each enabled scanner
        E->>X: run module scan helper
        X->>T: HTTP TLS socket probes
        T-->>X: responses
        X-->>C: list of findings via future
    end
    C->>C: merge counts and lists
    C->>C: total_vulnerabilities and risk_level
    C-->>F: results dict
    F->>R: generate_report and render
    R-->>U: HTML response
```

---

## 3. Inside run_all_scans: futures, summaries, interrupts

```mermaid
flowchart TB
    subgraph ENTER["Entry run_all_scans options"]
        O{options is None?}
        O -->|yes| DEF[Default: all module keys true\nxss sqli ports paths misconfig\nxxe ssrf rce idor csrf jwt\napi bruteforce ssl]
        O -->|no| USE[Use caller-provided flags]
        DEF --> TP
        USE --> TP
    end

    subgraph POOL["ThreadPoolExecutor max_workers 8"]
        direction LR
        SUB[For each enabled key:\nsubmit run helper on executor]
        MAP[Keep scan_tasks map:\nfuture to module name]
    end

    TP[Begin thread pool] --> SUB
    SUB --> MAP

    subgraph COMP["Completion loop as_completed scan_tasks"]
        FUT[Take next completed future]
        NAME[Resolve module label from map]
        FUT --> NAME
        NAME --> TRY{future.result with timeout}
        TRY -->|OK| OK[Store results name list\nsummary name length]
        TRY -->|except| BAD[Empty results name\nsummary zero\nlog error]
        OK --> NEXT
        BAD --> NEXT{More futures?}
        NEXT -->|yes| FUT
        NEXT -->|no| DONE[Exit loop]
    end

    MAP --> COMP

    subgraph GUARD["Outer exception handling"]
        KB[KeyboardInterrupt:\nmessage and return results]
        OUTER[Other errors:\nmessage and return results]
    end

    DONE --> SUMS
    SUMS[Sum summary values to total_vulnerabilities]

    SUMS --> RISK[Assign risk_level:\nover 10 CRITICAL\nover 5 HIGH\nover 2 MEDIUM\nover 0 LOW\nelse MINIMAL]

    RISK --> RET[Return self.results]

    ENTER -.-> GUARD
```

### Deep explanation (orchestration)

1. **Wrappers:** Each `_run_*` method calls the corresponding scanner.scan(url, api_key).
2. **as_completed:** Results merge as futures finish.
3. **future.result(timeout):** Aligns thread wait with scan timeout.
4. **KeyboardInterrupt:** Returns partial results.

---

## 4. Generic single scanner module flow

```mermaid
flowchart LR
    subgraph INP["Inputs"]
        URL2["Normalized URL"]
        KEY["Optional api_key"]
        TO["timeout from coordinator"]
    end

    subgraph PHASES["Typical module phases"]
        P1["1 Prepare request\nheaders cookies method"]
        P2["2 Emit probes\npaths params payloads"]
        P3["3 Observe responses\nstatus body headers"]
        P4["4 Classify signals\npatterns diffs timing"]
        P5["5 Emit findings\nlist of dicts"]
    end

    subgraph OUTM["Module output"]
        L["Python list\nempty means no issues"]
    end

    URL2 --> P1
    KEY -.-> P1
    TO -.-> P2
    P1 --> P2 --> P3 --> P4 --> P5 --> L
```

---

## 5. Data model: results and summary

```mermaid
flowchart TB
    subgraph DICT["self.results top-level dict"]
        KXSS["xss: list"]
        KSQL["sqli: list"]
        KPORT["ports: list"]
        KPATH["paths: list"]
        KMIS["misconfig: list"]
        KXXE["xxe: list"]
        KSSRF["ssrf: list"]
        KRCE["rce: list"]
        KIDOR["idor: list"]
        KCSRF["csrf: list"]
        KJWT["jwt: list"]
        KAPI["api: list"]
        KBF["bruteforce: list"]
        KSSL["ssl: list"]
        KSUM["summary: nested dict"]
    end

    subgraph SUMK["summary keys after run"]
        S1["per-module counts to int"]
        STOT["total_vulnerabilities int"]
        SRISK["risk_level string"]
    end

    KSUM --> S1
    S1 --> STOT
    STOT --> SRISK

    DICT --> RPTIN["report_generator,\nJinja, Streamlit"]
```

---

## 6. Error and resilience

```mermaid
flowchart TD
    subgraph INITERR["Constructor setup"]
        BADURL["validate_url fails"] --> NOCTOR["ValueError\nno scanner object"]
    end

    subgraph RUNERR["During run_all_scans"]
        SINGLE["Single module raises"] --> CATCH["Caught at future\nempty module result"]
        TIMEOUT["future.result timeout"] --> CATCH
        NET["HTTP errors in scanner"] --> CATCH2["Caught in module\nshort or empty list"]
        KB2["User Ctrl+C"] --> KRET["Interrupt handler\npartial results"]
    end

    subgraph POST["After merge"]
        AGGOK["All modules finished or cleared"] --> LABEL["Compute risk_level"]
    end

    CATCH --> AGGOK
    CATCH2 -.-> AGGOK
    KRET -.->|if returned early| UIEND
    LABEL --> UIEND([UI and report render])
```

---

## 7. Functional workflow table

| Step | Actor | Input | Processing | Output |
|------|-------|--------|------------|--------|
| 1 | User | Target URL, scan mode | Chooses web UI (Flask or Streamlit) | Scan request |
| 2 | System | URL | `validate_url` | Proceed or reject |
| 3 | System | URL, timeout, options | Construct `VulnerabilityScanner` | Ready orchestrator |
| 4 | System | Target | Parallel module execution | Per-module finding lists |
| 5 | System | Raw findings | Count + classify risk | `summary` |
| 6 | System | Results | `generate_report` / templates | HTML / downloadable report |
| 7 | User | Report | Review dashboard | Remediation planning |

---

## 8. Module-to-purpose mapping (scan layer)

| Module key | Purpose (short) |
|------------|-----------------|
| `xss` | Reflected/stored XSS heuristics |
| `sqli` | SQL injection probes / indicators |
| `ports` | Exposed services / port checks |
| `paths` | Sensitive path discovery |
| `misconfig` | Common header/config issues |
| `xxe` | XML external entity exposure patterns |
| `ssrf` | Server-side request misuse indicators |
| `rce` | Remote execution pattern signals |
| `idor` | Object reference access issues |
| `csrf` | CSRF protection signals |
| `jwt` | JWT structure / weak claims checks |
| `api` | REST/GraphQL-style API issues |
| `bruteforce` | Weak auth / rate-limit heuristics |
| `ssl` | TLS/SSL configuration review |

---

## 9. IEEE-style reference papers (table)

The following table lists **ten** references in **IEEE citation style** (numbered). Use `[1]`–`[10]` in your paper’s reference list. Verify page numbers and spelling against IEEE Xplore or the publisher site for final camera-ready copy.

| Ref. | IEEE-formatted bibliography |
|------|------------------------------|
| [1] | J. Bau, E. Bursztein, D. Gupta, and J. C. Mitchell, “State of the Art: Automated Black-Box Web Application Vulnerability Testing,” in *Proc. IEEE Symp. Security Privacy*, Oakland, CA, USA, 2010, pp. 332–346. |
| [2] | A. Doupé, M. Cova, and G. Vigna, “Why Johnny Can't Pentest: An Analysis of Black-Box Web Vulnerability Scanners,” in *Proc. 7th Int. Conf. Detection Intrusions Malware Vulnerability Assessment (DIMVA)*, Bonn, Germany, 2010, pp. 111–131, doi: 10.1007/978-3-642-14215-4\_7. |
| [3] | NIST, *Technical Guide to Information Security Testing and Assessment*, Special Publication 800-115, Aug. 2008. |
| [4] | MITRE, “2023 CWE Top 25 Most Dangerous Software Weaknesses,” MITRE Corp., 2023. [Online]. Available: https://cwe.mitre.org/top25/ |
| [5] | OWASP Foundation, “OWASP Top 10:2021 — The Ten Most Critical Web Application Security Risks,” OWASP, 2021. [Online]. Available: https://owasp.org/www-project-top-ten/ |
| [6] | D. Balzarotti et al., “Saner: Composing Static and Dynamic Analysis to Validate Sanitization in Web Applications,” in *Proc. IEEE Symp. Security Privacy*, Oakland, CA, USA, 2008, pp. 387–401. |
| [7] | J. C. Fonseca, M. Vieira, and H. Madeira, “Evaluation of Web Security Mechanisms Using Vulnerability & Attack Injection,” *IEEE Trans. Dependable Secure Comput.*, vol. 11, no. 5, pp. 453–468, Sep./Oct. 2014, doi: 10.1109/TDSC.2013.56. |
| [8] | S. Alazmi and D. Conte de León, “A Systematic Literature Review on the Characteristics and Effectiveness of Web Application Vulnerability Scanners,” *IEEE Access*, vol. 10, pp. 33200–33219, 2022, doi: 10.1109/ACCESS.2022.3161522. |
| [9] | S. B. Lipner, “Principles for Secure Software Development,” *IEEE Security Privacy*, vol. 9, no. 2, pp. 71–75, Mar./Apr. 2011, doi: 10.1109/MSP.2011.46. |
| [10] | J. V. Antunes, N. Neves, and P. Veríssimo, “Detection and Prediction of Resource Exhaustion Attacks,” in *Proc. IEEE/IFIP Int. Conf. Dependable Syst. Netw. (DSN)*, 2008, pp. 102–111, doi: 10.1109/DSN.2008.4630062. |

**Notes for authors**

- Entries **[1]**, **[6]**, **[7]**, **[8]**, **[9]**, and **[10]** are **IEEE** journals, magazines, or IEEE/co-sponsored conference proceedings (suitable for an IEEE-style reference list).
- **[2]** is a **highly cited** black-box scanner evaluation in **Springer LNCS** (DIMVA); commonly cited next to IEEE DAST work—confirm house style if your venue requires *only* IEEE publications.
- **[3]**, **[4]**, and **[5]** are **standards and industry bodies** (NIST, MITRE CWE, OWASP) frequently paired with IEEE sources in applied security papers.

Double-check vol./no./pages in IEEE Xplore before camera-ready submission; use the DOI links when available.

---

## 10. Link to repository artifacts

| Artifact | Path |
|---------|------|
| Architecture write-up | `Document/07_System_Architecture.md` |
| Workflow tables & Mermaid | `Document/10_Dataflow_Workflow_Tables.md` |
| SVG flowcharts | `Document/assets/flowcharts/*.svg` |
| Scan coordinator | `modules/scanner.py` |
| Flask integration | `app.py` |

---

*Document generated for CyberWolfScanner — working description, flowcharts, and bibliography table for academic referencing.*
