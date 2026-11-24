# ThreatLens
### Automated Threat Detection & Intelligence Platform

ThreatLens is a cybersecurity project I'm building to bring together security event ingestion, threat detection, threat intelligence enrichment, and incident investigation in one platform.

The idea is to build a working detection and investigation pipeline rather than just a dashboard that displays alerts. It takes security events, processes them, identifies suspicious activity using detection rules, enriches relevant indicators, and groups related alerts into incidents that can be investigated and reported.

## What it does

ThreatLens currently supports the following workflow:

1. Ingest security events from JSONL files.
2. Parse, normalize, and validate incoming events.
3. Run detection rules against processed events.
4. Enrich IP addresses, domains, and file hashes using threat intelligence sources.
5. Correlate related alerts into incidents.
6. Calculate incident risk scores with an explainable scoring breakdown.
7. Map relevant detections to MITRE ATT&CK.
8. Investigate incidents through a Streamlit dashboard.
9. Export incident reports in JSON and PDF formats.

## Features

### Event ingestion and processing

- JSONL event ingestion.
- JSON parsing and validation.
- Field normalization across different event formats.
- Timestamp standardization to UTC.
- IP address validation.
- SHA-256 fingerprinting to prevent duplicate event storage.
- SQLite database for storing events and investigation data.

### Detection engine

Detection logic is written in Python, with configurable rules stored in YAML.

| Rule ID | Detection | MITRE ATT&CK |
|---|---|---|
| TL-001 | Repeated failed authentication attempts | T1110 |
| TL-002 | Encoded PowerShell execution | T1059.001 |
| TL-003 | Outbound connection matching a local IOC | Not mapped |

The current rules cover:
- Brute-force authentication attempts within a defined time window.
- Encoded PowerShell command execution.
- Outbound connections to IP addresses in a local indicator list.

Each generated alert retains its detection details and references to the original events that triggered it.

### Threat intelligence enrichment

ThreatLens uses multiple sources to add context to detected indicators.

- VirusTotal API
- AlienVault OTX API
- Local IOC list

Supported indicator types:
- IP addresses
- Domains
- File hashes

The enrichment layer also includes:
- A unified provider manager.
- Independent handling of provider failures.
- SQLite-based caching.
- Cache expiration.
- Structured results from each provider.

Threat intelligence results are treated as supporting information for an investigation, not automatic confirmation that an indicator is malicious.

### Incident management

Related alerts can be grouped into incidents, giving an analyst a single place to investigate an activity.

Current functionality includes:
- Incident creation and alert correlation.
- Severity and priority tracking.
- Incident status management.
- Analyst investigation notes.
- Incident merging.
- Activity history and timelines.

Supported incident statuses are Open, Investigating, Resolved, and False Positive.

### Incident risk scoring

I implemented an explainable scoring engine to help prioritize incidents.

The score combines four components:

| Component | Maximum |
|---|---:|
| Alert severity | 40 |
| Alert volume | 15 |
| Threat intelligence | 25 |
| MITRE ATT&CK context | 10 |
| **Total** | **90** |

The result includes a numerical score, priority classification, and a breakdown showing how each component contributed.

Priority levels are Low, Medium, High, and Critical.

### Investigation dashboard

The dashboard is built with Streamlit and provides an interface for reviewing incidents and their associated evidence.

It currently includes:
- Security overview metrics.
- Incident filtering by priority and status.
- Incident investigation view.
- Related alert inspection.
- Retrieval of original security events.
- Source and destination IP information.
- Username, hostname, process, and command-line fields.
- Threat intelligence enrichment results.
- MITRE ATT&CK mappings.
- Risk score breakdown.
- Analyst notes.
- Incident activity timeline.

An important part of the investigation view is keeping the original observed events separate from the conclusions made by detection rules.

### Incident reporting

Incidents can be exported directly from the dashboard.

**JSON reports**
- Incident details and status.
- Risk assessment and scoring breakdown.
- Related alerts.
- Original evidence events.
- Threat intelligence results.
- MITRE ATT&CK mappings.
- Analyst notes and timeline.

**PDF reports**

A formatted version of the same investigation data, intended for easier review and documentation.

Both formats use the same underlying report data structure.

## Tech stack

| Area | Technologies |
|---|---|
| Language | Python |
| Database | SQLite |
| Dashboard | Streamlit |
| Visualization | Plotly |
| Detection rules | YAML |
| Threat intelligence | VirusTotal, AlienVault OTX |
| Framework | MITRE ATT&CK |
| Data formats | JSON, JSONL |
| Testing | Pytest |
| HTTP requests | Requests |
| PDF generation | ReportLab |
| Version control | Git, GitHub |

## Architecture

```text
Security Event Sources
         |
         v
   Event Ingestion
         |
         v
 Parsing & Normalization
         |
         v
   SQLite Database
         |
         v
   Detection Engine
    Python + YAML
         |
         v
       Alerts
         |
         +-------------------+
         |                   |
         v                   v
 Threat Intelligence    MITRE ATT&CK
 VirusTotal / OTX          Mapping
 Local IOC List
         |                   |
         +---------+---------+
                   |
                   v
           Alert Correlation
                   |
                   v
               Incidents
                   |
                   v
          Incident Risk Scoring
                   |
                   v
           Streamlit Dashboard
                   |
             +-----+-----+
             |           |
             v           v
       Investigation   Reporting
       Evidence/Notes  JSON/PDF
       Timeline
```

## Project structure

```text
ThreatLens/
│
├── ingestion/
│   ├── parser.py
│   ├── normalizer.py
│   └── pipeline.py
│
├── detection/
│   ├── engine.py
│   ├── runner.py
│   └── rules/
│       ├── brute_force.yaml
│       ├── powershell.yaml
│       └── malicious_ip.yaml
│
├── enrichment/
│   ├── enricher.py
│   ├── provider_manager.py
│   └── providers/
│       ├── virustotal.py
│       └── otx.py
│
├── intelligence/
│   ├── ioc_list.txt
│   └── scoring.py
│
├── correlation/
│
├── database/
│   └── models.py
│
├── dashboard/
│   └── app.py
│
├── reporting/
│   ├── __init__.py
│   └── report_generator.py
│
├── sample_data/
│   └── events.jsonl
│
├── tests/
│
├── run.py
├── requirements.txt
├── .env.example
├── .gitignore
└── README.md
```

## Running locally

### Requirements

- Python 3.10 or later
- Git

API keys for VirusTotal and AlienVault OTX are optional.

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/ThreatLens.git
cd ThreatLens
```

### 2. Create a virtual environment

```bash
python -m venv .venv
```

For Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

For macOS or Linux:

```bash
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API keys

Create a `.env` file in the root directory:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
OTX_API_KEY=your_alienvault_otx_api_key
```

These integrations are optional. The core ingestion and detection workflow can run using local indicators without external API credentials.

Do not commit `.env` or expose API keys in the repository.

### 5. Run the pipeline

```bash
python run.py
```

### 6. Launch the dashboard

```bash
python -m streamlit run dashboard/app.py
```

## Testing

The project uses Pytest.

Run the full test suite:

```bash
python -m pytest -v
```

**Current test status: 117 passing.**

Tests cover ingestion, normalization, detection logic, database operations, threat intelligence providers, caching, incident management, correlation, risk scoring, evidence retrieval, and report generation.

## Data and limitations

The current sample dataset and local IOC list use synthetic test data. The IP indicators are documentation-reserved TEST-NET addresses, not real malicious infrastructure.

The project is currently a development and portfolio implementation. It is not intended to replace a production SIEM or an organization's incident response infrastructure.

Alerts, intelligence matches, and risk scores are investigation aids. They still require analyst validation.

## Development roadmap

The next areas I plan to work on include:

- Expanding detection coverage.
- Behaviour-based detection across multiple events.
- More advanced correlation and threat hunting.
- Additional security event sources.
- Improving investigation workflows and reporting.

---

Built as an ongoing project to explore threat intelligence, detection engineering, incident response, and security automation.
