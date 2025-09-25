# Security QA Agent Data Processing Flow

## System Architecture Overview

```mermaid
graph TB
    subgraph "External Data Sources"
        A[Splunk SIEM<br/>Closed Incidents] 
        B[Confluence<br/>SOC Playbooks]
        C[MITRE ATT&CK<br/>Knowledge Base]
    end
    
    subgraph "Data Ingestion & Processing"
        D[confluence_to_vector_db.py<br/>Playbook Ingestion]
        E[mitre_attack_updater.py<br/>MITRE Data Update]
        F[soc_qa_agent.py<br/>Main QA Process]
    end
    
    subgraph "Vector Databases"
        G[Chroma Vector DB<br/>Playbooks]
        H[Chroma Vector DB<br/>MITRE ATT&CK]
    end
    
    subgraph "AI Processing"
        I[Ollama LLM<br/>llama3:8b]
        J[HuggingFace Embeddings<br/>all-MiniLM-L6-v2]
    end
    
    subgraph "Output & Storage"
        K[QA Reports<br/>JSON Format]
        L[Splunk HEC<br/>QA Reports Index]
        M[Log Files<br/>Processing Logs]
    end
    
    subgraph "Scheduling"
        N[Cron Jobs<br/>Hourly/Monthly]
    end
    
    %% Data Flow Connections
    B --> D
    C --> E
    A --> F
    
    D --> G
    E --> H
    
    G --> F
    H --> F
    
    F --> I
    F --> J
    
    I --> K
    J --> K
    
    K --> L
    F --> M
    
    N --> F
    N --> E
```

## Detailed Data Processing Flow

```mermaid
flowchart TD
    Start([QA Agent Started]) --> Init[Initialize Components]
    
    Init --> LoadConfig[Load Configuration<br/>- Splunk HEC settings<br/>- Confluence credentials<br/>- LLM parameters]
    
    LoadConfig --> LoadVectorDB[Load Vector Databases<br/>- Playbook embeddings<br/>- MITRE ATT&CK embeddings]
    
    LoadVectorDB --> LoadLLM[Initialize Ollama LLM<br/>- Model: llama3:8b<br/>- Temperature: 0.1]
    
    LoadLLM --> GetIncidents[Retrieve Closed Incidents<br/>from Splunk]
    
    GetIncidents --> ProcessIncident{For Each Incident}
    
    ProcessIncident --> ExtractData[Extract Incident Data<br/>- Incident ID & Title<br/>- Analyst Name<br/>- Notable Event Data<br/>- Audit Timeline]
    
    ExtractData --> RetrievePlaybook[Retrieve Relevant Playbook<br/>via Vector Similarity Search]
    
    RetrievePlaybook --> ExtractMITRE[Extract MITRE Techniques<br/>from Notable Data]
    
    ExtractMITRE --> RetrieveMITRE[Retrieve MITRE Context<br/>via Vector Similarity Search]
    
    RetrieveMITRE --> PreparePrompt[Prepare LLM Prompt<br/>- Incident details<br/>- Playbook text<br/>- MITRE context<br/>- Audit timeline]
    
    PreparePrompt --> GenerateReport[Generate QA Report<br/>using Ollama LLM]
    
    GenerateReport --> ValidateJSON{Valid JSON?}
    
    ValidateJSON -->|Yes| SendToSplunk[Send Report to Splunk HEC]
    ValidateJSON -->|No| LogWarning[Log Warning & Continue]
    
    SendToSplunk --> LogSuccess[Log Success]
    LogWarning --> LogSuccess
    
    LogSuccess --> NextIncident{More Incidents?}
    
    NextIncident -->|Yes| ProcessIncident
    NextIncident -->|No| Complete[QA Cycle Complete]
    
    Complete --> End([End])
    
    %% Error Handling
    ProcessIncident -->|Error| LogError[Log Error & Continue]
    LogError --> NextIncident
```

## Knowledge Base Update Flow

```mermaid
flowchart TD
    subgraph "Monthly MITRE Update"
        A1[Cron Trigger<br/>Monthly] --> A2[Check Last Update]
        A2 --> A3{Update Needed?}
        A3 -->|Yes| A4[Fetch MITRE ATT&CK Data<br/>via mitreattack-python]
        A3 -->|No| A5[Skip Update]
        A4 --> A6[Process Techniques<br/>to Documents]
        A6 --> A7[Create Embeddings<br/>HuggingFace all-MiniLM-L6-v2]
        A7 --> A8[Update Vector DB<br/>Chroma]
        A8 --> A9[Record Update Time]
    end
    
    subgraph "Initial Playbook Setup"
        B1[Manual Run] --> B2[Connect to Confluence<br/>using API credentials]
        B2 --> B3[Load Playbook Pages<br/>from SOC space]
        B3 --> B4[Split Documents<br/>1000 char chunks]
        B4 --> B5[Create Embeddings<br/>HuggingFace all-MiniLM-L6-v2]
        B5 --> B6[Store in Vector DB<br/>Chroma]
    end
```

## QA Report Structure

```mermaid
graph LR
    subgraph "Input Data"
        A[Incident Details<br/>- ID, Title, Analyst]
        B[Notable Event Data<br/>- MITRE Techniques<br/>- Severity, Source IP]
        C[Audit Timeline<br/>- Actions taken<br/>- Comments, Timestamps]
        D[Playbook Text<br/>- Official procedures]
        E[MITRE Context<br/>- Technique details]
    end
    
    subgraph "LLM Processing"
        F[Prompt Template<br/>Structured QA Instructions]
        G[Ollama LLM<br/>Analysis & Scoring]
    end
    
    subgraph "Output Report"
        H[JSON QA Report<br/>- Accuracy Score 1-5<br/>- Procedure Score 1-5<br/>- Documentation Score 1-5<br/>- Missed Steps List<br/>- Escalation Required<br/>- Summary & Recommendations]
    end
    
    A --> F
    B --> F
    C --> F
    D --> F
    E --> F
    
    F --> G
    G --> H
```

## System Components

| Component | Purpose | Technology |
|-----------|---------|------------|
| **Data Sources** | Incident data, playbooks, threat intel | Splunk, Confluence, MITRE |
| **Vector Storage** | Semantic search for relevant content | Chroma DB |
| **Embeddings** | Convert text to vectors | HuggingFace all-MiniLM-L6-v2 |
| **LLM** | Generate QA reports | Ollama (llama3:8b) |
| **Scheduling** | Automated execution | Cron jobs |
| **Logging** | Process monitoring | Python logging |

## Key Features

1. **Automated QA Review**: Processes closed incidents hourly
2. **Knowledge Base Integration**: Uses Confluence playbooks and MITRE ATT&CK
3. **AI-Powered Analysis**: Local LLM for consistent, private analysis
4. **Structured Output**: JSON reports for easy integration
5. **Splunk Integration**: Reports stored back in Splunk for dashboards
6. **Self-Updating**: Monthly MITRE ATT&CK knowledge base updates
