# **GitHub Repository File Architecture**  

Below is the proposed GitHub repository structure for the **SharePoint Restricted Environment Data Collector** project. Each file is described in detail, outlining its purpose in the repository.  

---

## **Repository Structure**  

```
sharepoint-data-collector/
│── src/
│   ├── SPDataCollector.ps1 [PENDING]
│   ├── modules/
│   │   ├── CSOMHelper.psm1 [COMPLETED]
│   │   ├── SPCmdletHelper.psm1 [COMPLETED]
│   │   ├── RESTHelper.psm1 [PENDING]
│   │   ├── SystemInfoHelper.psm1 [COMPLETED]
│   │   ├── Logger.psm1 [COMPLETED]
│   │   └── Failsafe.psm1 [COMPLETED]
│   ├── config/
│   │   ├── settings.json [COMPLETED]
│   │   ├── credentials.template.json [COMPLETED]
│   │   └── endpoints.json [COMPLETED]
│── logs/ [COMPLETED]
│   ├── SPDataCollector.log
│── output/ [COMPLETED]
│   ├── SPDataOutput.json
│   ├── SPDataOutput.txt
│── tests/ [COMPLETED]
│   ├── test_SPDataCollector.ps1 [PENDING]
│   ├── test_CSOMHelper.ps1 [PENDING]
│   ├── test_RESTHelper.ps1 [PENDING]
│── docs/ [COMPLETED]
│   ├── TECH_SPEC.md [COMPLETED]
│   ├── USAGE.md [PENDING]
│   ├── CONTRIBUTING.md [COMPLETED]
│   ├── CHANGELOG.md [COMPLETED]
│── .gitignore [COMPLETED]
│── README.md [COMPLETED]
│── LICENSE [COMPLETED]
```

---

## **File Descriptions**  

### **1. Source Code (`src/`)** [COMPLETED]
- **`SPDataCollector.ps1`** [PENDING] – The main PowerShell script that orchestrates data collection, calling various modules for SharePoint queries and system info retrieval.  
- **`modules/`** [COMPLETED] – Directory for modular PowerShell scripts.  
  - **`CSOMHelper.psm1`** [COMPLETED] – Handles SharePoint Client-Side Object Model (CSOM) operations, including authentication and data retrieval.  
  - **`SPCmdletHelper.psm1`** [COMPLETED] – Handles SharePoint Management Shell cmdlets for data retrieval.
  - **`RESTHelper.psm1`** [PENDING] – Facilitates communication with the SharePoint REST API, retrieving site and document metadata.  
  - **`SystemInfoHelper.psm1`** [COMPLETED] – Gathers local system details such as OS, PowerShell version, running processes, and network status.  
  - **`Logger.psm1`** [COMPLETED] – Provides centralized logging functionality to write logs to both the console and a log file.  
  - **`Failsafe.psm1`** [COMPLETED] – Implements retry mechanisms, failover logic, and error handling strategies.  

### **2. Configuration (`config/`)** [COMPLETED]
- **`settings.json`** [COMPLETED] – Stores runtime configurations such as retry limits and output formats.  
- **`credentials.template.json`** [COMPLETED] – A template for user credentials (users will copy and rename it to `credentials.json`).  
- **`endpoints.json`** [COMPLETED] – Defines SharePoint REST API endpoints and query structures.  

### **3. Logs (`logs/`)** [COMPLETED]
- **`SPDataCollector.log`** – Stores execution logs, including successes, failures, and debugging information.  

### **4. Output (`output/`)** [COMPLETED]
- **`SPDataOutput.json`** – Stores structured data collected from SharePoint in JSON format.  
- **`SPDataOutput.txt`** – Provides a human-readable summary of collected information.  

### **5. Tests (`tests/`)** [COMPLETED]
- **`test_SPDataCollector.ps1`** [PENDING] – Unit tests for the main script.  
- **`test_CSOMHelper.ps1`** [PENDING] – Unit tests for the CSOM module.  
- **`test_RESTHelper.ps1`** [PENDING] – Unit tests for the REST API module.  

### **6. Documentation (`docs/`)** [COMPLETED]
- **`TECH_SPEC.md`** [COMPLETED] – Contains the full technical specification document.  
- **`USAGE.md`** [PENDING] – Instructions on how to run the script, configure settings, and interpret outputs.  
- **`CONTRIBUTING.md`** [COMPLETED] – Guidelines for contributors, including coding standards.  
- **`CHANGELOG.md`** [COMPLETED] – A log of version changes and updates.  

### **7. Root Files**
- **`.gitignore`** [COMPLETED] – Excludes logs, output files, and sensitive data from version control.  
- **`README.md`** [COMPLETED] – Overview of the project, including purpose, setup, and usage instructions.  
- **`LICENSE`** [COMPLETED] – Open-source license file. 