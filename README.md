# **SharePoint Restricted Environment Data Collector**  

## **Overview**  
The **SharePoint Restricted Environment Data Collector** is a **PowerShell-based tool** designed to gather as much information as possible from a **SharePoint environment** with **minimal dependencies**, even in **locked-down or restricted conditions**. The script automatically determines the best available method to extract data, utilizing:  

- **SharePoint Management Shell Cmdlets** (if available)  
- **Client-Side Object Model (CSOM)** for SharePoint Online and On-Premises  
- **SharePoint REST API** for modern authentication and fallback  

This tool also collects **system diagnostics**, including user permissions, network status, and running processes, to help identify potential execution constraints. All collected information is **logged and saved** in structured formats (**JSON and text**) for easy analysis.  

---

## **Features**  
✅ **Multiple Data Retrieval Methods** – Uses SharePoint Management Shell, CSOM, and REST API, automatically switching based on availability. **(PARTIALLY COMPLETED - 2/3 Methods Implemented)**  
✅ **Minimal Dependencies** – Runs without requiring additional modules, ensuring compatibility in locked-down environments. **(COMPLETED)**  
✅ **Fault Tolerance & Failsafes** – Implements automatic retries, error handling, and fallback mechanisms for uninterrupted execution. **(COMPLETED)**  
✅ **Detailed Logging & Output** – Generates execution logs and structured reports in JSON and human-readable text formats. **(COMPLETED - Logger Module)**   
✅ **System Information Gathering** – Collects OS details, user permissions, and network diagnostics to assess environment restrictions. **(COMPLETED - SystemInfoHelper Module)**  

---

## **Installation & Usage**  

### **Prerequisites**  
- **Windows PowerShell 5.1+**  
- **SharePoint access credentials**  
- **Execution policy set to allow script execution** (`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)  

### **Clone the Repository**  
```sh
git clone https://github.com/your-repo/sharepoint-data-collector.git
cd sharepoint-data-collector
```

### **Run the Script**  
```powershell
.\src\SPDataCollector.ps1 -SiteUrl "https://your-sharepoint-site-url"
```

### **Example Output**  
After execution, results are saved in the **`output/`** directory:  
- `SPDataOutput.json` – Structured JSON report  
- `SPDataOutput.txt` – Human-readable summary  

Logs are stored in **`logs/SPDataCollector.log`**.  

---

## **Data Collection Methods & Failsafes**  

| **Method** | **Description** | **Failsafe Mechanisms** | **Status** |
|------------|----------------|-------------------------|------------|
| **SharePoint Management Shell Cmdlets** | Uses `Get-SPSite`, `Get-SPWeb`, etc. to retrieve site collections, users, and permissions. | If unavailable, falls back to CSOM or REST API. | **COMPLETED** |
| **Client-Side Object Model (CSOM)** | Uses .NET-based CSOM to authenticate and query SharePoint data. | If CSOM fails, attempts REST API. | **COMPLETED** |
| **REST API** | Uses `_api/web` to retrieve site metadata and lists. | If REST API is blocked, logs failure and returns partial results. | **PENDING** |
| **System Information** | Retrieves OS version, user privileges, network status, and running processes. | If restricted, logs failures and continues execution. | **COMPLETED** |

---

## **Repository Structure**  
```
sharepoint-data-collector/
│── src/
│   ├── SPDataCollector.ps1 (PENDING)
│   ├── modules/
│   │   ├── CSOMHelper.psm1 (COMPLETED)
│   │   ├── SPCmdletHelper.psm1 (COMPLETED)
│   │   ├── RESTHelper.psm1 (PENDING)
│   │   ├── SystemInfoHelper.psm1 (COMPLETED)
│   │   ├── Logger.psm1 (COMPLETED)
│   │   └── Failsafe.psm1 (COMPLETED)
│   ├── config/
│   │   ├── settings.json (COMPLETED)
│   │   ├── credentials.template.json (COMPLETED)
│   │   └── endpoints.json (COMPLETED)
│── logs/
│   ├── SPDataCollector.log
│── output/
│   ├── SPDataOutput.json
│   ├── SPDataOutput.txt
│── tests/
│   ├── test_SPDataCollector.ps1 (PENDING)
│   ├── test_CSOMHelper.ps1 (PENDING)
│   ├── test_RESTHelper.ps1 (PENDING)
│── docs/
│   ├── TECH_SPEC.md (COMPLETED)
│   ├── USAGE.md (PENDING)
│   ├── CHANGELOG.md (COMPLETED)
│── .gitignore (COMPLETED)
│── README.md (COMPLETED)
```

---

## **Logging & Output**  
All execution details, including successes and failures, are **logged in real time**.  

### **Example Log Entry**  
```
[2025-03-14 12:34:56] INFO: SharePoint Management Shell detected.
[2025-03-14 12:34:57] SUCCESS: Retrieved 3 site collections using Get-SPSite.
[2025-03-14 12:35:10] ERROR: CSOM authentication failed. Retrying...
[2025-03-14 12:35:15] ERROR: CSOM authentication failed. Moving to REST API.
[2025-03-14 12:35:20] SUCCESS: Retrieved site info via REST API.
```

---

## **Error Handling & Fallback Logic**  

The script automatically handles common failures:  

- **Permission Issues** – Falls back to another method if an API or cmdlet is blocked.  
- **Authentication Errors** – Retries with alternative authentication methods where possible.  
- **Network Issues** – Checks SharePoint connectivity before execution.  
- **Execution Policy Restrictions** – Warns the user and suggests solutions.  

---

## **Future Enhancements**  
🚀 **PnP PowerShell Support** – Expand capabilities using modern PnP PowerShell cmdlets.  
📊 **Export to CSV & Excel** – Provide structured data for business reporting.  
🔒 **Custom Authentication Methods** – Support app-based authentication for restricted environments.  
🖥️ **GUI Interface** – Develop a simple UI for non-technical users.  

---

## **Conclusion**  
The **SharePoint Restricted Environment Data Collector** is a powerful, **failsafe-driven** tool that maximizes **data extraction** while handling **locked-down access restrictions**. By dynamically selecting the best retrieval method and incorporating **robust error handling**, it ensures **reliable data collection** with **minimal setup**.  