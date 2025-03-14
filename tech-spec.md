# **Technical Specification Document**  
## **SharePoint Restricted Environment Data Collector (MVP)**  

## **Current Implementation Status**
As of the latest update, the following components have been implemented:

### **Completed Components**
- **Core Infrastructure**
  - ✅ Project Repository Structure
  - ✅ Documentation Framework

- **PowerShell Modules**
  - ✅ Logger Module (Logger.psm1)
  - ✅ Failsafe Module (Failsafe.psm1) 
  - ✅ System Information Helper (SystemInfoHelper.psm1)
  - ✅ SharePoint Management Shell (SPCmdletHelper.psm1)
  - ✅ Client-Side Object Model Helper (CSOMHelper.psm1)

- **Configuration**
  - ✅ Settings Configuration (settings.json)
  - ✅ Credentials Template (credentials.template.json)
  - ✅ REST API Endpoints (endpoints.json)

### **Pending Components**
- REST API Helper (RESTHelper.psm1)
- Main Script (SPDataCollector.ps1)
- Testing Framework
- Usage Documentation

### **1. Overview**  
This project aims to develop a robust PowerShell-based script that collects as much information as possible from a SharePoint environment with minimal dependencies, even in locked-down or restricted conditions. The script will implement multiple data retrieval methods, including SharePoint Management Shell, Client-Side Object Model (CSOM), and SharePoint REST API. Additionally, it will include fault tolerance mechanisms to handle errors gracefully, retry failed operations, and provide useful debugging information.

---

### **2. Objectives**  
- Collect detailed SharePoint environment information with minimal dependencies.  
- Implement multiple retrieval methods (SP Management Shell, CSOM, REST API).  
- Ensure fault tolerance with retries, fallback mechanisms, and error handling.  
- Collect system-related information to assess execution constraints.  
- Log failures and successes to aid debugging in restrictive environments.  

---

### **3. Technical Requirements**  
#### **3.1. Execution Environment**
- The script will be written in **PowerShell** (compatible with PowerShell 5.1 and above).  
- The script must be **executable with default system tools** (no external dependencies).  
- It must support execution in environments with **limited user privileges**.  
- It must be **network-aware** to check for connectivity to SharePoint.  

#### **3.2. SharePoint Compatibility**  
- Must support **SharePoint Online** (Microsoft 365).  
- Must support **SharePoint Server (On-Premises) 2013, 2016, and 2019**.  

---

### **4. Data Collection Methods & Failsafes**  
The script will attempt **multiple approaches** to collect data. If one method fails, it will **log the failure and attempt the next available method**.

| **Method** | **Description** | **Failsafe Mechanisms** | **Status** |
|------------|----------------|-------------------------|------------|
| **SharePoint Management Shell Cmdlets** | Uses native `Get-SPSite`, `Get-SPWeb`, and other SharePoint cmdlets to gather information. | If cmdlets are unavailable or fail, fallback to CSOM or REST API. | **COMPLETED** |
| **Client-Side Object Model (CSOM)** | Uses .NET-based CSOM libraries to query SharePoint. | If CSOM cannot authenticate or fails, fallback to REST API. | **COMPLETED** |
| **REST API** | Uses `Invoke-WebRequest` or `Invoke-RestMethod` to retrieve SharePoint metadata. | If REST API fails, log the issue and return partial results. | **PENDING** |
| **System Information** | Retrieves Windows OS, user privileges, network status, running processes. | If certain commands are blocked, log which ones failed and continue. | **COMPLETED** |

---

### **5. Script Execution Flow**  
1. **Preliminary Checks**  
   - Verify execution privileges (Admin vs. User mode).  
   - Check network connectivity to SharePoint.  
   - Detect SharePoint environment type (Online vs. On-Premises).  
   - Check for installed SharePoint cmdlets, CSOM libraries, and API access.  

2. **SharePoint Data Collection (Failsafe Approach)**  
   - **Attempt SharePoint Management Shell Cmdlets**  
     - If available, collect site collections, web details, users, and permissions.  
     - If unavailable, proceed to CSOM.  
   - **Attempt CSOM Method**  
     - Authenticate using the current user's credentials.  
     - Retrieve site details, sub-sites, document libraries, and user roles.  
     - If CSOM fails, proceed to REST API.  
   - **Attempt REST API Method**  
     - Fetch SharePoint metadata via `_api/web` endpoint.  
     - Collect site details, lists, users, and document libraries.  
     - If REST API is blocked, log failure and continue.  

3. **System Information Collection**  
   - Retrieve OS details, PowerShell version, network connectivity.  
   - List running processes to detect potential restrictions.  

4. **Error Handling & Fallback Mechanisms**  
   - If a method fails, log the error and retry up to 3 times before moving to the next method.  
   - If all methods fail, log environment constraints and suggest troubleshooting steps.  

---

### **6. Logging & Reporting**  
#### **6.1. Logging Mechanism**  
- The script will generate a log file (`SPDataCollector.log`) containing:  
  - Execution time and environment details.  
  - Success or failure of each method.  
  - Detailed error messages if a method fails.  
  - Summary of collected data.  

- Example Log Entry:  
```plaintext
[2025-03-14 12:34:56] INFO: SharePoint Management Shell detected.
[2025-03-14 12:34:57] SUCCESS: Retrieved 3 site collections using Get-SPSite.
[2025-03-14 12:35:10] ERROR: CSOM authentication failed. Retrying...
[2025-03-14 12:35:15] ERROR: CSOM authentication failed. Moving to REST API.
[2025-03-14 12:35:20] SUCCESS: Retrieved site info via REST API.
```

#### **6.2. Output Format**  
- The script will output data in:  
  - **Console logs** (real-time updates).  
  - **JSON file** (`SPDataOutput.json`) for structured data storage.  
  - **Plain text file** (`SPDataOutput.txt`) for simple analysis.  

---

### **7. Security Considerations**  
- **No external dependencies** (ensures execution in locked-down environments).  
- **Minimal credential exposure** (uses current user's context where possible).  
- **Secure storage** (temporary credentials stored in a SecureString object).  
- **No modification operations** (script is read-only to prevent accidental changes).  

---

### **8. Example PowerShell Snippet (Error Handling & Fallback)**  
```powershell
function Get-SharePointInfo {
    param (
        [string]$SiteUrl
    )

    Write-Host "Attempting SharePoint data collection..."

    # Try SharePoint Cmdlets
    try {
        if (Get-Command Get-SPSite -ErrorAction SilentlyContinue) {
            $sites = Get-SPSite -ErrorAction Stop
            Write-Host "Success: Retrieved $($sites.Count) site collections."
            return $sites
        } else {
            throw "SharePoint cmdlets not available."
        }
    } catch {
        Write-Host "SP Cmdlets Failed. Attempting CSOM..."
    }

    # Try CSOM
    try {
        Add-Type -Path "C:\Path\to\Microsoft.SharePoint.Client.dll"
        $context = New-Object Microsoft.SharePoint.Client.ClientContext($SiteUrl)
        $context.Credentials = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials($env:USERNAME, (ConvertTo-SecureString "password" -AsPlainText -Force))
        $context.Load($context.Web)
        $context.ExecuteQuery()
        Write-Host "Success: Retrieved CSOM data."
        return $context.Web
    } catch {
        Write-Host "CSOM Failed. Attempting REST API..."
    }

    # Try REST API
    try {
        $headers = @{"Accept"="application/json;odata=verbose"}
        $response = Invoke-RestMethod -Uri "$SiteUrl/_api/web" -Headers $headers -UseDefaultCredentials
        Write-Host "Success: Retrieved REST API data."
        return $response
    } catch {
        Write-Host "All methods failed. Check log for details." -ForegroundColor Red
    }
}
```

---

### **9. Future Enhancements**  
- Implement **PnP PowerShell** support for enhanced query capabilities.  
- Add **GUI-based execution** for easier usage by non-technical users.  
- Support for exporting data to **CSV and Excel** formats.  