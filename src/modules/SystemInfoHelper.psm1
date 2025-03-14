#Region Module Header
<#
.SYNOPSIS
PowerShell module for gathering system information in the SharePoint Restricted Environment Data Collector.

.DESCRIPTION
This module provides functions to collect information about the local system,
including OS details, PowerShell environment, user permissions, network status,
and SharePoint components.

.NOTES
File: SystemInfoHelper.psm1
Author: SharePoint Restricted Environment Data Collector Team
Version: 0.1.0
#>
#EndRegion Module Header

# Import required modules
# This assumes Logger.psm1 is in the same directory
$loggerPath = Join-Path -Path $PSScriptRoot -ChildPath "Logger.psm1"
if (Test-Path -Path $loggerPath) {
    Import-Module -Name $loggerPath -Force
}

# This assumes Failsafe.psm1 is in the same directory
$failsafePath = Join-Path -Path $PSScriptRoot -ChildPath "Failsafe.psm1"
if (Test-Path -Path $failsafePath) {
    Import-Module -Name $failsafePath -Force
}

<#
.SYNOPSIS
    Retrieves detailed information about the operating system.

.DESCRIPTION
    Collects comprehensive information about the operating system, 
    including version, architecture, and system properties.

.EXAMPLE
    Get-OSInformation

.NOTES
    Returns a PSObject with OS details.
#>
function Get-OSInformation {
    [CmdletBinding()]
    param()
    
    Write-VerboseLog "Collecting operating system information"
    
    try {
        # Get basic OS information
        $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
        
        # Get computer system information
        $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
        
        # Get BIOS information
        $bios = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop
        
        # Get processor information
        $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1
        
        # Check if the system is virtual
        $isVirtual = $false
        $virtualHints = @(
            "Virtual", "VMware", "VirtualBox", "Hyper-V", "Xen", "QEMU", "KVM"
        )
        
        foreach ($hint in $virtualHints) {
            if ($computerSystem.Manufacturer -like "*$hint*" -or $computerSystem.Model -like "*$hint*") {
                $isVirtual = $true
                break
            }
        }
        
        # Create and return an object with OS information
        $osInfo = [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            OSName = $os.Caption
            OSVersion = $os.Version
            OSBuildNumber = $os.BuildNumber
            OSArchitecture = $os.OSArchitecture
            OSLanguage = $os.OSLanguage
            SystemManufacturer = $computerSystem.Manufacturer
            SystemModel = $computerSystem.Model
            SerialNumber = $bios.SerialNumber
            BIOSVersion = $bios.SMBIOSBIOSVersion
            ProcessorName = $processor.Name
            ProcessorArchitecture = $processor.Architecture
            TotalPhysicalMemoryGB = [math]::Round($computerSystem.TotalPhysicalMemory / 1GB, 2)
            IsVirtualMachine = $isVirtual
            LastBootUpTime = $os.LastBootUpTime
            InstallDate = $os.InstallDate
            WindowsDirectory = $os.WindowsDirectory
            SystemDirectory = $os.SystemDirectory
            TempDirectory = $env:TEMP
            CurrentTimeZone = $os.CurrentTimeZone
            Locale = $os.Locale
            UserName = $env:USERNAME
            DomainName = $env:USERDOMAIN
        }
        
        Write-VerboseLog "OS information collected successfully"
        return $osInfo
    }
    catch {
        Write-ErrorLog -Message "Failed to collect OS information" -ErrorRecord $_
        
        # Return a minimal object with error information
        return [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Error = $_.Exception.Message
            OSName = $null
            OSVersion = $null
            UserName = $env:USERNAME
            DomainName = $env:USERDOMAIN
        }
    }
}

<#
.SYNOPSIS
    Retrieves information about the PowerShell environment.

.DESCRIPTION
    Collects details about the PowerShell version, installed modules,
    execution policy, and other runtime settings.

.EXAMPLE
    Get-PowerShellEnvironment

.NOTES
    Returns a PSObject with PowerShell environment details.
#>
function Get-PowerShellEnvironment {
    [CmdletBinding()]
    param()
    
    Write-VerboseLog "Collecting PowerShell environment information"
    
    try {
        # Get PowerShell version information
        $psVersion = $PSVersionTable
        
        # Get execution policy
        $executionPolicy = Get-ExecutionPolicy
        
        # Get execution policy for all scopes (might fail in restricted environments)
        $executionPolicies = Invoke-WithRetry -ScriptBlock {
            Get-ExecutionPolicy -List
        } -ContinueOnError -MaxRetries 0
        
        if ($executionPolicies.Success) {
            $executionPolicies = $executionPolicies.Result | ForEach-Object {
                [PSCustomObject]@{
                    Scope = $_.Scope
                    ExecutionPolicy = $_.ExecutionPolicy
                }
            }
        }
        else {
            $executionPolicies = @([PSCustomObject]@{
                Scope = "Current"
                ExecutionPolicy = $executionPolicy
            })
        }
        
        # Get installed modules
        $modules = @()
        try {
            $modules = Get-Module -ListAvailable | Select-Object Name, Version, ModuleBase, ModuleType
            Write-VerboseLog "Retrieved $(($modules | Measure-Object).Count) installed modules"
        }
        catch {
            Write-Log "Unable to retrieve installed modules: $($_.Exception.Message)" -Level WARNING
        }
        
        # Get loaded modules
        $loadedModules = @()
        try {
            $loadedModules = Get-Module | Select-Object Name, Version, ModuleBase, ModuleType
            Write-VerboseLog "Retrieved $(($loadedModules | Measure-Object).Count) loaded modules"
        }
        catch {
            Write-Log "Unable to retrieve loaded modules: $($_.Exception.Message)" -Level WARNING
        }
        
        # Check for common modules used with SharePoint
        $sharePointModules = @(
            "Microsoft.SharePoint.PowerShell",
            "SharePointPnPPowerShellOnline",
            "Microsoft.Online.SharePoint.PowerShell",
            "SharePointPnPPowerShell2013",
            "SharePointPnPPowerShell2016",
            "SharePointPnPPowerShell2019"
        )
        
        $installedSPModules = @()
        foreach ($spModule in $sharePointModules) {
            $moduleInfo = $modules | Where-Object { $_.Name -eq $spModule }
            if ($moduleInfo) {
                $installedSPModules += [PSCustomObject]@{
                    Name = $spModule
                    Version = $moduleInfo.Version
                    Path = $moduleInfo.ModuleBase
                }
            }
        }
        
        # Create and return an object with PowerShell environment information
        $psEnv = [PSCustomObject]@{
            PSVersion = $psVersion.PSVersion.ToString()
            PSEdition = $psVersion.PSEdition
            PSCompatibleVersions = $psVersion.PSCompatibleVersions
            CLRVersion = $psVersion.CLRVersion.ToString()
            BuildVersion = $psVersion.BuildVersion.ToString()
            Platform = [System.Environment]::OSVersion.Platform
            CurrentExecutionPolicy = $executionPolicy
            ExecutionPolicies = $executionPolicies
            Is64BitProcess = [System.Environment]::Is64BitProcess
            Is64BitOperatingSystem = [System.Environment]::Is64BitOperatingSystem
            PSModulePath = $env:PSModulePath
            InstalledModulesCount = ($modules | Measure-Object).Count
            LoadedModulesCount = ($loadedModules | Measure-Object).Count
            SharePointModules = $installedSPModules
        }
        
        Write-VerboseLog "PowerShell environment information collected successfully"
        return $psEnv
    }
    catch {
        Write-ErrorLog -Message "Failed to collect PowerShell environment information" -ErrorRecord $_
        
        # Return a minimal object with error information
        return [PSCustomObject]@{
            PSVersion = $PSVersionTable.PSVersion.ToString()
            Error = $_.Exception.Message
        }
    }
}

<#
.SYNOPSIS
    Checks the current user's permission level.

.DESCRIPTION
    Determines if the current user has administrator privileges
    and collects information about the user's security context.

.EXAMPLE
    Get-UserPermissionLevel

.NOTES
    Returns a PSObject with user permission details.
#>
function Get-UserPermissionLevel {
    [CmdletBinding()]
    param()
    
    Write-VerboseLog "Checking user permission level"
    
    try {
        # Get current user identity
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $currentPrincipal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
        
        # Check if running as administrator
        $isAdmin = $currentPrincipal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
        
        # Get user groups
        $userGroups = @()
        try {
            $currentUser.Groups | ForEach-Object {
                $sid = $_.Value
                $groupName = $null
                
                try {
                    $group = New-Object System.Security.Principal.SecurityIdentifier($sid)
                    $groupName = $group.Translate([System.Security.Principal.NTAccount]).Value
                }
                catch {
                    $groupName = $sid
                }
                
                $userGroups += [PSCustomObject]@{
                    Name = $groupName
                    SID = $sid
                }
            }
        }
        catch {
            Write-Log "Unable to enumerate all user groups: $($_.Exception.Message)" -Level WARNING
        }
        
        # Create and return an object with user permission information
        $permissionInfo = [PSCustomObject]@{
            UserName = $currentUser.Name
            UserSID = $currentUser.User.Value
            IsAdministrator = $isAdmin
            IsElevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
            AuthenticationType = $currentUser.AuthenticationType
            ImpersonationLevel = if ($currentUser.ImpersonationLevel) { $currentUser.ImpersonationLevel.ToString() } else { "None" }
            IsSystem = $currentUser.IsSystem
            IsGuest = $currentUser.IsGuest
            IsAnonymous = $currentUser.IsAnonymous
            GroupCount = ($userGroups | Measure-Object).Count
            Groups = $userGroups
        }
        
        Write-VerboseLog "User permission level checked successfully (IsAdmin: $isAdmin)"
        return $permissionInfo
    }
    catch {
        Write-ErrorLog -Message "Failed to check user permission level" -ErrorRecord $_
        
        # Return a minimal object with error information
        return [PSCustomObject]@{
            UserName = $env:USERNAME
            Error = $_.Exception.Message
            IsAdministrator = $null
        }
    }
}

<#
.SYNOPSIS
    Retrieves detailed network configuration information.

.DESCRIPTION
    Collects information about network adapters, IP configuration,
    DNS settings, proxy settings, and connectivity status.

.EXAMPLE
    Get-NetworkStatus

.NOTES
    Returns a PSObject with network configuration details.
#>
function Get-NetworkStatus {
    [CmdletBinding()]
    param()
    
    Write-VerboseLog "Collecting network status information"
    
    try {
        # Get network adapters
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true }
        
        # Get IP configuration
        $ipConfig = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        
        # Prepare network adapters information
        $adapterInfo = @()
        foreach ($adapter in $adapters) {
            $config = $ipConfig | Where-Object { $_.InterfaceIndex -eq $adapter.InterfaceIndex }
            
            if ($config) {
                $adapterInfo += [PSCustomObject]@{
                    Name = $adapter.Name
                    Description = $adapter.Description
                    MacAddress = $config.MACAddress
                    Status = $adapter.Status
                    Speed = if ($adapter.Speed) { "$([math]::Round($adapter.Speed / 1000000, 2)) Mbps" } else { "Unknown" }
                    IPAddresses = $config.IPAddress
                    SubnetMasks = $config.IPSubnet
                    DefaultGateway = $config.DefaultIPGateway
                    DNSServers = $config.DNSServerSearchOrder
                    DHCPEnabled = $config.DHCPEnabled
                    DHCPServer = $config.DHCPServer
                }
            }
        }
        
        # Get proxy settings
        $proxyInfo = $null
        try {
            $proxy = [System.Net.WebRequest]::GetSystemWebProxy()
            $proxyInfo = [PSCustomObject]@{
                ProxyAddress = if ($proxy.GetProxy([System.Uri]"http://example.com").OriginalString -ne "http://example.com") { $proxy.GetProxy([System.Uri]"http://example.com").OriginalString } else { "Direct" }
                BypassLocal = $proxy.BypassProxyOnLocal
                BypassList = $proxy.BypassList
            }
        }
        catch {
            Write-Log "Unable to retrieve proxy settings: $($_.Exception.Message)" -Level WARNING
        }
        
        # Test internet connectivity
        $internetConnectivity = $false
        try {
            $testConnectivity = Test-Connection -ComputerName "8.8.8.8" -Count 1 -Quiet -ErrorAction SilentlyContinue
            $internetConnectivity = $testConnectivity
        }
        catch {
            Write-Log "Internet connectivity test failed: $($_.Exception.Message)" -Level WARNING
        }
        
        # Create and return an object with network status information
        $networkInfo = [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            AdapterCount = ($adapterInfo | Measure-Object).Count
            Adapters = $adapterInfo
            ProxySettings = $proxyInfo
            InternetConnectivity = $internetConnectivity
            HostName = [System.Net.Dns]::GetHostName()
            DomainName = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties().DomainName
        }
        
        Write-VerboseLog "Network status information collected successfully"
        return $networkInfo
    }
    catch {
        Write-ErrorLog -Message "Failed to collect network status information" -ErrorRecord $_
        
        # Return a minimal object with error information
        return [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            Error = $_.Exception.Message
            InternetConnectivity = $null
        }
    }
}

<#
.SYNOPSIS
    Lists running processes that might impact SharePoint operations.

.DESCRIPTION
    Retrieves a list of running processes, focusing on those that might
    be relevant to SharePoint operations or security restrictions.

.EXAMPLE
    Get-RunningProcesses

.NOTES
    Returns an array of PSObjects with process details.
#>
function Get-RunningProcesses {
    [CmdletBinding()]
    param()
    
    Write-VerboseLog "Collecting running processes information"
    
    try {
        # Define processes of interest
        $processesOfInterest = @(
            # SharePoint-related
            "OWSTIMER", "w3wp", "SPUCHostService", "SPSearchHostController", "SPAdminV4", "MSSEARCH", "noderunner",
            # Office/Client applications
            "OUTLOOK", "EXCEL", "WINWORD", "POWERPNT", "MSACCESS", "ONENOTE", "MSPUB",
            # Database
            "SQLSERVR", "SQLAGENT", "SQLWRITER",
            # Browsers
            "chrome", "firefox", "iexplore", "edge", "msedge",
            # Security/Antivirus
            "MsMpEng", "KAVFS", "McAfee", "symantec", "TrendMicro", "AVP",
            # System
            "explorer", "lsass", "svchost", "services", "powershell", "cmd", "wininit"
        )
        
        # Get all running processes
        $allProcesses = Get-Process
        
        # Filter processes of interest or with high resource usage
        $filteredProcesses = $allProcesses | Where-Object {
            $_.Name -in $processesOfInterest -or
            $_.CPU -gt 10 -or
            $_.WorkingSet -gt 100MB -or
            $_.Name -like "*SharePoint*" -or
            $_.Name -like "*SP*" -or
            $_.Name -like "*SQL*"
        }
        
        # Sort by CPU usage (descending)
        $sortedProcesses = $filteredProcesses | Sort-Object -Property CPU -Descending
        
        # Create a detailed process list
        $processList = $sortedProcesses | ForEach-Object {
            [PSCustomObject]@{
                Name = $_.Name
                ID = $_.Id
                CPU = [math]::Round($_.CPU, 2)
                MemoryMB = [math]::Round($_.WorkingSet / 1MB, 2)
                HandleCount = $_.HandleCount
                ThreadCount = $_.Threads.Count
                StartTime = if ($_.StartTime) { $_.StartTime } else { $null }
                Path = try { $_.Path } catch { "Access Denied" }
                Company = try { $_.Company } catch { "Unknown" }
                Product = try { $_.Product } catch { "Unknown" }
                Priority = $_.PriorityClass
                IsResponding = $_.Responding
            }
        }
        
        Write-VerboseLog "Running processes information collected successfully (Found $($processList.Count) relevant processes)"
        return $processList
    }
    catch {
        Write-ErrorLog -Message "Failed to collect running processes information" -ErrorRecord $_
        
        # Return a minimal array with error information
        return @([PSCustomObject]@{
            Error = $_.Exception.Message
        })
    }
}

<#
.SYNOPSIS
    Detects installed SharePoint components on the system.

.DESCRIPTION
    Scans the system for SharePoint-related components, including
    client components, server installations, and development tools.

.EXAMPLE
    Get-InstalledSharePointComponents

.NOTES
    Returns a PSObject with detected SharePoint components.
#>
function Get-InstalledSharePointComponents {
    [CmdletBinding()]
    param()
    
    Write-VerboseLog "Detecting installed SharePoint components"
    
    try {
        $spComponents = [PSCustomObject]@{
            SPServerInstalled = $false
            SPClientComponentsInstalled = $false
            SPDesignerInstalled = $false
            PnPComponentsInstalled = $false
            SPManagementShellInstalled = $false
            SPOnlinePSModuleInstalled = $false
            SPDLLsAvailable = $false
            VisualStudioWithSPToolsInstalled = $false
            ComponentDetails = @{}
        }
        
        # Check for SharePoint Server (registry check)
        $spServerKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Office Server\16.0",
            "HKLM:\SOFTWARE\Microsoft\Office Server\15.0"
        )
        
        foreach ($key in $spServerKeys) {
            if (Test-Path $key) {
                $spComponents.SPServerInstalled = $true
                try {
                    $spVersion = Get-ItemProperty -Path $key -Name "BuildVersion" -ErrorAction SilentlyContinue
                    $spComponents.ComponentDetails["SPServerVersion"] = if ($spVersion) { $spVersion.BuildVersion } else { "Unknown" }
                }
                catch {
                    $spComponents.ComponentDetails["SPServerVersion"] = "Access denied or registry error"
                }
                break
            }
        }
        
        # Check for SharePoint PSSnapin
        $spSnapin = Get-PSSnapin -Name "Microsoft.SharePoint.PowerShell" -Registered -ErrorAction SilentlyContinue
        if ($spSnapin) {
            $spComponents.SPManagementShellInstalled = $true
            $spComponents.ComponentDetails["SPSnapinVersion"] = $spSnapin.Version.ToString()
        }
        
        # Check for SharePoint Online PS Module
        $spOnlineModule = Get-Module -Name "Microsoft.Online.SharePoint.PowerShell" -ListAvailable -ErrorAction SilentlyContinue
        if ($spOnlineModule) {
            $spComponents.SPOnlinePSModuleInstalled = $true
            $spComponents.ComponentDetails["SPOnlineModuleVersion"] = $spOnlineModule.Version.ToString()
        }
        
        # Check for PnP PowerShell
        $pnpModules = @(
            "SharePointPnPPowerShellOnline",
            "PnP.PowerShell",
            "SharePointPnPPowerShell2013",
            "SharePointPnPPowerShell2016",
            "SharePointPnPPowerShell2019"
        )
        
        $pnpInstalledModules = @()
        foreach ($module in $pnpModules) {
            $pnpModule = Get-Module -Name $module -ListAvailable -ErrorAction SilentlyContinue
            if ($pnpModule) {
                $pnpInstalledModules += [PSCustomObject]@{
                    Name = $module
                    Version = $pnpModule.Version.ToString()
                }
            }
        }
        
        if ($pnpInstalledModules.Count -gt 0) {
            $spComponents.PnPComponentsInstalled = $true
            $spComponents.ComponentDetails["PnPModules"] = $pnpInstalledModules
        }
        
        # Check for SharePoint Client Components
        $spClientKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Office\16.0\Common\InstallRoot",
            "HKLM:\SOFTWARE\Microsoft\Office\15.0\Common\InstallRoot"
        )
        
        foreach ($key in $spClientKeys) {
            if (Test-Path $key) {
                try {
                    $clientPath = Get-ItemProperty -Path $key -Name "Path" -ErrorAction SilentlyContinue
                    if ($clientPath) {
                        $clientComponentsPath = Join-Path -Path $clientPath.Path -ChildPath "ISAPI"
                        if (Test-Path $clientComponentsPath) {
                            $spComponents.SPClientComponentsInstalled = $true
                            $spComponents.ComponentDetails["SPClientComponentsPath"] = $clientComponentsPath
                            break
                        }
                    }
                }
                catch {
                    Write-VerboseLog "Error checking client components: $($_.Exception.Message)"
                }
            }
        }
        
        # Check for SharePoint DLLs in GAC
        $gacPaths = @(
            "${env:WINDIR}\assembly",
            "${env:WINDIR}\Microsoft.NET\assembly\GAC_MSIL"
        )
        
        foreach ($gacPath in $gacPaths) {
            if (Test-Path $gacPath) {
                try {
                    $spDlls = Get-ChildItem -Path $gacPath -Recurse -Filter "Microsoft.SharePoint*.dll" -ErrorAction SilentlyContinue | Select-Object -First 1
                    if ($spDlls) {
                        $spComponents.SPDLLsAvailable = $true
                        $spComponents.ComponentDetails["SPDLLsPath"] = $gacPath
                        break
                    }
                }
                catch {
                    Write-VerboseLog "Error checking GAC: $($_.Exception.Message)"
                }
            }
        }
        
        # Check for SharePoint Designer
        $spDesignerKeys = @(
            "HKLM:\SOFTWARE\Microsoft\Office\16.0\SharePoint Designer",
            "HKLM:\SOFTWARE\Microsoft\Office\15.0\SharePoint Designer"
        )
        
        foreach ($key in $spDesignerKeys) {
            if (Test-Path $key) {
                $spComponents.SPDesignerInstalled = $true
                $spComponents.ComponentDetails["SPDesignerRegistryKey"] = $key
                break
            }
        }
        
        # Check for Visual Studio with SharePoint Tools
        $vsWithSPTools = Get-ChildItem -Path "HKLM:\SOFTWARE\Microsoft\VisualStudio" -ErrorAction SilentlyContinue | 
            Where-Object { $_.PSChildName -match "^\d+\.\d+$" } | 
            ForEach-Object {
                $vsKey = $_.PSPath
                $spToolsKey = Join-Path -Path $vsKey -ChildPath "InstalledProducts\Microsoft.VisualStudio.SharePoint"
                Test-Path $spToolsKey
            } | Where-Object { $_ -eq $true }
        
        if ($vsWithSPTools) {
            $spComponents.VisualStudioWithSPToolsInstalled = $true
        }
        
        Write-VerboseLog "SharePoint component detection completed"
        return $spComponents
    }
    catch {
        Write-ErrorLog -Message "Failed to detect SharePoint components" -ErrorRecord $_
        
        # Return a minimal object with error information
        return [PSCustomObject]@{
            Error = $_.Exception.Message
            SPServerInstalled = $null
            SPClientComponentsInstalled = $null
        }
    }
}

<#
.SYNOPSIS
    Verifies PowerShell execution policy across different scopes.

.DESCRIPTION
    Checks the current execution policy and attempts to determine if it's
    sufficient for running SharePoint scripts and commands.

.EXAMPLE
    Test-ExecutionPolicy

.NOTES
    Returns a PSObject with execution policy details and recommendations.
#>
function Test-ExecutionPolicy {
    [CmdletBinding()]
    param()
    
    Write-VerboseLog "Testing PowerShell execution policy"
    
    try {
        # Get current execution policy
        $currentPolicy = Get-ExecutionPolicy
        
        # Try to get all policies (might fail in restricted environments)
        $allPolicies = Invoke-WithRetry -ScriptBlock {
            Get-ExecutionPolicy -List
        } -ContinueOnError -MaxRetries 0
        
        if ($allPolicies.Success) {
            $policyScopes = $allPolicies.Result | ForEach-Object {
                [PSCustomObject]@{
                    Scope = $_.Scope
                    ExecutionPolicy = $_.ExecutionPolicy
                }
            }
        }
        else {
            $policyScopes = @([PSCustomObject]@{
                Scope = "CurrentScope"
                ExecutionPolicy = $currentPolicy
            })
        }
        
        # Determine the effective policy
        $effectivePolicy = $currentPolicy
        
        # Evaluate if policy will allow script execution
        $policyLevel = switch ($effectivePolicy) {
            "Restricted" { 0 }
            "AllSigned" { 1 }
            "RemoteSigned" { 2 }
            "Unrestricted" { 3 }
            "Bypass" { 4 }
            default { -1 }
        }
        
        $canRunScripts = $policyLevel -ge 2
        $canRunRemoteScripts = $policyLevel -ge 2
        $canRunUnsignedScripts = $policyLevel -ge 2 -or $policyLevel -eq 0
        
        # Generate recommendations
        $recommendations = @()
        
        if (-not $canRunScripts) {
            $recommendations += "Current execution policy ($effectivePolicy) prevents running scripts. Consider changing to RemoteSigned or higher."
            $recommendations += "Use 'Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass' for temporary script execution."
        }
        
        if ($effectivePolicy -eq "AllSigned") {
            $recommendations += "AllSigned policy requires all scripts to be signed by a trusted publisher."
        }
        
        if ($policyLevel -eq 4) {
            $recommendations += "Bypass policy disables security checks. This is not recommended for production environments."
        }
        
        # Create result object
        $result = [PSCustomObject]@{
            CurrentPolicy = $currentPolicy
            EffectivePolicy = $effectivePolicy
            PolicyScopes = $policyScopes
            CanRunScripts = $canRunScripts
            CanRunRemoteScripts = $canRunRemoteScripts
            CanRunUnsignedScripts = $canRunUnsignedScripts
            Recommendations = $recommendations
        }
        
        Write-VerboseLog "Execution policy test completed (Effective policy: $effectivePolicy, Can run scripts: $canRunScripts)"
        return $result
    }
    catch {
        Write-ErrorLog -Message "Failed to test execution policy" -ErrorRecord $_
        
        # Return a minimal object with error information
        return [PSCustomObject]@{
            Error = $_.Exception.Message
            CurrentPolicy = Get-ExecutionPolicy -ErrorAction SilentlyContinue
            CanRunScripts = $null
        }
    }
}

<#
.SYNOPSIS
    Creates a comprehensive system diagnostics report.

.DESCRIPTION
    Combines data from multiple system information functions to create
    a comprehensive report about the execution environment.

.PARAMETER OutputPath
    The file path where the report should be saved. If not specified,
    no file will be created.

.PARAMETER Format
    The format of the output report (Text or JSON).

.EXAMPLE
    Export-SystemReport -OutputPath "C:\Temp\SystemReport.json" -Format JSON

.NOTES
    Returns a PSObject with the complete system report data.
#>
function Export-SystemReport {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$OutputPath,
        
        [Parameter()]
        [ValidateSet("Text", "JSON")]
        [string]$Format = "JSON"
    )
    
    Write-VerboseLog "Generating system diagnostics report"
    
    try {
        # Collect all system information
        $reportData = [PSCustomObject]@{
            Timestamp = Get-Date
            OSInfo = Get-OSInformation
            PowerShellEnv = Get-PowerShellEnvironment
            UserPermissions = Get-UserPermissionLevel
            NetworkStatus = Get-NetworkStatus
            RunningProcesses = Get-RunningProcesses
            SharePointComponents = Get-InstalledSharePointComponents
            ExecutionPolicy = Test-ExecutionPolicy
        }
        
        # Export to file if path is specified
        if ($OutputPath) {
            $parentFolder = Split-Path -Path $OutputPath -Parent
            
            if ($parentFolder -and -not (Test-Path -Path $parentFolder)) {
                New-Item -ItemType Directory -Path $parentFolder -Force | Out-Null
            }
            
            if ($Format -eq "JSON") {
                $reportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
            }
            else {
                # Create a text report
                $textReport = @"
==========================================
SYSTEM DIAGNOSTICS REPORT
Generated: $($reportData.Timestamp)
==========================================

OPERATING SYSTEM INFORMATION
------------------------------------------
Computer Name: $($reportData.OSInfo.ComputerName)
OS: $($reportData.OSInfo.OSName)
Version: $($reportData.OSInfo.OSVersion) (Build $($reportData.OSInfo.OSBuildNumber))
Architecture: $($reportData.OSInfo.OSArchitecture)
System: $($reportData.OSInfo.SystemManufacturer) $($reportData.OSInfo.SystemModel)
Memory: $($reportData.OSInfo.TotalPhysicalMemoryGB) GB
Virtual Machine: $($reportData.OSInfo.IsVirtualMachine)

POWERSHELL ENVIRONMENT
------------------------------------------
Version: $($reportData.PowerShellEnv.PSVersion)
Edition: $($reportData.PowerShellEnv.PSEdition)
Execution Policy: $($reportData.PowerShellEnv.CurrentExecutionPolicy)
64-bit Process: $($reportData.PowerShellEnv.Is64BitProcess)
Installed Modules: $($reportData.PowerShellEnv.InstalledModulesCount)
Loaded Modules: $($reportData.PowerShellEnv.LoadedModulesCount)

SharePoint Modules:
$(if ($reportData.PowerShellEnv.SharePointModules) {
    ($reportData.PowerShellEnv.SharePointModules | ForEach-Object { "- $($_.Name) (v$($_.Version))" }) -join "`n"
} else {
    "None found"
})

USER PERMISSIONS
------------------------------------------
User: $($reportData.UserPermissions.UserName)
Administrator: $($reportData.UserPermissions.IsAdministrator)
Elevated: $($reportData.UserPermissions.IsElevated)
Groups: $($reportData.UserPermissions.GroupCount)

NETWORK STATUS
------------------------------------------
Internet Connectivity: $($reportData.NetworkStatus.InternetConnectivity)
Hostname: $($reportData.NetworkStatus.HostName)
Domain: $($reportData.NetworkStatus.DomainName)
Network Adapters: $($reportData.NetworkStatus.AdapterCount)

$(if ($reportData.NetworkStatus.Adapters) {
    ($reportData.NetworkStatus.Adapters | ForEach-Object {
        "- $($_.Name): $($_.Status) ($($_.Speed))`n  IP: $($_.IPAddresses -join ', ')`n  MAC: $($_.MacAddress)"
    }) -join "`n`n"
})

SHAREPOINT COMPONENTS
------------------------------------------
SP Server Installed: $($reportData.SharePointComponents.SPServerInstalled)
SP Client Components: $($reportData.SharePointComponents.SPClientComponentsInstalled)
SP Management Shell: $($reportData.SharePointComponents.SPManagementShellInstalled)
SP Online PS Module: $($reportData.SharePointComponents.SPOnlinePSModuleInstalled)
PnP Components: $($reportData.SharePointComponents.PnPComponentsInstalled)
SP DLLs Available: $($reportData.SharePointComponents.SPDLLsAvailable)

EXECUTION POLICY
------------------------------------------
Current Policy: $($reportData.ExecutionPolicy.CurrentPolicy)
Can Run Scripts: $($reportData.ExecutionPolicy.CanRunScripts)
Can Run Unsigned Scripts: $($reportData.ExecutionPolicy.CanRunUnsignedScripts)

Recommendations:
$(if ($reportData.ExecutionPolicy.Recommendations) {
    ($reportData.ExecutionPolicy.Recommendations | ForEach-Object { "- $_" }) -join "`n"
} else {
    "No recommendations"
})

RUNNING PROCESSES (TOP 10 BY CPU)
------------------------------------------
$(if ($reportData.RunningProcesses) {
    ($reportData.RunningProcesses | Select-Object -First 10 | ForEach-Object {
        "- $($_.Name) (PID: $($_.ID)): CPU: $($_.CPU)%, Memory: $($_.MemoryMB) MB"
    }) -join "`n"
} else {
    "No process information available"
})

==========================================
End of Report
==========================================
"@
                
                $textReport | Out-File -FilePath $OutputPath -Encoding UTF8
            }
            
            Write-Log "System diagnostics report saved to $OutputPath" -Level INFO
        }
        
        return $reportData
    }
    catch {
        Write-ErrorLog -Message "Failed to generate system diagnostics report" -ErrorRecord $_
        
        # Return a minimal object with error information
        return [PSCustomObject]@{
            Timestamp = Get-Date
            Error = $_.Exception.Message
        }
    }
}

# Export the public functions
Export-ModuleMember -Function Get-OSInformation, Get-PowerShellEnvironment, Get-UserPermissionLevel, Get-NetworkStatus, Get-RunningProcesses, Get-InstalledSharePointComponents, Test-ExecutionPolicy, Export-SystemReport 