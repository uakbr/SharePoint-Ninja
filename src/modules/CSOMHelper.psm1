#Region Module Header
<#
.SYNOPSIS
PowerShell module for SharePoint CSOM (Client-Side Object Model) operations in the SharePoint Restricted Environment Data Collector.

.DESCRIPTION
This module provides functions for connecting to and retrieving data from SharePoint using
the Client-Side Object Model (CSOM). It offers an alternative to SharePoint Management Shell
cmdlets in environments where those are not available.

.NOTES
File: CSOMHelper.psm1
Author: SharePoint Restricted Environment Data Collector Team
Version: 0.1.0
#>
#EndRegion Module Header

# Import required modules
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "Logger.psm1"
if (Test-Path -Path $modulePath) {
    Import-Module -Name $modulePath -Force
}

$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "Failsafe.psm1"
if (Test-Path -Path $modulePath) {
    Import-Module -Name $modulePath -Force
}

# Define global variables
$script:CSOMAssembliesLoaded = $false
$script:CSOMClientContext = $null
$script:CSOMRetryCount = 3
$script:CSOMRetryDelay = 2

<#
.SYNOPSIS
    Checks if CSOM assemblies are available and loads them if possible.

.DESCRIPTION
    Attempts to load the required Microsoft.SharePoint.Client assemblies
    to enable CSOM-based operations. Searches for the assemblies in common
    installation locations and the current directory.

.PARAMETER AssemblyPath
    Optional. The directory path where the CSOM assemblies are located.

.EXAMPLE
    Initialize-CSOM -AssemblyPath "C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\16\ISAPI"

.NOTES
    Returns $true if assemblies are loaded successfully, $false otherwise.
#>
function Initialize-CSOM {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$AssemblyPath
    )
    
    Write-VerboseLog "Initializing CSOM assemblies"
    
    if ($script:CSOMAssembliesLoaded) {
        Write-VerboseLog "CSOM assemblies already loaded"
        return $true
    }
    
    try {
        # Define required assemblies
        $requiredAssemblies = @(
            "Microsoft.SharePoint.Client.dll",
            "Microsoft.SharePoint.Client.Runtime.dll"
        )
        
        # Define potential paths where CSOM assemblies might be located
        $potentialPaths = @(
            # If a specific path is provided, check there first
            if ($AssemblyPath) { $AssemblyPath }
            
            # Common CSOM installation paths for SharePoint Online PnP
            "$env:ProgramFiles\SharePointOnlineManagementShell\Microsoft.SharePoint.Client.dll",
            "$env:ProgramFiles\Common Files\microsoft shared\Web Server Extensions\16\ISAPI",
            "$env:ProgramFiles\Common Files\microsoft shared\Web Server Extensions\15\ISAPI",
            
            # Office 365 CLI installation paths
            "$env:USERPROFILE\.o365\libs",
            
            # Current directory and subdirectories
            ".",
            ".\lib",
            ".\libs",
            ".\bin"
        )
        
        $assemblyFound = $false
        
        # Try each path until we find the assemblies
        foreach ($path in $potentialPaths) {
            if (Test-Path -Path $path) {
                Write-VerboseLog "Testing assembly path: $path"
                
                $fullAssemblyPath = ""
                
                # Check if the path points directly to the DLL or to a directory
                if ($path.EndsWith(".dll")) {
                    $fullAssemblyPath = $path
                    
                    if (Test-Path -Path $fullAssemblyPath) {
                        try {
                            Add-Type -Path $fullAssemblyPath -ErrorAction Stop
                            $assemblyFound = $true
                            Write-Log "Loaded CSOM assembly: $fullAssemblyPath" -Level INFO
                            break
                        }
                        catch {
                            Write-VerboseLog "Failed to load assembly from $fullAssemblyPath`: $_"
                            continue
                        }
                    }
                }
                else {
                    $foundAllAssemblies = $true
                    
                    foreach ($assembly in $requiredAssemblies) {
                        $fullAssemblyPath = Join-Path -Path $path -ChildPath $assembly
                        
                        if (-not (Test-Path -Path $fullAssemblyPath)) {
                            $foundAllAssemblies = $false
                            break
                        }
                    }
                    
                    if ($foundAllAssemblies) {
                        try {
                            foreach ($assembly in $requiredAssemblies) {
                                $fullAssemblyPath = Join-Path -Path $path -ChildPath $assembly
                                Add-Type -Path $fullAssemblyPath -ErrorAction Stop
                                Write-Log "Loaded CSOM assembly: $fullAssemblyPath" -Level INFO
                            }
                            $assemblyFound = $true
                            break
                        }
                        catch {
                            Write-VerboseLog "Failed to load assemblies from $path`: $_"
                            continue
                        }
                    }
                }
            }
        }
        
        if (-not $assemblyFound) {
            # Try to load from GAC as a last resort
            try {
                Add-Type -AssemblyName "Microsoft.SharePoint.Client, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" -ErrorAction Stop
                Add-Type -AssemblyName "Microsoft.SharePoint.Client.Runtime, Version=16.0.0.0, Culture=neutral, PublicKeyToken=71e9bce111e9429c" -ErrorAction Stop
                $assemblyFound = $true
                Write-Log "Loaded CSOM assemblies from GAC" -Level INFO
            }
            catch {
                Write-Log "Failed to load CSOM assemblies from GAC: $_" -Level WARNING
            }
        }
        
        $script:CSOMAssembliesLoaded = $assemblyFound
        
        if (-not $assemblyFound) {
            Write-Log "CSOM assemblies could not be loaded from any location" -Level ERROR
            return $false
        }
        
        return $true
    }
    catch {
        Write-ErrorLog -Message "Failed to initialize CSOM assemblies" -ErrorRecord $_
        return $false
    }
}

<#
.SYNOPSIS
    Connects to a SharePoint site using CSOM.

.DESCRIPTION
    Establishes a connection to a SharePoint site using the Client-Side Object Model.
    Supports multiple authentication methods including SharePoint Online, Windows Auth,
    and App-Only authentication.

.PARAMETER SiteUrl
    The URL of the SharePoint site to connect to.

.PARAMETER Credentials
    PSCredential object containing the username and password.

.PARAMETER UseCurrentUser
    If specified, uses the current user's credentials.

.PARAMETER ClientId
    Client ID for app-only or add-in authentication.

.PARAMETER ClientSecret
    Client Secret for app-only or add-in authentication.

.PARAMETER AuthenticationMethod
    The authentication method to use. Valid options are "Windows", "Modern", and "AppOnly".

.EXAMPLE
    Connect-CSOM -SiteUrl "https://contoso.sharepoint.com/sites/intranet" -Credentials $cred

.NOTES
    Returns the ClientContext object if successful, $null otherwise.
#>
function Connect-CSOM {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteUrl,
        
        [Parameter(ParameterSetName = "Credentials")]
        [System.Management.Automation.PSCredential]$Credentials,
        
        [Parameter(ParameterSetName = "CurrentUser")]
        [switch]$UseCurrentUser,
        
        [Parameter(ParameterSetName = "AppOnly")]
        [string]$ClientId,
        
        [Parameter(ParameterSetName = "AppOnly")]
        [string]$ClientSecret,
        
        [Parameter()]
        [ValidateSet("Windows", "Modern", "AppOnly")]
        [string]$AuthenticationMethod = "Modern"
    )
    
    Write-VerboseLog "Connecting to SharePoint site $SiteUrl using CSOM"
    
    # Check if CSOM assemblies are loaded
    if (-not $script:CSOMAssembliesLoaded) {
        $initialized = Initialize-CSOM
        if (-not $initialized) {
            Write-Log "Cannot connect to SharePoint using CSOM because assemblies could not be loaded" -Level ERROR
            return $null
        }
    }
    
    try {
        # Create ClientContext
        $clientContext = New-Object Microsoft.SharePoint.Client.ClientContext($SiteUrl)
        
        # Configure request timeout (60 seconds)
        $clientContext.RequestTimeout = 60000
        
        # Set up authentication based on method
        switch ($AuthenticationMethod) {
            "Windows" {
                if ($Credentials) {
                    $networkCredential = $Credentials.GetNetworkCredential()
                    $clientContext.Credentials = New-Object System.Net.NetworkCredential(
                        $networkCredential.UserName,
                        $networkCredential.Password,
                        $networkCredential.Domain
                    )
                    Write-VerboseLog "Using provided Windows credentials for authentication"
                }
                elseif ($UseCurrentUser) {
                    $clientContext.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                    Write-VerboseLog "Using current user's Windows credentials for authentication"
                }
                else {
                    Write-Log "No credentials provided for Windows authentication" -Level ERROR
                    return $null
                }
            }
            "Modern" {
                # For SharePoint Online
                if ($SiteUrl -like "*sharepoint.com*") {
                    if ($Credentials) {
                        # Check if we have the right assembly loaded
                        try {
                            # For SharePoint Online, we need the SharePointOnlineCredentials
                            $onlineCredentials = New-Object Microsoft.SharePoint.Client.SharePointOnlineCredentials(
                                $Credentials.UserName,
                                $Credentials.Password
                            )
                            $clientContext.Credentials = $onlineCredentials
                            Write-VerboseLog "Using SharePoint Online credentials for authentication"
                        }
                        catch {
                            Write-Log "Failed to create SharePointOnlineCredentials: $_" -Level ERROR
                            return $null
                        }
                    }
                    elseif ($UseCurrentUser) {
                        # For current user in SharePoint Online, we need to use other methods
                        # such as token-based auth, which is more complex
                        Write-Log "UseCurrentUser not implemented for SharePoint Online with CSOM" -Level ERROR
                        return $null
                    }
                    else {
                        Write-Log "No credentials provided for SharePoint Online authentication" -Level ERROR
                        return $null
                    }
                }
                else {
                    # For on-premises with modern auth, revert to Windows auth for now
                    if ($Credentials) {
                        $networkCredential = $Credentials.GetNetworkCredential()
                        $clientContext.Credentials = New-Object System.Net.NetworkCredential(
                            $networkCredential.UserName,
                            $networkCredential.Password,
                            $networkCredential.Domain
                        )
                        Write-VerboseLog "Using provided Windows credentials for authentication"
                    }
                    elseif ($UseCurrentUser) {
                        $clientContext.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
                        Write-VerboseLog "Using current user's Windows credentials for authentication"
                    }
                    else {
                        Write-Log "No credentials provided for authentication" -Level ERROR
                        return $null
                    }
                }
            }
            "AppOnly" {
                if ($ClientId -and $ClientSecret) {
                    # App-Only authentication is more complex and requires
                    # additional assembly references not included in basic CSOM
                    Write-Log "App-Only authentication is not yet implemented in this version" -Level ERROR
                    return $null
                }
                else {
                    Write-Log "ClientId and ClientSecret required for App-Only authentication" -Level ERROR
                    return $null
                }
            }
        }
        
        # Test the connection by retrieving the site
        $clientContext.Load($clientContext.Web)
        
        # Execute with retry logic
        $success = Invoke-WithRetry -ScriptBlock {
            $clientContext.ExecuteQuery()
            return $true
        } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay -ContinueOnError
        
        if (-not $success.Success) {
            Write-Log "Failed to connect to SharePoint site $SiteUrl: $($success.Error.Message)" -Level ERROR
            return $null
        }
        
        Write-Log "Successfully connected to SharePoint site $SiteUrl using CSOM" -Level INFO
        
        # Store the client context
        $script:CSOMClientContext = $clientContext
        
        return $clientContext
    }
    catch {
        Write-ErrorLog -Message "Failed to connect to SharePoint site $SiteUrl using CSOM" -ErrorRecord $_
        return $null
    }
}

<#
.SYNOPSIS
    Gets detailed information about a SharePoint site using CSOM.

.DESCRIPTION
    Retrieves comprehensive information about a SharePoint site including
    site properties, lists, content types, features, and more using CSOM.

.PARAMETER ClientContext
    The CSOM ClientContext object. If not provided, uses the context from Connect-CSOM.

.PARAMETER IncludeSubsites
    If specified, also retrieves information about subsites.

.PARAMETER IncludeListDetails
    If specified, includes detailed information about lists and libraries.

.EXAMPLE
    $siteData = Get-CSOMSiteData -IncludeSubsites

.NOTES
    Returns a custom object with site information.
#>
function Get-CSOMSiteData {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Microsoft.SharePoint.Client.ClientContext]$ClientContext,
        
        [Parameter()]
        [switch]$IncludeSubsites,
        
        [Parameter()]
        [switch]$IncludeListDetails
    )
    
    Write-VerboseLog "Retrieving SharePoint site data using CSOM"
    
    try {
        # Use provided context or the stored one
        if (-not $ClientContext) {
            $ClientContext = $script:CSOMClientContext
        }
        
        if (-not $ClientContext) {
            Write-Log "No CSOM ClientContext available. Use Connect-CSOM first." -Level ERROR
            return $null
        }
        
        # Get the current site and web
        $site = $ClientContext.Site
        $web = $ClientContext.Web
        
        # Load the site and web with their properties
        $ClientContext.Load($site)
        $ClientContext.Load($web)
        $ClientContext.Load($web.Webs)
        
        # Execute the query to retrieve basic site properties
        Invoke-WithRetry -ScriptBlock {
            $ClientContext.ExecuteQuery()
        } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
        
        # Create a custom object to store the site data
        $siteData = [PSCustomObject]@{
            SiteUrl = $web.Url
            Title = $web.Title
            Description = $web.Description
            Created = $web.Created
            LastModified = $web.LastItemModifiedDate
            WebTemplate = $web.WebTemplate
            Language = $web.Language
            IsRootWeb = $web.IsRootWeb
            AlternateCssUrl = $web.AlternateCssUrl
            CustomMasterUrl = $web.CustomMasterUrl
            MasterUrl = $web.MasterUrl
            SiteLogoUrl = $web.SiteLogoUrl
            RequestAccessEmail = $web.RequestAccessEmail
            HasUniquePermissions = $web.HasUniqueRoleAssignments
            Lists = @()
            ContentTypes = @()
            Features = @()
            SubSites = @()
            SiteUsers = @()
            SiteGroups = @()
            TimeZone = $null
            RegionalSettings = $null
            RetrievedUsingMethod = "CSOM"
        }
        
        # Load regional settings
        $ClientContext.Load($web.RegionalSettings)
        Invoke-WithRetry -ScriptBlock {
            $ClientContext.ExecuteQuery()
        } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
        
        $siteData.TimeZone = [PSCustomObject]@{
            Description = $web.RegionalSettings.TimeZone.Description
            Id = $web.RegionalSettings.TimeZone.Id
        }
        
        $siteData.RegionalSettings = [PSCustomObject]@{
            WorkDayStartHour = $web.RegionalSettings.WorkDayStartHour
            WorkDayEndHour = $web.RegionalSettings.WorkDayEndHour
            FirstDayOfWeek = $web.RegionalSettings.FirstDayOfWeek
            Locale = $web.RegionalSettings.LocaleId
        }
        
        # Get lists if requested
        if ($IncludeListDetails) {
            Write-VerboseLog "Retrieving lists and libraries"
            
            $lists = $web.Lists
            $ClientContext.Load($lists)
            Invoke-WithRetry -ScriptBlock {
                $ClientContext.ExecuteQuery()
            } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
            
            foreach ($list in $lists) {
                # Skip hidden lists unless configured to include them
                if ($list.Hidden -and -not $IncludeHiddenLists) {
                    continue
                }
                
                $listData = [PSCustomObject]@{
                    Title = $list.Title
                    Description = $list.Description
                    Id = $list.Id
                    ItemCount = $list.ItemCount
                    BaseTemplate = $list.BaseTemplate
                    Created = $list.Created
                    LastModified = $list.LastItemModifiedDate
                    DefaultViewUrl = $list.DefaultViewUrl
                    IsDocumentLibrary = ($list.BaseTemplate -eq 101)
                    Hidden = $list.Hidden
                    EnableVersioning = $list.EnableVersioning
                    MajorVersionLimit = $list.MajorVersionLimit
                    HasUniquePermissions = $list.HasUniqueRoleAssignments
                }
                
                $siteData.Lists += $listData
            }
        }
        
        # Get content types
        $contentTypes = $web.ContentTypes
        $ClientContext.Load($contentTypes)
        Invoke-WithRetry -ScriptBlock {
            $ClientContext.ExecuteQuery()
        } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
        
        foreach ($ct in $contentTypes) {
            $contentTypeData = [PSCustomObject]@{
                Name = $ct.Name
                Id = $ct.StringId
                Description = $ct.Description
                Group = $ct.Group
                Hidden = $ct.Hidden
            }
            
            $siteData.ContentTypes += $contentTypeData
        }
        
        # Get features
        $features = $web.Features
        $ClientContext.Load($features)
        Invoke-WithRetry -ScriptBlock {
            $ClientContext.ExecuteQuery()
        } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
        
        foreach ($feature in $features) {
            $featureData = [PSCustomObject]@{
                Id = $feature.DefinitionId
            }
            
            $siteData.Features += $featureData
        }
        
        # Get site users and groups
        $users = $web.SiteUsers
        $ClientContext.Load($users)
        $groups = $web.SiteGroups
        $ClientContext.Load($groups)
        Invoke-WithRetry -ScriptBlock {
            $ClientContext.ExecuteQuery()
        } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
        
        foreach ($user in $users) {
            $userData = [PSCustomObject]@{
                Id = $user.Id
                Title = $user.Title
                LoginName = $user.LoginName
                Email = $user.Email
                IsSiteAdmin = $user.IsSiteAdmin
            }
            
            $siteData.SiteUsers += $userData
        }
        
        foreach ($group in $groups) {
            $groupData = [PSCustomObject]@{
                Id = $group.Id
                Title = $group.Title
                Description = $group.Description
                Owner = if ($group.Owner) { $group.Owner.Title } else { $null }
            }
            
            $siteData.SiteGroups += $groupData
        }
        
        # Get subsites if requested
        if ($IncludeSubsites -and $web.Webs.Count -gt 0) {
            Write-VerboseLog "Retrieving subsite information for $($web.Webs.Count) subsites"
            
            foreach ($subWeb in $web.Webs) {
                # Creating a new context for the subsite
                $subContext = New-Object Microsoft.SharePoint.Client.ClientContext($subWeb.Url)
                $subContext.Credentials = $ClientContext.Credentials
                
                # Get subsite data recursively
                $subSiteData = Get-CSOMSiteData -ClientContext $subContext -IncludeListDetails:$IncludeListDetails
                $siteData.SubSites += $subSiteData
                
                # Dispose of the subcontext when done
                $subContext.Dispose()
            }
        }
        
        return $siteData
    }
    catch {
        Write-ErrorLog -Message "Failed to retrieve SharePoint site data using CSOM" -ErrorRecord $_
        return $null
    }
}

<#
.SYNOPSIS
    Retrieves list items from a SharePoint list using CSOM.

.DESCRIPTION
    Gets items from a specified SharePoint list with optional filtering,
    ordering, and limiting the number of items returned.

.PARAMETER ClientContext
    The CSOM ClientContext object. If not provided, uses the context from Connect-CSOM.

.PARAMETER ListTitle
    The title of the list to retrieve items from.

.PARAMETER ListId
    The GUID of the list to retrieve items from.

.PARAMETER Query
    A CAML query string to filter items.

.PARAMETER Fields
    An array of field names to retrieve.

.PARAMETER OrderBy
    The field to order results by.

.PARAMETER Ascending
    If specified, sorts results in ascending order.

.PARAMETER Limit
    Maximum number of items to retrieve.

.EXAMPLE
    $items = Get-CSOMListItems -ListTitle "Documents" -Limit 100

.NOTES
    Returns an array of list items.
#>
function Get-CSOMListItems {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Microsoft.SharePoint.Client.ClientContext]$ClientContext,
        
        [Parameter(Mandatory = $true, ParameterSetName = "ByTitle")]
        [string]$ListTitle,
        
        [Parameter(Mandatory = $true, ParameterSetName = "ById")]
        [guid]$ListId,
        
        [Parameter()]
        [string]$Query,
        
        [Parameter()]
        [string[]]$Fields,
        
        [Parameter()]
        [string]$OrderBy,
        
        [Parameter()]
        [switch]$Ascending,
        
        [Parameter()]
        [int]$Limit = 5000
    )
    
    Write-VerboseLog "Retrieving items from SharePoint list using CSOM"
    
    try {
        # Use provided context or the stored one
        if (-not $ClientContext) {
            $ClientContext = $script:CSOMClientContext
        }
        
        if (-not $ClientContext) {
            Write-Log "No CSOM ClientContext available. Use Connect-CSOM first." -Level ERROR
            return $null
        }
        
        # Get the list based on title or ID
        $list = $null
        if ($PSCmdlet.ParameterSetName -eq "ByTitle") {
            $list = $ClientContext.Web.Lists.GetByTitle($ListTitle)
        }
        else {
            $list = $ClientContext.Web.Lists.GetById($ListId)
        }
        
        # Load the list
        $ClientContext.Load($list)
        Invoke-WithRetry -ScriptBlock {
            $ClientContext.ExecuteQuery()
        } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
        
        # Create a CAML query if needed
        $camlQuery = New-Object Microsoft.SharePoint.Client.CamlQuery
        
        if ($Query) {
            $camlQuery.ViewXml = $Query
        }
        else {
            # Build a basic query
            $queryXml = "<View>"
            
            # Add row limit
            if ($Limit -gt 0) {
                $queryXml += "<RowLimit>$Limit</RowLimit>"
            }
            
            # Add fields to retrieve
            if ($Fields -and $Fields.Count -gt 0) {
                $queryXml += "<ViewFields>"
                foreach ($field in $Fields) {
                    $queryXml += "<FieldRef Name='$field' />"
                }
                $queryXml += "</ViewFields>"
            }
            
            # Add order by clause
            if ($OrderBy) {
                $sortDirection = if ($Ascending) { "Ascending" } else { "Descending" }
                $queryXml += "<OrderBy><FieldRef Name='$OrderBy' Ascending='$sortDirection' /></OrderBy>"
            }
            
            $queryXml += "</View>"
            $camlQuery.ViewXml = $queryXml
        }
        
        # Execute the query to get items
        $listItems = $list.GetItems($camlQuery)
        $ClientContext.Load($listItems)
        Invoke-WithRetry -ScriptBlock {
            $ClientContext.ExecuteQuery()
        } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
        
        # Convert results to a PowerShell array
        $items = @()
        foreach ($item in $listItems) {
            $itemProperties = @{}
            
            # Get field values
            foreach ($fieldName in $item.FieldValues.Keys) {
                $itemProperties[$fieldName] = $item[$fieldName]
            }
            
            $items += [PSCustomObject]$itemProperties
        }
        
        Write-VerboseLog "Retrieved $($items.Count) items from list"
        return $items
    }
    catch {
        Write-ErrorLog -Message "Failed to retrieve list items using CSOM" -ErrorRecord $_
        return $null
    }
}

<#
.SYNOPSIS
    Gets permission details for a SharePoint site using CSOM.

.DESCRIPTION
    Retrieves role definitions and permission assignments for a SharePoint site.
    Can also get permissions for specific users.

.PARAMETER ClientContext
    The CSOM ClientContext object. If not provided, uses the context from Connect-CSOM.

.PARAMETER UserLoginName
    Optional. The login name of a specific user to get permissions for.

.PARAMETER IncludeInheritedPermissions
    If specified, also returns permissions inherited from parent sites.

.EXAMPLE
    $permissions = Get-CSOMPermissionData -UserLoginName "i:0#.f|membership|user@contoso.com"

.NOTES
    Returns an object with role definitions and permission assignments.
#>
function Get-CSOMPermissionData {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Microsoft.SharePoint.Client.ClientContext]$ClientContext,
        
        [Parameter()]
        [string]$UserLoginName,
        
        [Parameter()]
        [switch]$IncludeInheritedPermissions
    )
    
    Write-VerboseLog "Retrieving SharePoint permission data using CSOM"
    
    try {
        # Use provided context or the stored one
        if (-not $ClientContext) {
            $ClientContext = $script:CSOMClientContext
        }
        
        if (-not $ClientContext) {
            Write-Log "No CSOM ClientContext available. Use Connect-CSOM first." -Level ERROR
            return $null
        }
        
        $web = $ClientContext.Web
        
        # Create result object
        $permissionData = [PSCustomObject]@{
            SiteUrl = $web.Url
            HasUniquePermissions = $false
            RoleDefinitions = @()
            RoleAssignments = @()
            UserPermissions = @()
        }
        
        # Load role definitions and role assignments
        $roleDefinitions = $web.RoleDefinitions
        $roleAssignments = $web.RoleAssignments
        
        $ClientContext.Load($web)
        $ClientContext.Load($roleDefinitions)
        $ClientContext.Load($roleAssignments)
        Invoke-WithRetry -ScriptBlock {
            $ClientContext.ExecuteQuery()
        } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
        
        $permissionData.HasUniquePermissions = $web.HasUniqueRoleAssignments
        
        # Process role definitions
        foreach ($roleDef in $roleDefinitions) {
            $roleDefData = [PSCustomObject]@{
                Id = $roleDef.Id
                Name = $roleDef.Name
                Description = $roleDef.Description
                BasePermissions = $roleDef.BasePermissions.ToString()
            }
            
            $permissionData.RoleDefinitions += $roleDefData
        }
        
        # Process role assignments
        foreach ($roleAssignment in $roleAssignments) {
            $ClientContext.Load($roleAssignment.Member)
            $ClientContext.Load($roleAssignment.RoleDefinitionBindings)
            Invoke-WithRetry -ScriptBlock {
                $ClientContext.ExecuteQuery()
            } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
            
            $roles = @()
            foreach ($roleDef in $roleAssignment.RoleDefinitionBindings) {
                $roles += $roleDef.Name
            }
            
            $roleAssignmentData = [PSCustomObject]@{
                PrincipalId = $roleAssignment.PrincipalId
                PrincipalType = $roleAssignment.Member.PrincipalType
                PrincipalName = $roleAssignment.Member.Title
                LoginName = if ($roleAssignment.Member.LoginName) { $roleAssignment.Member.LoginName } else { $null }
                Roles = $roles
            }
            
            $permissionData.RoleAssignments += $roleAssignmentData
        }
        
        # If a specific user is requested, get their permissions
        if ($UserLoginName) {
            Write-VerboseLog "Getting permissions for user: $UserLoginName"
            
            try {
                $user = $web.EnsureUser($UserLoginName)
                $ClientContext.Load($user)
                Invoke-WithRetry -ScriptBlock {
                    $ClientContext.ExecuteQuery()
                } -MaxRetries $script:CSOMRetryCount -RetryDelaySeconds $script:CSOMRetryDelay | Out-Null
                
                $userPermissions = @()
                
                # Get direct permissions
                $userRoleAssignments = $roleAssignments | Where-Object { 
                    $_.Member.LoginName -eq $user.LoginName -or 
                    ($_.Member.PrincipalType -eq "SharePointGroup" -and 
                     $permissionData.RoleAssignments.Where({ $_.PrincipalType -eq "User" -and $_.LoginName -eq $user.LoginName -and $_.PrincipalName -eq $_.PrincipalName }).Count -gt 0)
                }
                
                foreach ($roleAssignment in $userRoleAssignments) {
                    foreach ($roleDef in $roleAssignment.RoleDefinitionBindings) {
                        $userPermissions += [PSCustomObject]@{
                            SiteUrl = $web.Url
                            RoleName = $roleDef.Name
                            RoleDefinitionId = $roleDef.Id
                            DirectlyAssigned = $true
                            AssignedThrough = $roleAssignment.Member.Title
                            AssignedThroughType = $roleAssignment.Member.PrincipalType
                        }
                    }
                }
                
                $permissionData.UserPermissions = $userPermissions
            }
            catch {
                Write-Log "Failed to get permissions for user $UserLoginName`: $_" -Level WARNING
            }
        }
        
        return $permissionData
    }
    catch {
        Write-ErrorLog -Message "Failed to retrieve permission data using CSOM" -ErrorRecord $_
        return $null
    }
}

<#
.SYNOPSIS
    Exports all collected CSOM data to a file.

.DESCRIPTION
    Saves all the data collected using CSOM methods to a structured JSON file
    for later analysis.

.PARAMETER SiteData
    The site data collected using Get-CSOMSiteData.

.PARAMETER PermissionData
    The permission data collected using Get-CSOMPermissionData.

.PARAMETER ListData
    The list data collected from various lists.

.PARAMETER OutputPath
    The directory where the output file should be saved.

.PARAMETER FileNamePrefix
    A prefix for the output file name.

.EXAMPLE
    Export-CSOMData -SiteData $siteInfo -PermissionData $permissions -OutputPath "./output"

.NOTES
    Creates a JSON file with a timestamp in the filename.
#>
function Export-CSOMData {
    [CmdletBinding()]
    param (
        [Parameter()]
        [PSObject]$SiteData,
        
        [Parameter()]
        [PSObject]$PermissionData,
        
        [Parameter()]
        [hashtable]$ListData,
        
        [Parameter()]
        [string]$OutputPath = "./output",
        
        [Parameter()]
        [string]$FileNamePrefix = "CSOMDataExport"
    )
    
    Write-VerboseLog "Exporting CSOM data to file"
    
    try {
        # Create the output directory if it doesn't exist
        if (-not (Test-Path -Path $OutputPath)) {
            New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        }
        
        # Create a timestamp for the filename
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $fileName = "$FileNamePrefix`_$timestamp.json"
        $filePath = Join-Path -Path $OutputPath -ChildPath $fileName
        
        # Combine all data into one object
        $exportData = [PSCustomObject]@{
            Timestamp = Get-Date
            Method = "CSOM"
            SiteData = $SiteData
            PermissionData = $PermissionData
            ListData = $ListData
        }
        
        # Convert to JSON and save to file
        $jsonData = ConvertTo-Json -InputObject $exportData -Depth 10
        $jsonData | Out-File -FilePath $filePath -Encoding utf8
        
        Write-Log "CSOM data exported to $filePath" -Level INFO
        return $filePath
    }
    catch {
        Write-ErrorLog -Message "Failed to export CSOM data to file" -ErrorRecord $_
        return $null
    }
}

<#
.SYNOPSIS
    Disposes of the CSOM ClientContext to free resources.

.DESCRIPTION
    Cleanly disposes of the CSOM ClientContext object to release resources
    and close connections.

.PARAMETER ClientContext
    The CSOM ClientContext object to dispose. If not provided, uses the context from Connect-CSOM.

.EXAMPLE
    Disconnect-CSOM

.NOTES
    Should be called at the end of CSOM operations to clean up resources.
#>
function Disconnect-CSOM {
    [CmdletBinding()]
    param (
        [Parameter()]
        [Microsoft.SharePoint.Client.ClientContext]$ClientContext
    )
    
    Write-VerboseLog "Disposing CSOM client context"
    
    try {
        # Use provided context or the stored one
        if (-not $ClientContext) {
            $ClientContext = $script:CSOMClientContext
        }
        
        if ($ClientContext) {
            $ClientContext.Dispose()
            $script:CSOMClientContext = $null
            Write-Log "CSOM client context disposed" -Level INFO
        }
        else {
            Write-VerboseLog "No CSOM client context to dispose"
        }
    }
    catch {
        Write-ErrorLog -Message "Failed to dispose CSOM client context" -ErrorRecord $_
    }
}

# Export functions
Export-ModuleMember -Function Initialize-CSOM, Connect-CSOM, Get-CSOMSiteData, Get-CSOMListItems, Get-CSOMPermissionData, Export-CSOMData, Disconnect-CSOM 