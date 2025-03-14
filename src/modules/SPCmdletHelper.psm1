#Region Module Header
<#
.SYNOPSIS
PowerShell module for SharePoint Management Shell operations in the SharePoint Restricted Environment Data Collector.

.DESCRIPTION
This module provides functions for retrieving SharePoint data using SharePoint Management Shell cmdlets.
It's designed to work as the first method of data retrieval, with fallback to CSOM or REST API if these cmdlets are unavailable.

.NOTES
File: SPCmdletHelper.psm1
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

<#
.SYNOPSIS
    Checks if SharePoint Management Shell cmdlets are available.

.DESCRIPTION
    Tests if essential SharePoint Management Shell cmdlets are available in the current PowerShell session.
    This helps determine if this method of data retrieval can be used.

.PARAMETER RequiredCmdlets
    Array of cmdlet names to check for availability.

.EXAMPLE
    $result = Test-SPCmdletsAvailability
    if ($result.Available) {
        Write-Host "SharePoint cmdlets are available: $($result.AvailableCmdlets -join ', ')"
    }

.NOTES
    Returns a PSObject with availability information and details about available/missing cmdlets.
#>
function Test-SPCmdletsAvailability {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string[]]$RequiredCmdlets = @(
            "Get-SPSite", 
            "Get-SPWeb", 
            "Get-SPList", 
            "Get-SPUser", 
            "Get-SPGroup"
        )
    )
    
    Write-VerboseLog "Testing SharePoint Management Shell cmdlets availability"
    
    $result = [PSCustomObject]@{
        Available = $false
        AvailableCmdlets = @()
        MissingCmdlets = @()
        SharePointSnapInLoaded = $false
        SharePointModuleLoaded = $false
        SharePointVersion = $null
        IsOnline = $false
        IsOnPremises = $false
    }
    
    # Check if SharePoint snap-in is loaded
    $spSnapIn = Get-PSSnapin -Name "Microsoft.SharePoint.PowerShell" -ErrorAction SilentlyContinue
    if ($spSnapIn) {
        $result.SharePointSnapInLoaded = $true
        $result.IsOnPremises = $true
        Write-VerboseLog "SharePoint Management Shell snap-in is loaded"
    }
    
    # Check if SharePoint Online module is loaded
    $spModule = Get-Module -Name "Microsoft.Online.SharePoint.PowerShell" -ErrorAction SilentlyContinue
    if ($spModule) {
        $result.SharePointModuleLoaded = $true
        $result.IsOnline = $true
        $result.SharePointVersion = $spModule.Version.ToString()
        Write-VerboseLog "SharePoint Online PowerShell module is loaded (Version: $($result.SharePointVersion))"
    }
    
    # Check each required cmdlet
    foreach ($cmdlet in $RequiredCmdlets) {
        $cmdletResult = Test-CommandAvailability -CommandName $cmdlet
        
        if ($cmdletResult.IsAvailable) {
            $result.AvailableCmdlets += $cmdlet
            Write-VerboseLog "Cmdlet '$cmdlet' is available"
        } else {
            $result.MissingCmdlets += $cmdlet
            Write-VerboseLog "Cmdlet '$cmdlet' is not available"
        }
    }
    
    # Determine overall availability
    if ($result.AvailableCmdlets.Count -gt 0) {
        $result.Available = $true
        Write-Log "SharePoint Management Shell contains $($result.AvailableCmdlets.Count) available cmdlets" -Level INFO
    } else {
        Write-Log "No SharePoint Management Shell cmdlets are available" -Level WARNING
    }
    
    return $result
}

<#
.SYNOPSIS
    Loads SharePoint snap-in or module.

.DESCRIPTION
    Attempts to load the SharePoint Management Shell snap-in or module
    to enable the use of SharePoint cmdlets.

.PARAMETER Online
    If specified, attempts to load the SharePoint Online PowerShell module.

.PARAMETER ModuleName
    The name of the SharePoint module to load (default is based on the Online parameter).

.EXAMPLE
    Connect-SPCmdlets -Online

.NOTES
    Returns a boolean indicating success or failure.
#>
function Connect-SPCmdlets {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$Online,
        
        [Parameter()]
        [string]$ModuleName = ""
    )
    
    # Determine which module to load based on parameters
    if (-not $ModuleName) {
        if ($Online) {
            $ModuleName = "Microsoft.Online.SharePoint.PowerShell"
            Write-VerboseLog "Attempting to load SharePoint Online PowerShell module"
        } else {
            $snapInName = "Microsoft.SharePoint.PowerShell"
            Write-VerboseLog "Attempting to load SharePoint Management Shell snap-in"
        }
    }
    
    try {
        $result = $false
        
        if ($Online -or $ModuleName -ne "Microsoft.SharePoint.PowerShell") {
            # Try loading the module
            if (-not (Get-Module -Name $ModuleName)) {
                if (Get-Module -Name $ModuleName -ListAvailable) {
                    Import-Module -Name $ModuleName -ErrorAction Stop
                    $module = Get-Module -Name $ModuleName
                    Write-Log "Successfully loaded SharePoint module: $ModuleName (Version: $($module.Version))" -Level INFO
                    $result = $true
                } else {
                    Write-Log "SharePoint module $ModuleName is not available on this system" -Level WARNING
                }
            } else {
                Write-VerboseLog "SharePoint module $ModuleName is already loaded"
                $result = $true
            }
        } else {
            # Try loading the snap-in
            if (-not (Get-PSSnapin -Name $snapInName -ErrorAction SilentlyContinue)) {
                Add-PSSnapin -Name $snapInName -ErrorAction Stop
                Write-Log "Successfully loaded SharePoint snap-in: $snapInName" -Level INFO
                $result = $true
            } else {
                Write-VerboseLog "SharePoint snap-in $snapInName is already loaded"
                $result = $true
            }
        }
        
        return $result
    } catch {
        Write-ErrorLog -Message "Failed to load SharePoint commands" -ErrorRecord $_
        return $false
    }
}

<#
.SYNOPSIS
    Retrieves all site collections.

.DESCRIPTION
    Uses SharePoint Management Shell cmdlets to retrieve all available site collections.

.PARAMETER WebApplication
    The URL of the SharePoint web application (for on-premises).

.PARAMETER Tenant
    The SharePoint Online tenant URL (for SharePoint Online).

.PARAMETER Limit
    Maximum number of site collections to retrieve.

.EXAMPLE
    $sites = Get-SPSiteCollections -WebApplication "https://sharepoint.contoso.com"

.NOTES
    Returns an array of site collection objects or $null if retrieval fails.
#>
function Get-SPSiteCollections {
    [CmdletBinding()]
    param (
        [Parameter(ParameterSetName="OnPremises")]
        [string]$WebApplication = "",
        
        [Parameter(ParameterSetName="Online")]
        [string]$Tenant = "",
        
        [Parameter()]
        [int]$Limit = 0
    )
    
    Write-VerboseLog "Retrieving SharePoint site collections"
    
    # Determine if we're using online or on-premises cmdlets
    $isOnline = $PSCmdlet.ParameterSetName -eq "Online"
    
    try {
        $siteCollections = @()
        
        # Using Invoke-WithRetry for automatic retry logic
        if ($isOnline) {
            if (-not $Tenant) {
                Write-Log "No tenant URL specified, attempting to retrieve all sites" -Level WARNING
            }
            
            $scriptBlock = {
                if ($Tenant) {
                    Get-SPOSite -Limit $Limit
                } else {
                    Get-SPOSite
                }
            }
            
            $result = Invoke-WithRetry -ScriptBlock $scriptBlock -MaxRetries 3 -ContinueOnError
            
            if ($result.Success) {
                $siteCollections = $result.Result
                Write-Log "Successfully retrieved $($siteCollections.Count) SharePoint Online site collections" -Level INFO
            } else {
                Write-Log "Failed to retrieve SharePoint Online site collections: $($result.Error.Message)" -Level ERROR
            }
        } else {
            $scriptBlock = {
                if ($WebApplication) {
                    Get-SPSite -WebApplication $WebApplication -Limit $Limit
                } else {
                    Get-SPSite -Limit $Limit
                }
            }
            
            $result = Invoke-WithRetry -ScriptBlock $scriptBlock -MaxRetries 3 -ContinueOnError
            
            if ($result.Success) {
                $siteCollections = $result.Result
                Write-Log "Successfully retrieved $($siteCollections.Count) SharePoint site collections" -Level INFO
            } else {
                Write-Log "Failed to retrieve SharePoint site collections: $($result.Error.Message)" -Level ERROR
            }
        }
        
        return $siteCollections
    } catch {
        $errorDetail = Handle-Exception -Exception $_.Exception -Operation "Retrieving site collections" -Category "SharePoint" -ContinueOperation
        Write-Log "Failed to retrieve site collections: $($errorDetail.Message)" -Level ERROR
        return $null
    }
}

<#
.SYNOPSIS
    Gets detailed web properties.

.DESCRIPTION
    Retrieves detailed information about a SharePoint web (site).

.PARAMETER SiteUrl
    The URL of the SharePoint site.

.PARAMETER IncludeSubsites
    If specified, also retrieves all subsites recursively.

.PARAMETER MaxDepth
    The maximum depth for retrieving subsites.

.EXAMPLE
    $webDetails = Get-SPWebDetails -SiteUrl "https://sharepoint.contoso.com/sites/teamsite"

.NOTES
    Returns a hashtable with web details or $null if retrieval fails.
#>
function Get-SPWebDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteUrl,
        
        [Parameter()]
        [switch]$IncludeSubsites,
        
        [Parameter()]
        [int]$MaxDepth = 2
    )
    
    Write-VerboseLog "Retrieving web details for $SiteUrl"
    
    try {
        $webDetails = @{}
        
        # Using Invoke-WithRetry for automatic retry logic
        $scriptBlock = {
            $site = Get-SPSite -Identity $SiteUrl -ErrorAction Stop
            $web = $site.OpenWeb()
            
            # Get basic web information
            $webInfo = [PSCustomObject]@{
                Title = $web.Title
                Description = $web.Description
                Url = $web.Url
                ID = $web.ID
                WebTemplateId = $web.WebTemplateId
                Created = $web.Created
                LastItemModifiedDate = $web.LastItemModifiedDate
                Author = $web.Author
                HasUniqueRoleAssignments = $web.HasUniqueRoleAssignments
                RequestAccessEmail = $web.RequestAccessEmail
                RequestAccessEnabled = $web.RequestAccessEnabled
                UIVersion = $web.UIVersion
                WebTemplate = $web.WebTemplate
                Configuration = $web.Configuration
                Language = $web.Language
                IsMultilingual = $web.IsMultilingual
                SupportedLanguages = $web.SupportedLanguages
                RegionalSettings = @{
                    LocaleId = $web.RegionalSettings.LocaleId
                    TimeZone = $web.RegionalSettings.TimeZone.Description
                    Time24 = $web.RegionalSettings.Time24
                    CalendarType = $web.RegionalSettings.CalendarType
                    WorkDays = $web.RegionalSettings.WorkDays
                    WorkDayStartHour = $web.RegionalSettings.WorkDayStartHour
                    WorkDayEndHour = $web.RegionalSettings.WorkDayEndHour
                    FirstDayOfWeek = $web.RegionalSettings.FirstDayOfWeek
                }
            }
            
            # Get subwebs if requested
            $subsites = @()
            if ($IncludeSubsites) {
                $subwebs = $web.Webs
                foreach ($subweb in $subwebs) {
                    $subsiteInfo = [PSCustomObject]@{
                        Title = $subweb.Title
                        Description = $subweb.Description
                        Url = $subweb.Url
                        ID = $subweb.ID
                        Created = $subweb.Created
                        WebTemplate = $subweb.WebTemplate
                    }
                    $subsites += $subsiteInfo
                    $subweb.Dispose()
                }
            }
            
            # Clean up
            $web.Dispose()
            $site.Dispose()
            
            return @{
                WebInfo = $webInfo
                Subsites = $subsites
            }
        }
        
        $result = Invoke-WithRetry -ScriptBlock $scriptBlock -MaxRetries 3 -ContinueOnError
        
        if ($result.Success) {
            $webDetails = $result.Result
            Write-Log "Successfully retrieved web details for $SiteUrl" -Level INFO
            
            # If we need to get subsites recursively and MaxDepth > 1, process each subsite
            if ($IncludeSubsites -and $MaxDepth -gt 1 -and $webDetails.Subsites.Count -gt 0) {
                $allSubsites = @()
                foreach ($subsite in $webDetails.Subsites) {
                    $allSubsites += $subsite
                    
                    if ($MaxDepth -gt 1) {
                        $subWebDetails = Get-SPWebDetails -SiteUrl $subsite.Url -IncludeSubsites -MaxDepth ($MaxDepth - 1)
                        if ($subWebDetails -and $subWebDetails.Subsites) {
                            $allSubsites += $subWebDetails.Subsites
                        }
                    }
                }
                $webDetails.Subsites = $allSubsites
            }
        } else {
            Write-Log "Failed to retrieve web details for $SiteUrl: $($result.Error.Message)" -Level ERROR
        }
        
        return $webDetails
    } catch {
        $errorDetail = Handle-Exception -Exception $_.Exception -Operation "Retrieving web details" -Category "SharePoint" -ContinueOperation
        Write-Log "Failed to retrieve web details for $SiteUrl: $($errorDetail.Message)" -Level ERROR
        return $null
    }
}

<#
.SYNOPSIS
    Lists document libraries.

.DESCRIPTION
    Retrieves information about document libraries in a SharePoint site.

.PARAMETER SiteUrl
    The URL of the SharePoint site.

.PARAMETER IncludeDetails
    If specified, includes detailed information about each document library.

.PARAMETER IncludeHidden
    If specified, includes hidden document libraries.

.EXAMPLE
    $docLibs = Get-SPDocumentLibraries -SiteUrl "https://sharepoint.contoso.com/sites/teamsite"

.NOTES
    Returns an array of document library objects or $null if retrieval fails.
#>
function Get-SPDocumentLibraries {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteUrl,
        
        [Parameter()]
        [switch]$IncludeDetails,
        
        [Parameter()]
        [switch]$IncludeHidden
    )
    
    Write-VerboseLog "Retrieving document libraries for $SiteUrl"
    
    try {
        # Using Invoke-WithRetry for automatic retry logic
        $scriptBlock = {
            $site = Get-SPSite -Identity $SiteUrl -ErrorAction Stop
            $web = $site.OpenWeb()
            
            $docLibs = @()
            
            # Get all lists
            $lists = $web.Lists
            
            # Filter for document libraries (BaseType = 1)
            foreach ($list in $lists) {
                if ($list.BaseType -eq 1) {
                    # Skip hidden libraries if not requested
                    if (-not $list.Hidden -or $IncludeHidden) {
                        $docLib = [PSCustomObject]@{
                            Title = $list.Title
                            ID = $list.ID
                            Description = $list.Description
                            ItemCount = $list.ItemCount
                            Created = $list.Created
                            LastItemModifiedDate = $list.LastItemModifiedDate
                            Hidden = $list.Hidden
                            EnableVersioning = $list.EnableVersioning
                            EnableMinorVersions = $list.EnableMinorVersions
                            RootFolder = $list.RootFolder.ServerRelativeUrl
                        }
                        
                        # Add detailed information if requested
                        if ($IncludeDetails) {
                            $folders = @()
                            $rootFolder = $list.RootFolder
                            
                            # Get top-level folders
                            foreach ($folder in $rootFolder.SubFolders) {
                                $folderInfo = [PSCustomObject]@{
                                    Name = $folder.Name
                                    ServerRelativeUrl = $folder.ServerRelativeUrl
                                    ItemCount = $folder.ItemCount
                                    Created = $folder.Created
                                    TimeLastModified = $folder.TimeLastModified
                                }
                                $folders += $folderInfo
                            }
                            
                            # Add advanced properties
                            $docLib | Add-Member -MemberType NoteProperty -Name "Folders" -Value $folders
                            $docLib | Add-Member -MemberType NoteProperty -Name "ContentTypes" -Value ($list.ContentTypes | Select-Object Name, ID, Description, Group)
                            $docLib | Add-Member -MemberType NoteProperty -Name "DefaultViewUrl" -Value $list.DefaultViewUrl
                            $docLib | Add-Member -MemberType NoteProperty -Name "Views" -Value ($list.Views | Select-Object Title, ID, DefaultView, Url)
                        }
                        
                        $docLibs += $docLib
                    }
                }
            }
            
            # Clean up
            $web.Dispose()
            $site.Dispose()
            
            return $docLibs
        }
        
        $result = Invoke-WithRetry -ScriptBlock $scriptBlock -MaxRetries 3 -ContinueOnError
        
        if ($result.Success) {
            $documentLibraries = $result.Result
            Write-Log "Successfully retrieved $($documentLibraries.Count) document libraries from $SiteUrl" -Level INFO
            return $documentLibraries
        } else {
            Write-Log "Failed to retrieve document libraries from $SiteUrl: $($result.Error.Message)" -Level ERROR
            return $null
        }
    } catch {
        $errorDetail = Handle-Exception -Exception $_.Exception -Operation "Retrieving document libraries" -Category "SharePoint" -ContinueOperation
        Write-Log "Failed to retrieve document libraries from $SiteUrl: $($errorDetail.Message)" -Level ERROR
        return $null
    }
}

<#
.SYNOPSIS
    Gets lists and views.

.DESCRIPTION
    Retrieves information about lists and their views in a SharePoint site.

.PARAMETER SiteUrl
    The URL of the SharePoint site.

.PARAMETER IncludeViews
    If specified, includes detailed view information for each list.

.PARAMETER IncludeItems
    If specified, includes top-level items for each list (use with caution for large lists).

.PARAMETER IncludeHidden
    If specified, includes hidden lists.

.EXAMPLE
    $lists = Get-SPListsAndViews -SiteUrl "https://sharepoint.contoso.com/sites/teamsite" -IncludeViews

.NOTES
    Returns an array of list objects or $null if retrieval fails.
#>
function Get-SPListsAndViews {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteUrl,
        
        [Parameter()]
        [switch]$IncludeViews,
        
        [Parameter()]
        [switch]$IncludeItems,
        
        [Parameter()]
        [switch]$IncludeHidden,
        
        [Parameter()]
        [int]$MaxItemsPerList = 100
    )
    
    Write-VerboseLog "Retrieving lists and views for $SiteUrl"
    
    try {
        # Using Invoke-WithRetry for automatic retry logic
        $scriptBlock = {
            $site = Get-SPSite -Identity $SiteUrl -ErrorAction Stop
            $web = $site.OpenWeb()
            
            $lists = @()
            
            foreach ($list in $web.Lists) {
                # Skip hidden lists if not requested
                if (-not $list.Hidden -or $IncludeHidden) {
                    $listInfo = [PSCustomObject]@{
                        Title = $list.Title
                        ID = $list.ID
                        Description = $list.Description
                        ItemCount = $list.ItemCount
                        Created = $list.Created
                        LastItemModifiedDate = $list.LastItemModifiedDate
                        Hidden = $list.Hidden
                        BaseType = $list.BaseType
                        BaseTemplate = $list.BaseTemplate
                        DefaultViewUrl = $list.DefaultViewUrl
                        ContentTypesEnabled = $list.ContentTypesEnabled
                        IsCatalog = $list.IsCatalog
                        EnableAttachments = $list.EnableAttachments
                        EnableFolderCreation = $list.EnableFolderCreation
                        Fields = $list.Fields | Select-Object -First 10 | ForEach-Object {
                            [PSCustomObject]@{
                                Title = $_.Title
                                InternalName = $_.InternalName
                                Type = $_.Type
                                Required = $_.Required
                                Hidden = $_.Hidden
                            }
                        }
                    }
                    
                    # Include views if requested
                    if ($IncludeViews) {
                        $views = @()
                        foreach ($view in $list.Views) {
                            $viewInfo = [PSCustomObject]@{
                                Title = $view.Title
                                ID = $view.ID
                                DefaultView = $view.DefaultView
                                Url = $view.Url
                                ViewType = $view.ViewType
                                RowLimit = $view.RowLimit
                                Paged = $view.Paged
                                Hidden = $view.Hidden
                                ViewFields = $view.ViewFields.ToStringCollection()
                            }
                            $views += $viewInfo
                        }
                        $listInfo | Add-Member -MemberType NoteProperty -Name "Views" -Value $views
                    }
                    
                    # Include top items if requested (with caution for large lists)
                    if ($IncludeItems -and $list.ItemCount -gt 0) {
                        $items = @()
                        $query = New-Object Microsoft.SharePoint.SPQuery
                        $query.RowLimit = [Math]::Min($MaxItemsPerList, 100)
                        
                        $listItems = $list.GetItems($query)
                        foreach ($item in $listItems) {
                            $itemInfo = [PSCustomObject]@{
                                ID = $item.ID
                                Title = $item["Title"]
                                Created = $item["Created"]
                                Modified = $item["Modified"]
                                CreatedBy = $item["Author"].LookupValue
                                ModifiedBy = $item["Editor"].LookupValue
                            }
                            $items += $itemInfo
                        }
                        $listInfo | Add-Member -MemberType NoteProperty -Name "Items" -Value $items
                    }
                    
                    $lists += $listInfo
                }
            }
            
            # Clean up
            $web.Dispose()
            $site.Dispose()
            
            return $lists
        }
        
        $result = Invoke-WithRetry -ScriptBlock $scriptBlock -MaxRetries 3 -ContinueOnError
        
        if ($result.Success) {
            $listsAndViews = $result.Result
            Write-Log "Successfully retrieved $($listsAndViews.Count) lists from $SiteUrl" -Level INFO
            return $listsAndViews
        } else {
            Write-Log "Failed to retrieve lists from $SiteUrl: $($result.Error.Message)" -Level ERROR
            return $null
        }
    } catch {
        $errorDetail = Handle-Exception -Exception $_.Exception -Operation "Retrieving lists and views" -Category "SharePoint" -ContinueOperation
        Write-Log "Failed to retrieve lists from $SiteUrl: $($errorDetail.Message)" -Level ERROR
        return $null
    }
}

<#
.SYNOPSIS
    Retrieves user permissions.

.DESCRIPTION
    Gets detailed information about users and their permissions in a SharePoint site.

.PARAMETER SiteUrl
    The URL of the SharePoint site.

.PARAMETER IncludeGroups
    If specified, includes detailed information about SharePoint groups.

.EXAMPLE
    $permissions = Get-SPUserPermissions -SiteUrl "https://sharepoint.contoso.com/sites/teamsite" -IncludeGroups

.NOTES
    Returns a hashtable with user and permission information or $null if retrieval fails.
#>
function Get-SPUserPermissions {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteUrl,
        
        [Parameter()]
        [switch]$IncludeGroups
    )
    
    Write-VerboseLog "Retrieving user permissions for $SiteUrl"
    
    try {
        # Using Invoke-WithRetry for automatic retry logic
        $scriptBlock = {
            $site = Get-SPSite -Identity $SiteUrl -ErrorAction Stop
            $web = $site.OpenWeb()
            
            $permissionInfo = @{
                Users = @()
                Groups = @()
                RoleDefinitions = @()
                SiteHasUniquePermissions = $site.HasUniqueRoleAssignments
                WebHasUniquePermissions = $web.HasUniqueRoleAssignments
            }
            
            # Get role definitions (permission levels)
            foreach ($roleDef in $web.RoleDefinitions) {
                $roleInfo = [PSCustomObject]@{
                    Name = $roleDef.Name
                    ID = $roleDef.Id
                    Description = $roleDef.Description
                    Hidden = $roleDef.Hidden
                    Type = $roleDef.Type
                    BasePermissions = $roleDef.BasePermissions.ToString()
                }
                $permissionInfo.RoleDefinitions += $roleInfo
            }
            
            # Get SharePoint groups
            foreach ($group in $web.SiteGroups) {
                $groupInfo = [PSCustomObject]@{
                    Name = $group.Name
                    ID = $group.ID
                    Description = $group.Description
                    OwnerTitle = $group.Owner.Title
                    UserCount = $group.Users.Count
                    Users = @()
                }
                
                # Include group members if requested
                if ($IncludeGroups) {
                    foreach ($user in $group.Users) {
                        $userInfo = [PSCustomObject]@{
                            LoginName = $user.LoginName
                            Name = $user.Name
                            Email = $user.Email
                            ID = $user.ID
                            IsSiteAdmin = $user.IsSiteAdmin
                        }
                        $groupInfo.Users += $userInfo
                    }
                }
                
                $permissionInfo.Groups += $groupInfo
            }
            
            # Get all users
            foreach ($user in $web.SiteUsers) {
                $userInfo = [PSCustomObject]@{
                    LoginName = $user.LoginName
                    Name = $user.Name
                    Email = $user.Email
                    ID = $user.ID
                    IsSiteAdmin = $user.IsSiteAdmin
                    Groups = ($user.Groups | ForEach-Object { $_.Name })
                    Roles = @()
                }
                
                # Get user's direct permissions
                if ($web.HasUniqueRoleAssignments) {
                    foreach ($assignment in $web.RoleAssignments) {
                        if ($assignment.Member.ID -eq $user.ID) {
                            foreach ($roleDefinitionBinding in $assignment.RoleDefinitionBindings) {
                                $userInfo.Roles += $roleDefinitionBinding.Name
                            }
                        }
                    }
                }
                
                $permissionInfo.Users += $userInfo
            }
            
            # Clean up
            $web.Dispose()
            $site.Dispose()
            
            return $permissionInfo
        }
        
        $result = Invoke-WithRetry -ScriptBlock $scriptBlock -MaxRetries 3 -ContinueOnError
        
        if ($result.Success) {
            $permissions = $result.Result
            Write-Log "Successfully retrieved permissions from $SiteUrl (Users: $($permissions.Users.Count), Groups: $($permissions.Groups.Count))" -Level INFO
            return $permissions
        } else {
            Write-Log "Failed to retrieve permissions from $SiteUrl: $($result.Error.Message)" -Level ERROR
            return $null
        }
    } catch {
        $errorDetail = Handle-Exception -Exception $_.Exception -Operation "Retrieving user permissions" -Category "SharePoint" -ContinueOperation
        Write-Log "Failed to retrieve permissions from $SiteUrl: $($errorDetail.Message)" -Level ERROR
        return $null
    }
}

<#
.SYNOPSIS
    Exports all collected data.

.DESCRIPTION
    Consolidates and exports all data collected using SharePoint cmdlets to a structured format.

.PARAMETER Data
    A hashtable containing all collected SharePoint data.

.PARAMETER OutputPath
    The path where the output file should be saved.

.PARAMETER Format
    The format of the output file (JSON or Text).

.EXAMPLE
    Export-SPCmdletData -Data $collectedData -OutputPath "C:\Output\SPCmdletData.json" -Format "JSON"

.NOTES
    Returns the path to the exported file or $null if export fails.
#>
function Export-SPCmdletData {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Data,
        
        [Parameter()]
        [string]$OutputPath = "",
        
        [Parameter()]
        [ValidateSet("JSON", "Text")]
        [string]$Format = "JSON"
    )
    
    if (-not $OutputPath) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $fileName = "SPCmdletData_$timestamp.$($Format.ToLower())"
        $scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
        $outputDir = Join-Path -Path $scriptRoot -ChildPath "output"
        
        if (-not (Test-Path -Path $outputDir)) {
            New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
        }
        
        $OutputPath = Join-Path -Path $outputDir -ChildPath $fileName
    }
    
    Write-VerboseLog "Exporting SharePoint data to $OutputPath in $Format format"
    
    try {
        # Add metadata to the output
        $outputData = @{
            Metadata = @{
                ExportTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Method = "SharePoint Management Shell"
                Version = "0.1.0"
            }
            Data = $Data
        }
        
        # Export based on format
        if ($Format -eq "JSON") {
            $outputData | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding utf8
        } else {
            # For text format, create a more human-readable output
            $textOutput = @"
SharePoint Data Export (SharePoint Management Shell)
Generated: $($outputData.Metadata.ExportTimestamp)
Method: $($outputData.Metadata.Method)
Version: $($outputData.Metadata.Version)

"@
            
            # Add site collections
            if ($Data.ContainsKey("SiteCollections") -and $Data.SiteCollections) {
                $textOutput += "SITE COLLECTIONS`n"
                $textOutput += "-" * 80 + "`n"
                foreach ($site in $Data.SiteCollections) {
                    $textOutput += "Title: $($site.Title)`n"
                    $textOutput += "URL: $($site.Url)`n"
                    $textOutput += "ID: $($site.ID)`n"
                    $textOutput += "Created: $($site.Created)`n"
                    $textOutput += "`n"
                }
            }
            
            # Add web details
            if ($Data.ContainsKey("WebDetails") -and $Data.WebDetails) {
                $textOutput += "WEB DETAILS`n"
                $textOutput += "-" * 80 + "`n"
                foreach ($webUrl in $Data.WebDetails.Keys) {
                    $web = $Data.WebDetails[$webUrl].WebInfo
                    $textOutput += "Title: $($web.Title)`n"
                    $textOutput += "URL: $($web.Url)`n"
                    $textOutput += "Description: $($web.Description)`n"
                    $textOutput += "Created: $($web.Created)`n"
                    $textOutput += "Last Modified: $($web.LastItemModifiedDate)`n"
                    
                    if ($Data.WebDetails[$webUrl].Subsites.Count -gt 0) {
                        $textOutput += "  Subsites:`n"
                        foreach ($subsite in $Data.WebDetails[$webUrl].Subsites) {
                            $textOutput += "  - $($subsite.Title) ($($subsite.Url))`n"
                        }
                    }
                    $textOutput += "`n"
                }
            }
            
            # Add lists and document libraries
            if ($Data.ContainsKey("Lists") -and $Data.Lists) {
                $textOutput += "LISTS AND LIBRARIES`n"
                $textOutput += "-" * 80 + "`n"
                foreach ($webUrl in $Data.Lists.Keys) {
                    $textOutput += "Web: $webUrl`n"
                    foreach ($list in $Data.Lists[$webUrl]) {
                        $textOutput += "  - $($list.Title) (Items: $($list.ItemCount), Type: $($list.BaseType))`n"
                        if ($list.PSObject.Properties.Name -contains "Views") {
                            $textOutput += "    Views: $($list.Views.Count)`n"
                        }
                    }
                    $textOutput += "`n"
                }
            }
            
            # Add users and permissions
            if ($Data.ContainsKey("Permissions") -and $Data.Permissions) {
                $textOutput += "USERS AND PERMISSIONS`n"
                $textOutput += "-" * 80 + "`n"
                foreach ($webUrl in $Data.Permissions.Keys) {
                    $textOutput += "Web: $webUrl`n"
                    $textOutput += "  Users: $($Data.Permissions[$webUrl].Users.Count)`n"
                    $textOutput += "  Groups: $($Data.Permissions[$webUrl].Groups.Count)`n"
                    $textOutput += "  Role Definitions: $($Data.Permissions[$webUrl].RoleDefinitions.Count)`n"
                    $textOutput += "`n"
                }
            }
            
            $textOutput | Out-File -FilePath $OutputPath -Encoding utf8
        }
        
        Write-Log "Successfully exported SharePoint data to $OutputPath" -Level INFO
        return $OutputPath
    } catch {
        Write-ErrorLog -Message "Failed to export SharePoint data" -ErrorRecord $_
        return $null
    }
}

# Export the public functions
Export-ModuleMember -Function Test-SPCmdletsAvailability, Connect-SPCmdlets, Get-SPSiteCollections, Get-SPWebDetails, Get-SPDocumentLibraries, Get-SPListsAndViews, Get-SPUserPermissions, Export-SPCmdletData 