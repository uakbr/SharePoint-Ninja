#Region Module Header
<#
.SYNOPSIS
PowerShell module for implementing fault tolerance in the SharePoint Restricted Environment Data Collector.

.DESCRIPTION
This module provides functions for retry logic, failover mechanisms, and error handling
to ensure reliable execution in restricted environments.

.NOTES
File: Failsafe.psm1
Author: SharePoint Restricted Environment Data Collector Team
Version: 0.1.0
#>
#EndRegion Module Header

# Import required modules
# This assumes Logger.psm1 is in the same directory
$modulePath = Join-Path -Path $PSScriptRoot -ChildPath "Logger.psm1"
if (Test-Path -Path $modulePath) {
    Import-Module -Name $modulePath -Force
}

<#
.SYNOPSIS
    Executes a script block with automatic retries on failure.

.DESCRIPTION
    Attempts to execute a script block up to the specified number of retries.
    Implements exponential backoff between retry attempts.

.PARAMETER ScriptBlock
    The script block to execute.

.PARAMETER MaxRetries
    The maximum number of retry attempts (default: 3).

.PARAMETER RetryDelaySeconds
    The initial delay between retries in seconds (default: 2).

.PARAMETER BackoffMultiplier
    The multiplier for exponential backoff (default: 2).

.PARAMETER ExceptionMessage
    A custom message to use when all retries have failed.

.PARAMETER RetryableErrorCodes
    An array of error codes that should trigger a retry.

.PARAMETER ContinueOnError
    If specified, the function will return a failed result instead of throwing.

.EXAMPLE
    Invoke-WithRetry -ScriptBlock { Invoke-RestMethod -Uri "https://site.sharepoint.com/_api/web" }

.NOTES
    Uses exponential backoff to space out retries.
#>
function Invoke-WithRetry {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [scriptblock]$ScriptBlock,
        
        [Parameter()]
        [int]$MaxRetries = 3,
        
        [Parameter()]
        [int]$RetryDelaySeconds = 2,
        
        [Parameter()]
        [double]$BackoffMultiplier = 2,
        
        [Parameter()]
        [string]$ExceptionMessage = "Operation failed after all retry attempts",
        
        [Parameter()]
        [array]$RetryableErrorCodes = @(),
        
        [Parameter()]
        [switch]$ContinueOnError
    )
    
    $retryCount = 0
    $currentDelay = $RetryDelaySeconds
    $success = $false
    $result = $null
    $finalError = $null
    
    # Log the start of the retry operation
    Write-VerboseLog "Starting operation with retry (max attempts: $MaxRetries)"
    
    while (-not $success -and $retryCount -le $MaxRetries) {
        try {
            if ($retryCount -gt 0) {
                Write-Log "Retry attempt $retryCount of $MaxRetries (delay: ${currentDelay}s)" -Level INFO
                Start-Sleep -Seconds $currentDelay
                $currentDelay = $currentDelay * $BackoffMultiplier
            }
            
            # Execute the script block
            $result = & $ScriptBlock
            $success = $true
            
            if ($retryCount -gt 0) {
                Write-Log "Operation succeeded after $retryCount retries" -Level INFO
            }
        }
        catch {
            $finalError = $_
            $errorCode = $_.Exception.HResult
            
            # Determine if this error is retryable
            $shouldRetry = $retryCount -lt $MaxRetries
            
            if ($RetryableErrorCodes.Count -gt 0) {
                $shouldRetry = $shouldRetry -and ($RetryableErrorCodes -contains $errorCode)
            }
            
            if ($shouldRetry) {
                Write-ErrorLog -Message "Operation failed (attempt $($retryCount + 1) of $($MaxRetries + 1))" -ErrorRecord $_
                $retryCount++
            }
            else {
                # We've hit max retries or encountered a non-retryable error
                Write-ErrorLog -Message "Operation failed permanently after $retryCount retries" -ErrorRecord $_
                break
            }
        }
    }
    
    if (-not $success) {
        if ($ContinueOnError) {
            # Return an object with error information but don't throw
            return [PSCustomObject]@{
                Success = $false
                Error = $finalError
                RetryCount = $retryCount
                Message = $ExceptionMessage
            }
        }
        else {
            $detailedMessage = "$ExceptionMessage (Failed after $retryCount retries)"
            Write-ErrorLog -Message $detailedMessage -ErrorRecord $finalError
            throw $detailedMessage
        }
    }
    
    if ($ContinueOnError) {
        # Return a success object with the result
        return [PSCustomObject]@{
            Success = $true
            Result = $result
            RetryCount = $retryCount
        }
    }
    else {
        # Just return the result directly
        return $result
    }
}

<#
.SYNOPSIS
    Tests network connectivity to a SharePoint site.

.DESCRIPTION
    Checks if a SharePoint site is accessible by attempting to connect to it.
    Uses multiple methods for testing connectivity.

.PARAMETER SiteUrl
    The URL of the SharePoint site to test.

.PARAMETER Timeout
    The timeout in seconds for the connection test (default: 15).

.EXAMPLE
    Test-NetworkConnectivity -SiteUrl "https://contoso.sharepoint.com"

.NOTES
    Returns an object with detailed connectivity information.
#>
function Test-NetworkConnectivity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SiteUrl,
        
        [Parameter()]
        [int]$Timeout = 15
    )
    
    Write-VerboseLog "Testing network connectivity to $SiteUrl"
    
    try {
        # Parse the URL to get the host
        $uri = [System.Uri]$SiteUrl
        $hostname = $uri.Host
        
        # Create result object
        $result = [PSCustomObject]@{
            SiteUrl = $SiteUrl
            Hostname = $hostname
            PingSuccessful = $false
            HttpSuccessful = $false
            DnsResolution = $false
            LatencyMs = $null
            HttpStatusCode = $null
            ErrorMessage = $null
            Timestamp = Get-Date
        }
        
        # Test DNS resolution
        try {
            $dnsResult = Resolve-DnsName -Name $hostname -ErrorAction Stop
            $result.DnsResolution = $true
            Write-VerboseLog "DNS resolution successful for $hostname"
        }
        catch {
            $result.ErrorMessage = "DNS resolution failed: $($_.Exception.Message)"
            Write-Log "DNS resolution failed for $hostname" -Level WARNING
        }
        
        # Test ping (ICMP)
        try {
            $pingResult = Test-Connection -ComputerName $hostname -Count 2 -Quiet
            $result.PingSuccessful = $pingResult
            if ($pingResult) {
                $pingDetail = Test-Connection -ComputerName $hostname -Count 1
                $result.LatencyMs = $pingDetail.ResponseTime
                Write-VerboseLog "Ping successful to $hostname (${result.LatencyMs}ms)"
            }
            else {
                Write-Log "Ping to $hostname failed or is blocked" -Level WARNING
            }
        }
        catch {
            Write-Log "Ping test threw an exception: $($_.Exception.Message)" -Level WARNING
        }
        
        # Test HTTP connectivity
        try {
            $webRequest = Invoke-WebRequest -Uri $SiteUrl -Method HEAD -UseBasicParsing -TimeoutSec $Timeout
            $result.HttpSuccessful = $true
            $result.HttpStatusCode = $webRequest.StatusCode
            Write-VerboseLog "HTTP request to $SiteUrl successful (Status: $($webRequest.StatusCode))"
        }
        catch [System.Net.WebException] {
            $webExc = $_.Exception
            
            # If there's a response, get the status code
            if ($webExc.Response -ne $null) {
                $result.HttpStatusCode = [int]$webExc.Response.StatusCode
                $result.ErrorMessage = "HTTP request failed with status code $($result.HttpStatusCode)"
            }
            else {
                $result.ErrorMessage = "HTTP request failed: $($webExc.Message)"
            }
            
            Write-Log "HTTP connectivity test to $SiteUrl failed: $($result.ErrorMessage)" -Level WARNING
        }
        catch {
            $result.ErrorMessage = "HTTP request failed: $($_.Exception.Message)"
            Write-Log "HTTP connectivity test to $SiteUrl failed: $($_.Exception.Message)" -Level WARNING
        }
        
        return $result
    }
    catch {
        Write-ErrorLog -Message "Failed to complete network connectivity test" -ErrorRecord $_
        return [PSCustomObject]@{
            SiteUrl = $SiteUrl
            Hostname = $null
            PingSuccessful = $false
            HttpSuccessful = $false
            DnsResolution = $false
            LatencyMs = $null
            HttpStatusCode = $null
            ErrorMessage = "Test failed with exception: $($_.Exception.Message)"
            Timestamp = Get-Date
        }
    }
}

<#
.SYNOPSIS
    Tests if a PowerShell command is available.

.DESCRIPTION
    Checks if a specified PowerShell command (cmdlet, function, alias) exists
    and can be executed in the current session.

.PARAMETER CommandName
    The name of the command to test.

.PARAMETER ModuleName
    The name of the module containing the command (optional).

.EXAMPLE
    Test-CommandAvailability -CommandName "Get-SPSite"

.NOTES
    Returns an object with availability status and details.
#>
function Test-CommandAvailability {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$CommandName,
        
        [Parameter()]
        [string]$ModuleName
    )
    
    Write-VerboseLog "Testing availability of command '$CommandName'"
    
    try {
        $result = [PSCustomObject]@{
            CommandName = $CommandName
            IsAvailable = $false
            CommandType = $null
            ModuleName = $null
            Version = $null
            ErrorMessage = $null
        }
        
        # If a module was specified, first check if it's available
        if ($ModuleName) {
            if (-not (Get-Module -Name $ModuleName -ListAvailable)) {
                $result.ErrorMessage = "Module '$ModuleName' is not available"
                Write-Log "Command '$CommandName' is not available because module '$ModuleName' is not installed" -Level WARNING
                return $result
            }
            
            # Try to import the module if it's not already imported
            if (-not (Get-Module -Name $ModuleName)) {
                try {
                    Import-Module -Name $ModuleName -ErrorAction Stop
                    Write-VerboseLog "Successfully imported module '$ModuleName'"
                }
                catch {
                    $result.ErrorMessage = "Failed to import module '$ModuleName': $($_.Exception.Message)"
                    Write-Log "Failed to import module '$ModuleName': $($_.Exception.Message)" -Level WARNING
                    return $result
                }
            }
        }
        
        # Check if the command exists
        $command = Get-Command -Name $CommandName -ErrorAction SilentlyContinue
        
        if ($command) {
            $result.IsAvailable = $true
            $result.CommandType = $command.CommandType
            
            # Get module details if the command comes from a module
            if ($command.ModuleName) {
                $result.ModuleName = $command.ModuleName
                
                $module = Get-Module -Name $command.ModuleName
                if ($module) {
                    $result.Version = $module.Version
                }
            }
            
            Write-VerboseLog "Command '$CommandName' is available (Type: $($result.CommandType), Module: $($result.ModuleName), Version: $($result.Version))"
        }
        else {
            $result.ErrorMessage = "Command '$CommandName' does not exist"
            Write-Log "Command '$CommandName' is not available" -Level WARNING
        }
        
        return $result
    }
    catch {
        Write-ErrorLog -Message "Error testing command availability" -ErrorRecord $_
        return [PSCustomObject]@{
            CommandName = $CommandName
            IsAvailable = $false
            CommandType = $null
            ModuleName = $null
            Version = $null
            ErrorMessage = "Test failed with exception: $($_.Exception.Message)"
        }
    }
}

<#
.SYNOPSIS
    Determines the next method to try when the current one fails.

.DESCRIPTION
    Based on a specified method name and its failure details, this function
    returns the next method to try according to the failover strategy.

.PARAMETER CurrentMethod
    The current method that failed (SharePointCmdlets, CSOM, or REST).

.PARAMETER FailureDetails
    An object containing details about the failure.

.EXAMPLE
    Get-FailoverMethod -CurrentMethod "SharePointCmdlets" -FailureDetails $error

.NOTES
    Returns the next method name or $null if no more methods are available.
#>
function Get-FailoverMethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("SharePointCmdlets", "CSOM", "REST")]
        [string]$CurrentMethod,
        
        [Parameter()]
        [object]$FailureDetails
    )
    
    Write-VerboseLog "Determining failover method from '$CurrentMethod'"
    
    # Define the failover chain
    $failoverChain = @("SharePointCmdlets", "CSOM", "REST")
    
    # Find the current position in the chain
    $currentIndex = $failoverChain.IndexOf($CurrentMethod)
    
    if ($currentIndex -eq -1) {
        Write-Log "Unknown method '$CurrentMethod', defaulting to first available method" -Level WARNING
        return $failoverChain[0]
    }
    
    # Check if there's a next method in the chain
    if ($currentIndex -lt ($failoverChain.Count - 1)) {
        $nextMethod = $failoverChain[$currentIndex + 1]
        Write-Log "Failing over from '$CurrentMethod' to '$nextMethod'" -Level INFO
        return $nextMethod
    }
    else {
        Write-Log "No more failover methods available after '$CurrentMethod'" -Level WARNING
        return $null
    }
}

<#
.SYNOPSIS
    Measures the execution time of an operation.

.DESCRIPTION
    Executes a script block and measures the time it takes to complete.
    Optionally logs the execution time.

.PARAMETER Name
    A name to identify the operation being measured.

.PARAMETER ScriptBlock
    The script block to execute and measure.

.PARAMETER LogLevel
    The log level to use when logging the execution time.

.PARAMETER NoLogging
    If specified, no logging will be performed.

.EXAMPLE
    Measure-OperationTime -Name "Get-SPSite" -ScriptBlock { Get-SPSite }

.NOTES
    Returns an object with operation details and execution time.
#>
function Measure-OperationTime {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Name,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        
        [Parameter()]
        [ValidateSet("ERROR", "WARNING", "INFO", "VERBOSE", "DEBUG")]
        [string]$LogLevel = "INFO",
        
        [Parameter()]
        [switch]$NoLogging
    )
    
    try {
        $startTime = Get-Date
        
        if (-not $NoLogging) {
            Write-VerboseLog "Starting operation '$Name'"
        }
        
        # Execute the script block
        $result = & $ScriptBlock
        
        $endTime = Get-Date
        $duration = $endTime - $startTime
        $milliseconds = [math]::Round($duration.TotalMilliseconds)
        
        if (-not $NoLogging) {
            $logMessage = "Operation '$Name' completed in ${milliseconds}ms"
            Write-Log -Message $logMessage -Level $LogLevel
        }
        
        # Return an object with results and timing
        return [PSCustomObject]@{
            Name = $Name
            StartTime = $startTime
            EndTime = $endTime
            DurationMs = $milliseconds
            Result = $result
        }
    }
    catch {
        $endTime = Get-Date
        $duration = $endTime - $startTime
        $milliseconds = [math]::Round($duration.TotalMilliseconds)
        
        if (-not $NoLogging) {
            Write-ErrorLog -Message "Operation '$Name' failed after ${milliseconds}ms" -ErrorRecord $_
        }
        
        # Rethrow the exception
        throw
    }
}

<#
.SYNOPSIS
    Handles exceptions in a standardized way.

.DESCRIPTION
    Processes exceptions with consistent logging and categorization.
    Helps with debugging and reporting errors.

.PARAMETER Exception
    The exception to handle.

.PARAMETER Operation
    The name of the operation that generated the exception.

.PARAMETER Category
    The category of the exception (default: "General").

.PARAMETER ContinueOperation
    If specified, the function returns error details instead of throwing.

.EXAMPLE
    try {
        # Some operation
    } catch {
        Handle-Exception -Exception $_.Exception -Operation "Getting SharePoint site"
    }

.NOTES
    Can categorize errors for better reporting and handling.
#>
function Handle-Exception {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Exception]$Exception,
        
        [Parameter(Mandatory = $true)]
        [string]$Operation,
        
        [Parameter()]
        [ValidateSet("General", "Authentication", "Network", "Permission", "Timeout", "SharePoint")]
        [string]$Category = "General",
        
        [Parameter()]
        [switch]$ContinueOperation
    )
    
    # Categorize the exception
    $errorCategory = $Category
    
    # Try to determine a more specific category based on the exception type
    if ($Category -eq "General") {
        if ($Exception -is [System.Net.WebException]) {
            $errorCategory = "Network"
            if ($Exception.Status -eq [System.Net.WebExceptionStatus]::Timeout) {
                $errorCategory = "Timeout"
            }
            elseif ($Exception.Response -ne $null) {
                $statusCode = [int]$Exception.Response.StatusCode
                if ($statusCode -eq 401 -or $statusCode -eq 403) {
                    $errorCategory = "Authentication"
                }
                elseif ($statusCode -eq 404) {
                    $errorCategory = "SharePoint"
                }
            }
        }
        elseif ($Exception.Message -match "access denied|unauthorized|not authorized|permission") {
            $errorCategory = "Permission"
        }
        elseif ($Exception.Message -match "timed out|timeout") {
            $errorCategory = "Timeout"
        }
    }
    
    # Log the exception
    Write-ErrorLog -Message "[$errorCategory] Exception in operation '$Operation'" -Exception $Exception
    
    # Create a structured error object
    $errorDetail = [PSCustomObject]@{
        Timestamp = Get-Date
        Operation = $Operation
        Category = $errorCategory
        Message = $Exception.Message
        ExceptionType = $Exception.GetType().FullName
        StackTrace = $Exception.StackTrace
        InnerException = if ($Exception.InnerException) { $Exception.InnerException.Message } else { $null }
    }
    
    if ($ContinueOperation) {
        return $errorDetail
    }
    else {
        # Rethrow with categorized message
        $newException = New-Object System.Exception "[$errorCategory] $Operation failed: $($Exception.Message)", $Exception
        throw $newException
    }
}

# Export the public functions
Export-ModuleMember -Function Invoke-WithRetry, Test-NetworkConnectivity, Test-CommandAvailability, Get-FailoverMethod, Measure-OperationTime, Handle-Exception 