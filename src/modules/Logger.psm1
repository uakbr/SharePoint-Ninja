#Region Module Header
<#
.SYNOPSIS
PowerShell module for comprehensive logging in the SharePoint Restricted Environment Data Collector.

.DESCRIPTION
This module provides functions for logging operations, errors, and warnings to both console and file.
It includes functionality for log file creation, rotation, and various logging levels.

.NOTES
File: Logger.psm1
Author: SharePoint Restricted Environment Data Collector Team
Version: 0.1.0
#>
#EndRegion Module Header

# Define logging levels
enum LogLevel {
    ERROR = 1
    WARNING = 2
    INFO = 3
    VERBOSE = 4
    DEBUG = 5
}

# Define global variables
$script:LogFile = $null
$script:LogLevel = [LogLevel]::INFO
$script:LogStartTime = Get-Date
$script:ErrorCount = 0
$script:WarningCount = 0
$script:InfoCount = 0

<#
.SYNOPSIS
    Initializes the log file for the current session.

.DESCRIPTION
    Creates a new log file with a timestamp in the filename and writes initial
    session information including PowerShell version and execution environment.

.PARAMETER LogFilePath
    The path where the log file should be created. If not specified, logs will be created
    in the 'logs' directory relative to the script's location.

.PARAMETER LogPrefix
    A prefix to add to the log filename. Default is "SPDataCollector".

.PARAMETER LogLevel
    The minimum level of messages to log. Default is "INFO".

.EXAMPLE
    Initialize-LogFile -LogLevel "DEBUG"

.NOTES
    This function should be called at the beginning of script execution.
#>
function Initialize-LogFile {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]$LogFilePath,
        
        [Parameter()]
        [string]$LogPrefix = "SPDataCollector",
        
        [Parameter()]
        [ValidateSet("ERROR", "WARNING", "INFO", "VERBOSE", "DEBUG")]
        [string]$Level = "INFO"
    )
    
    try {
        # Set the global log level
        $script:LogLevel = [LogLevel]$Level
        
        # Create log directory if it doesn't exist
        if (-not $LogFilePath) {
            $scriptRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
            $LogFilePath = Join-Path -Path $scriptRoot -ChildPath "logs"
        }
        
        if (-not (Test-Path -Path $LogFilePath)) {
            New-Item -ItemType Directory -Path $LogFilePath -Force | Out-Null
        }
        
        # Create log file name with timestamp
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $logFileName = "${LogPrefix}_${timestamp}.log"
        $script:LogFile = Join-Path -Path $LogFilePath -ChildPath $logFileName
        
        # Write header information to log file
        $headerText = @"
# SharePoint Restricted Environment Data Collector Log
# Started: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# PowerShell Version: $($PSVersionTable.PSVersion)
# OS: $([System.Environment]::OSVersion.VersionString)
# Machine: $([System.Environment]::MachineName)
# User: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
# Log Level: $Level
#-------------------------------------------------------------

"@
        
        $headerText | Out-File -FilePath $script:LogFile -Encoding utf8
        
        # Log the initialization
        Write-Log -Message "Log file initialized at $script:LogFile" -Level INFO
        return $script:LogFile
    }
    catch {
        Write-Error "Failed to initialize log file: $_"
        throw $_
    }
}

<#
.SYNOPSIS
    Writes a log message to both the console and log file.

.DESCRIPTION
    Logs a message with a timestamp and specified log level to both
    the console and the log file. Console output is color-coded by level.

.PARAMETER Message
    The message to log.

.PARAMETER Level
    The level of the message (ERROR, WARNING, INFO, VERBOSE, DEBUG).

.PARAMETER NoConsole
    If specified, the message will not be displayed in the console.

.EXAMPLE
    Write-Log -Message "Operation completed successfully" -Level INFO

.NOTES
    Ensure Initialize-LogFile has been called before using this function.
#>
function Write-Log {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Position = 1)]
        [ValidateSet("ERROR", "WARNING", "INFO", "VERBOSE", "DEBUG")]
        [string]$Level = "INFO",
        
        [Parameter()]
        [switch]$NoConsole
    )
    
    # Convert string level to enum
    $logLevelEnum = [LogLevel]$Level
    
    # Only log if the message level is less than or equal to the current log level
    if ($logLevelEnum -le $script:LogLevel) {
        # Increment counter for the appropriate level
        switch ($logLevelEnum) {
            ([LogLevel]::ERROR) { $script:ErrorCount++ }
            ([LogLevel]::WARNING) { $script:WarningCount++ }
            ([LogLevel]::INFO) { $script:InfoCount++ }
        }
        
        # Format timestamp
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        # Format log entry
        $logEntry = "[$timestamp] $Level`: $Message"
        
        # Check if log file has been initialized
        if (-not $script:LogFile) {
            Initialize-LogFile
        }
        
        # Write to log file
        $logEntry | Out-File -FilePath $script:LogFile -Append -Encoding utf8
        
        # Write to console with color coding unless NoConsole is specified
        if (-not $NoConsole) {
            $consoleColor = switch ($logLevelEnum) {
                ([LogLevel]::ERROR) { "Red" }
                ([LogLevel]::WARNING) { "Yellow" }
                ([LogLevel]::INFO) { "White" }
                ([LogLevel]::VERBOSE) { "Gray" }
                ([LogLevel]::DEBUG) { "Cyan" }
                default { "White" }
            }
            
            Write-Host $logEntry -ForegroundColor $consoleColor
        }
    }
}

<#
.SYNOPSIS
    Logs an error message with additional error details.

.DESCRIPTION
    Logs an error message with detailed information from an ErrorRecord
    or Exception, including stack trace for debugging purposes.

.PARAMETER Message
    The error message to log.

.PARAMETER ErrorRecord
    The ErrorRecord object from a catch block.

.PARAMETER Exception
    An Exception object to log details from.

.EXAMPLE
    try {
        # Some operation
    } catch {
        Write-ErrorLog -Message "Failed to perform operation" -ErrorRecord $_
    }

.NOTES
    This function logs at the ERROR level.
#>
function Write-ErrorLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message,
        
        [Parameter(Position = 1, ParameterSetName = "ErrorRecord")]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,
        
        [Parameter(Position = 1, ParameterSetName = "Exception")]
        [System.Exception]$Exception
    )
    
    # Basic error message
    Write-Log -Message $Message -Level ERROR
    
    # Add detailed error information if available
    if ($ErrorRecord) {
        $errorMessage = "  Error details: $($ErrorRecord.Exception.Message)"
        $errorPosition = "  Position: $($ErrorRecord.InvocationInfo.PositionMessage)"
        $errorScriptName = "  Script: $($ErrorRecord.InvocationInfo.ScriptName)"
        $errorLine = "  Line: $($ErrorRecord.InvocationInfo.Line)"
        
        Write-Log -Message $errorMessage -Level ERROR -NoConsole
        Write-Log -Message $errorPosition -Level ERROR -NoConsole
        Write-Log -Message $errorScriptName -Level ERROR -NoConsole
        Write-Log -Message $errorLine -Level ERROR -NoConsole
        
        # Include stack trace for DEBUG level
        if ($script:LogLevel -ge [LogLevel]::DEBUG) {
            $stackTrace = "  Stack Trace: $($ErrorRecord.ScriptStackTrace)"
            Write-Log -Message $stackTrace -Level DEBUG -NoConsole
        }
    }
    elseif ($Exception) {
        $exceptionMessage = "  Exception details: $($Exception.Message)"
        Write-Log -Message $exceptionMessage -Level ERROR -NoConsole
        
        # Include stack trace for DEBUG level
        if ($script:LogLevel -ge [LogLevel]::DEBUG) {
            $stackTrace = "  Stack Trace: $($Exception.StackTrace)"
            Write-Log -Message $stackTrace -Level DEBUG -NoConsole
        }
    }
}

<#
.SYNOPSIS
    Logs a message at the VERBOSE level.

.DESCRIPTION
    Logs a message at the VERBOSE level if the current logging level is
    set to VERBOSE or higher. Useful for detailed operational information.

.PARAMETER Message
    The message to log at VERBOSE level.

.EXAMPLE
    Write-VerboseLog -Message "Processing item $item"

.NOTES
    This is a convenience function that wraps Write-Log.
#>
function Write-VerboseLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )
    
    Write-Log -Message $Message -Level VERBOSE
}

<#
.SYNOPSIS
    Logs a message at the DEBUG level.

.DESCRIPTION
    Logs a message at the DEBUG level if the current logging level is
    set to DEBUG. Useful for detailed diagnostic information.

.PARAMETER Message
    The message to log at DEBUG level.

.EXAMPLE
    Write-DebugLog -Message "Variable value: $value"

.NOTES
    This is a convenience function that wraps Write-Log.
#>
function Write-DebugLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )
    
    Write-Log -Message $Message -Level DEBUG
}

<#
.SYNOPSIS
    Gets a summary of the current logging session.

.DESCRIPTION
    Returns a summary of the current logging session, including counts of
    errors, warnings, and info messages, as well as the elapsed time.

.PARAMETER AsObject
    If specified, returns the summary as a PSObject instead of a string.

.EXAMPLE
    $summary = Get-LogSummary
    Write-Host $summary

.NOTES
    This can be useful for adding a summary at the end of a log file.
#>
function Get-LogSummary {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$AsObject
    )
    
    $elapsedTime = (Get-Date) - $script:LogStartTime
    $elapsedFormatted = "{0:D2}:{1:D2}:{2:D2}" -f $elapsedTime.Hours, $elapsedTime.Minutes, $elapsedTime.Seconds
    
    if ($AsObject) {
        return [PSCustomObject]@{
            StartTime = $script:LogStartTime
            EndTime = Get-Date
            ElapsedTime = $elapsedTime
            ElapsedTimeFormatted = $elapsedFormatted
            ErrorCount = $script:ErrorCount
            WarningCount = $script:WarningCount
            InfoCount = $script:InfoCount
            LogFile = $script:LogFile
        }
    }
    else {
        $summary = @"
Log Summary:
-----------------------------------------
Started: $($script:LogStartTime)
Ended: $(Get-Date)
Elapsed Time: $elapsedFormatted
Errors: $script:ErrorCount
Warnings: $script:WarningCount
Info Messages: $script:InfoCount
Log File: $script:LogFile
-----------------------------------------
"@
        return $summary
    }
}

<#
.SYNOPSIS
    Closes the current log session and writes a summary.

.DESCRIPTION
    Finalizes the current logging session by writing a summary
    to the log file and resetting the log file variable.

.PARAMETER NoSummary
    If specified, no summary will be written to the log file.

.EXAMPLE
    Close-Log

.NOTES
    This function should be called at the end of script execution.
#>
function Close-Log {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$NoSummary
    )
    
    if (-not $script:LogFile) {
        return
    }
    
    if (-not $NoSummary) {
        $summary = Get-LogSummary
        $summary | Out-File -FilePath $script:LogFile -Append -Encoding utf8
        Write-Host "Log file closed: $script:LogFile" -ForegroundColor Cyan
    }
    
    # Reset log file variable
    $script:LogFile = $null
}

# Export the public functions
Export-ModuleMember -Function Initialize-LogFile, Write-Log, Write-ErrorLog, Write-VerboseLog, Write-DebugLog, Get-LogSummary, Close-Log 