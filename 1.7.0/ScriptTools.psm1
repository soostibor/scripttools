<#
    Author: Tibor Soós (soos.tibor@hotmail.com)
    Version: 1.7.0 [2025.10.03]
#>

#region Logging

<#
.SYNOPSIS
    Initializes the logging system for PowerShell scripts.
.DESCRIPTION
    Sets up a logging infrastructure including log file creation, environment detection,
    and configuration of logging parameters. Supports various execution environments including
    Azure Automation, Hybrid Workers, and standard PowerShell sessions.
#>
function Initialize-Logging {
    [CmdletBinding()]
    param(
        [string] $Title,
        [string] $Name,
        [string] $Path,
        # [hashtable[]] $AdditionalColumns,
        [string[]] $IgnoreCommand = "HandleError",
        [int]    $KeepDays = 60,
        [int]    $ProgressBarSec = 1,
        [int]    $ProgressLogFirst = 60,
        [int]    $ProgressLogMin = 5,
        [string[]] $IgnoreLocation = ("ScriptTools", "ScriptBlock"),
        [string] $MergeTo,
        [string[]] $EmailNotification,
        [string] $SMTPServer,
        [switch] $BySeconds,
        [string] $DatePart,
        [switch] $SimulateRunbook
    )
    if ($MergeTo) {
        return $MergeTo
    }

    (Get-Variable -Name Error -Scope global -ValueOnly).Clear()

    $CS = @(Get-PSCallStack)
    $ScriptInvocation = $CS[1].InvocationInfo

    $Version = "0.0.0"
    $ReleaseDate = ""

    $AdditionalColumns = @(@{Name = "Function"; Rule = { $EnvironmentInvocation.MyCommand.Name }; width = 26 })

    if (($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters.Debug) -or ($MergeTo -and $global:Logging.$MergeTo._DebugMode)) {
        $AdditionalColumns += @{Name = "Module"; Rule = { $EnvironmentInvocation.MyCommand.ModuleName }; width = 20 },
        @{Name = "Environment"; Rule = { $EnvironmentInvocation.BoundParameters.CmdEnvironment } },
        @{Name = "Resource"; Rule = { $EnvironmentInvocation.BoundParameters.Resource }; width = 20 },
        @{Name = "ResourceID"; Rule = { $EnvironmentInvocation.BoundParameters.ResourceID }; width = 13 }
    }

    if (Get-Member -InputObject $ScriptInvocation.MyCommand -Name ScriptContents -ErrorAction Ignore) {
        $ScriptText = $ScriptInvocation.MyCommand.ScriptContents
        $VersionFound = $ScriptText -match "Version\s*:\s*(?<version>\d+\.\d+(\.\d+)*)(\s*\((?<releasedate>\d{4}\.\d{2}\.\d{2})\))?"
        if ($VersionFound) {
            $ReleaseDate = $Matches.ReleaseDate
            $Version = $Matches.Version
        }
    }

    $Environment = $Host.Name
    $UseOutput = $false

    if ($SimulateRunbook) {
        $Path = $env:TEMP
        $Environment = 'Simulated Runbook'
        $BySeconds = $true
        $UseOutput = $true
    }
    elseif ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation') {
        $Path = $env:TEMP
        $Environment = $env:AZUREPS_HOST_ENVIRONMENT
        $BySeconds = $true
        $UseOutput = $true
    }
    elseif ($Host.Name -eq 'Default Host') {
        $Path = $env:TEMP
        $Environment = "Hybrid Worker"
        $BySeconds = $true
        $UseOutput = $true
    }
    elseif (!$Path) {
        if ($ScriptInvocation.MyCommand.Path) {
            $Path = Split-Path $ScriptInvocation.MyCommand.Path
        }
        else {
            $Path = $env:TEMP
        }

        $Path = Join-Path $Path Logs
    }

    if ($ScriptInvocation.MyCommand.Name) {
        $ScriptName = $ScriptInvocation.MyCommand.Name
    }
    else {
        $ScriptName = "Interactive"
    }

    if ($ScriptInvocation.MyCommand.Path) {
        $ScriptPath = Split-Path -Path $ScriptInvocation.MyCommand.Path
    }
    else {
        $ScriptPath = "Interactive"
    }

    $Columns = @('"DateTime"           ', '"Line"  ', '"Type"     ')
    if ($AdditionalColumns) {
        $Columns += $AdditionalColumns | ForEach-Object { "{0,$(-([math]::Max($_.Width,$_.Name.Length)+2))}" -f """$($_.Name)""" }
    }
    $Columns += '"Message"'

    if (!$Name) {
        $LogName = "$($ScriptName).log"
    }
    else {
        $LogName = $Name
    }

    if (!$global:Logging -or $global:Logging -isnot [hashtable]) {
        $global:Logging = @{}
    }

    $LogFile = New-LogFile -Name $LogName -Path $Path -KeepDays $KeepDays -LogName $LogName -BySeconds:$BySeconds -DatePart $DatePart

    $CS[1].InvocationInfo.BoundParameters.LogName = $LogFile.Name

    $ParentProcess = $null
    $MyProcess = Get-CimInstance -ClassName Win32_process -Filter "ProcessID = '$PID'" -Verbose:$false
    if ($MyProcess.ParentProcessId) {
        $ParentProcess = Get-CimInstance -ClassName Win32_process -Filter "ProcessID = '$($MyProcess.ParentProcessId)'" -Verbose:$false
    }

    $global:Logging.$($LogFile.Key) = [PSCustomObject] @{
        Title              = $Title
        ScriptName         = $ScriptName
        ScriptPath         = $ScriptPath
        ScriptVersion      = "$Version $(if($ReleaseDate){"($ReleaseDate)"})"
        RunBy              = "$env:USERDOMAIN\$env:USERNAME"
        IsAdministrator    = Get-LogIsAdministrator
        Computer           = $env:COMPUTERNAME
        LogPath            = $LogFile.FullName
        LogFolder          = $LogFile.DirectoryName
        LogStart           = Get-Date
        Environment        = $Environment
        _IndentOffset      = $CS.Count
        _LastLine          = ""
        _WarningsLogged    = 0
        _ErrorsLogged      = 0
        _UnhandledErrors   = 0
        _VerboseMode       = if ($PSBoundParameters.ContainsKey('verbose')) { $PSBoundParameters.Verbose }else { $false }
        _DebugMode         = $PSBoundParameters.Debug
        _Progress          = [PSCustomObject] @{
            ArrayID  = 0
            Counter  = 0
            Start    = $null
            BarSec   = $ProgressBarSec
            BarNext  = $null
            LogFirst = $ProgressLogFirst
            LogNext  = $null
            LogMin   = $ProgressLogMin
        }
        _AdditionalColumns = $AdditionalColumns
        _IgnoreCommand     = $IgnoreCommand
        _IgnoreLocation    = $IgnoreLocation
        _Email             = $EmailNotification
        _SmtpServer        = $SMTPServer
        _BaseIndent        = 0
        _LogCache          = [System.Collections.Queue] @()
        _MaxCacheSize      = 1000
        _UseOutput         = $UseOutput
        _ParentProcess     = $ParentProcess
    }

    if ($LogFile.New) {
        Set-Content -Path $LogFile.FullName -Value ($Columns -join ",")
    }

    $global:Logging.$($LogFile.Key) | Format-LogStringList -ExcludeProperty _* | FormatBorder | New-LogEntry -Type Header -LogName $LogFile.Key

    if ($ScriptInvocation.BoundParameters.Count) {
        [PSCustomObject][hashtable]$ScriptInvocation.BoundParameters | Format-LogStringList -ExcludeProperty LogName |
        FormatBorder -title "Bound Parameters:" -IndentLevel 1 |
        New-LogEntry -IndentLevel 1 -LogName $LogFile.Key
    }

    if ($ScriptImplicitParams = Get-Variable -Name ScriptImplicitParams -Scope Global -ErrorAction Ignore -ValueOnly) {
        [PSCustomObject] $ScriptImplicitParams | Format-LogStringList |
        FormatBorder -title "Parameters with defaults:" -IndentLevel 1 |
        New-LogEntry -IndentLevel 1 -LogName $LogFile.Key
    }

    $LogFile.DelayedLogEntries | New-LogEntry -IndentLevel 1

    return $LogFile.Key
}

<#
.SYNOPSIS
    Internal helper function to retrieve the current log name from the call stack.
.DESCRIPTION
    Traverses the PowerShell call stack to find the active log name from bound parameters
    or global variables. Used internally by logging functions.
#>
function GetLogName {
    if ($global:Logging -and $global:Logging -is [hashtable] -and $global:Logging.Keys.Count -eq 1) {
        $LogName = $global:Logging.Keys | Select-Object -First 1
    }

    $CS = @(Get-PSCallStack | Where-Object { $_.Location -ne '<No file>' })
    $RealStack = @($CS | Where-Object { $_.ScriptName -ne $CS[0].ScriptName })
    Set-Variable -Name LogCallStack -Value $CS -Scope 1
    Set-Variable -Name LogRealDepth -Value $RealStack.Count -Scope 1

    if (!$LogName) {
        for ($i = 1; $i -lt $CS.Length; $i++) {
            if (!$LogName -and $CS[$i].InvocationInfo.BoundParameters.ContainsKey('LogName')) {
                $LogName = $CS[$i].InvocationInfo.BoundParameters.LogName
                break
            }
        }
    }

    if (!$LogName -and $global:LogName) {
        $LogName = $global:LogName
    }

    $LogName
}

<#
.SYNOPSIS
    Writes progress information for iterative operations to the log.
.DESCRIPTION
    Tracks and logs progress for array/collection processing operations. Displays progress bars
    in verbose mode and periodically logs progress statistics including estimated time remaining.
#>
function Write-LogProgress {
    [CmdletBinding()]
    param(
        $InputArray,
        [string][Alias('Action')] $Activity,
        [int] $Percent,
        [string] $LogName,
        [int] $ProgressLogFirst
    )

    if (!$InputArray -or !$InputArray.Count) {
        return
    }

    if ($PSBoundParameters.ContainsKey('LogName') -and !$LogName) {
        return
    }

    $LogName = GetLogName

    if (!$LogName -or !$global:Logging.ContainsKey($LogName)) {
        $LogName = $null
        if ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation') {
            Write-Error "LogName '$LogName' is not valid"
            $global:Error.RemoveAt(0)
        }
        else {
            Write-Host "LogName '$LogName' is not valid" -ForegroundColor Red
        }
        return
    }

    if ($ProgressLogFirst -eq 0) {
        $ProgressLogFirst = $global:Logging.$LogName._Progress.LogFirst
    }

    if ($InputArray.GetHashCode() -ne $global:Logging.$LogName._Progress.ArrayID) {
        $global:Logging.$LogName._Progress.ArrayID = $InputArray.GetHashCode()
        $global:Logging.$LogName._Progress.Start = Get-Date
        $global:Logging.$LogName._Progress.BarNext = Get-Date
        $global:Logging.$LogName._Progress.Counter = 0
        $global:Logging.$LogName._Progress.LogNext = (Get-Date).AddSeconds($ProgressLogFirst)
    }

    if ((Get-Date) -ge $global:Logging.$LogName._Progress.BarNext -and ($global:Logging.$LogName._VerboseMode -or $PSBoundParameters.verbose)) {
        if (!$PSBoundParameters.ContainsKey('percent')) {
            $Percent = $global:Logging.$LogName._Progress.Counter / $InputArray.Count * 100
        }

        if ($Percent -gt 100) {
            $Percent = 100
        }

        if ($global:Logging.$LogName._Progress.Counter -eq 0) {
            $TimeLeft = [int]::MaxValue
        }
        else {
            $TimeLeft = ((Get-Date) - $global:Logging.$LogName._Progress.Start).TotalSeconds * ($InputArray.Count - $global:Logging.$LogName._Progress.Counter) / $global:Logging.$LogName._Progress.Counter
        }

        $Done = "{0,$("$($InputArray.Count)".Length)}" -f $global:Logging.$LogName._Progress.Counter
        $Left = "{0,$("$($InputArray.Count)".Length)}" -f ($InputArray.Count - $global:Logging.$LogName._Progress.Counter)
        Write-Progress -Activity $Activity -Status "All: $($InputArray.Count), Done: $Done, Left: $Left" -PercentComplete $Percent -SecondsRemaining $TimeLeft
        $global:Logging.$LogName._Progress.BarNext = (Get-Date).AddSeconds($global:Logging.$LogName._Progress.BarSec)
    }

    if ((Get-Date) -ge $global:Logging.$LogName._Progress.LogNext) {
        if ($global:Logging.$LogName._Progress.Counter -eq 0) {
            $TimeLeft = [int]::MaxValue
        }
        else {
            $TimeLeft = [int] (((Get-Date) - $global:Logging.$LogName._Progress.Start).TotalSeconds * ($InputArray.Count - $global:Logging.$LogName._Progress.Counter) / $global:Logging.$LogName._Progress.Counter)
        }

        $TimeLeft = [TimeSpan]::FromSeconds($TimeLeft).ToString()

        $Done = "{0,$("$($InputArray.Count)".Length)}" -f $global:Logging.$LogName._Progress.Counter
        $Left = "{0,$("$($InputArray.Count)".Length)}" -f ($InputArray.Count - $global:Logging.$LogName._Progress.Counter)

        New-LogEntry -Message "All: $($InputArray.Count), Done: $Done, Left: $Left, Estimated time left: $TimeLeft" -Type Progress

        $global:Logging.$LogName._Progress.LogNext = (Get-Date).AddMinutes($global:Logging.$LogName._Progress.LogMin)
    }

    $global:Logging.$LogName._Progress.Counter++
}

<#
.SYNOPSIS
    Creates a new log file with automatic cleanup of old logs.
.DESCRIPTION
    Generates a timestamped log file and removes obsolete log files older than the specified
    retention period. Supports both date-based and second-based file naming.
#>
function New-LogFile {
    param(
        [string] $Name,
        [string] $Path,
        [int]    $KeepDays = 60,
        [switch] $BySeconds,
        [switch] $Overwrite,
        [string] $DatePart
    )
    if (!$Path) {
        $LogName = GetLogName

        $Path = $global:Logging.$LogName.LogFolder
    }

    if (!(Test-Path -Path $Path -PathType Container)) {
        [void] (New-Item -Path $Path -ItemType Directory -ErrorAction Stop)
    }

    if ($BySeconds) {
        $DatePart = Get-Date -Format 'yyyyMMddHHmmss'
    }
    elseif (!$DatePart) {
        $DatePart = Get-Date -Format 'yyyyMMdd'
    }

    $FileName = $Name -replace "(?=\.(?!.*?\.))", "-$DatePart"
    $SearchName = $Name -replace "(?=\.(?!.*?\.))", "-*"

    if ($PSBoundParameters.ContainsKey('datepart')) {
        $Key = $FileName
    }
    else {
        $Key = $Name
    }

    $DelayedLogEntries = @()
    if ($KeepDays) {
        Get-ChildItem -Path $Path -Filter $SearchName | Where-Object { ((Get-Date) - $_.LastWriteTime).TotalDays -gt $KeepDays } |
        ForEach-Object {
            if (!$LogName -or !$global.Logging.$LogName) {
                $DelayedLogEntries += "Removing obsolete file: '$($_.FullName)'"
            }
            else {
                New-LogEntry -Message "Removing obsolete file: '$($_.FullName)'" -IndentLevel 1
            }
            Remove-Item -Path $_.FullName
        }
    }

    if ($Overwrite -or (!(Test-Path -Path (Join-Path -Path $Path -ChildPath $FileName)))) {
        $File = New-Item -Path $Path -Name $FileName -ItemType file -Force:$Overwrite | Add-Member -MemberType NoteProperty -Name New -Value $true -PassThru
    }
    else {
        $File = Get-Item -Path (Join-Path -Path $Path -ChildPath $FileName) | Add-Member -MemberType NoteProperty -Name New -Value $false -PassThru
    }

    Add-Member -InputObject $File -MemberType NoteProperty -Name Key -Value $Key -PassThru | Add-Member -MemberType NoteProperty -Name DelayedLogEntries -Value $DelayedLogEntries -PassThru
}

<#
.SYNOPSIS
    Formats text strings with a decorative border.
.DESCRIPTION
    Creates a hash (#) bordered box around text strings for enhanced visual presentation
    in log files. Used for headers and important log sections.
#>
function FormatBorder {
    param(
        [Parameter(ValueFromPipeline = $true)][string[]]$Strings,
        [string] $Title,
        [int] $IndentLevel
    )
    begin {
        $Lines = @()
        if ($Title) {
            $Lines += $Title
        }
    }
    process {
        foreach ($String in $Strings) {
            $Lines += " " * $IndentLevel * 4 + $String
        }
    }
    end {
        $Longest = $Lines | Sort-Object -Property Length -Descending | Select-Object -First 1 -ExpandProperty Length
        "#" * ($Longest + 4)
        foreach ($Line in $Lines) {
            "# $($Line.PadRight($Longest)) #"
        }
        "#" * ($Longest + 4)
    }
}

<#
.SYNOPSIS
    Formats objects as property lists for logging.
.DESCRIPTION
    Converts objects to formatted string lists showing property names and values.
    Useful for logging object details in a readable format.
#>
function Format-LogStringList {
    param(
        [Parameter(ValueFromPipeline = $true)]$Object,
        [string[]] $Property = "*",
        [string[]] $ExcludeProperty = $null,
        [switch] $Divide,
        [switch] $HideNulls,
        [int] $IndentLevel,
        [switch] $Sort,
        $SortBy,
        [switch] $Bordered,
        [string[]] $HideProperty
    )
    begin {
        $Lines = @()
    }

    process {
        $SelectedProps = @()
        $Longest = 0

        foreach ($p in $Object.PSObject.Properties) {
            if ($ExcludeProperty | Where-Object { $p.Name -like $_ } | Select-Object -First 1) {
                continue
            }
            if (($Property | Where-Object { $p.Name -like $_ } | Select-Object -First 1) -and (!$HideNulls -or $p.Value)) {
                $SelectedProps += $p

                if ($p.Name.Length -gt $Longest) {
                    $Longest = $p.Name.Length + 1
                }
            }
        }

        if ($Object -is [string]) {
            $Lines += " " * $IndentLevel * 4 + $Object
        }
        elseif ($SelectedProps) {
            if ($Sort) {
                if (!$SortBy) {
                    $SortProperty = "name"
                }
                else {
                    $SortProperty = $SortBy
                }
            }
            else {
                $SortProperty = "dummy"
            }

            foreach ($SP in ($SelectedProps | Sort-Object -Property $SortProperty -Debug:$false)) {
                if ($SP.Value -as [string] -and ($HideProperty | Where-Object { $SP.Name -like $_ })) {
                    $Value = '*' * ([string]$SP.Value).Length
                }
                else {
                    $Value = $SP.Value
                }
                $Lines += " " * $IndentLevel * 4 + $SP.Name.PadRight($Longest) + ": " + $Value
            }
        }
        if ($Divide) {
            $Lines += "-" * 92
        }
    }
    end {
        if ($Bordered) {
            $Lines | FormatBorder
        }
        else {
            $Lines
        }
    }
}

<#
.SYNOPSIS
    Formats objects as tables for logging.
.DESCRIPTION
    Converts objects to formatted table strings for logging purposes.
    Uses Format-Table with AutoSize for optimal display.
#>
function Format-LogStringTable {
    param(
        [Parameter(ValueFromPipeline = $true)]$Object,
        [object[]] $Property = "*",
        [string[]] $ExcludeProperty = $null,
        [switch] $Bordered
    )
    $SelectObjParams = @{}

    if ($Property) {
        $SelectObjParams.Property = $Property
    }

    if ($ExcludeProperty) {
        $SelectObjParams.ExcludeProperty = $ExcludeProperty
    }

    $Lines = ($Input | Select-Object @SelectObjParams | Format-Table -AutoSize | Out-String) -split "\r\n" |
    Where-Object { $_ -and $_.Trim() }

    if ($Bordered) {
        $Lines | FormatBorder
    }
    else {
        $Lines
    }
}

<#
.SYNOPSIS
    Logs any unhandled errors from the global error variable.
.DESCRIPTION
    Captures and logs all errors from the global $Error variable that weren't explicitly
    handled by the script. Helps ensure no errors are missed in logging.
#>
function Write-LogUnhandledErrors {
    $ScriptError = Get-Variable -Name Error -Scope Global -ValueOnly

    if ($ScriptError) {
        $Err2 = $ScriptError.Clone()
        $Err2.Reverse()
        $ScriptError.Clear()
        foreach ($e in $Err2) {
            New-LogEntry -Message "$($e.ScriptStackTrace): $($e.Exception.Message)" -Type Unhandled
            $global:Logging.$LogName._UnhandledErrors++
        }
    }
}

<#
.SYNOPSIS
    Appends text to log files with retry logic for file locking.
.DESCRIPTION
    Writes text to log files with automatic retry mechanism to handle file locking scenarios.
    Includes caching mechanism for when files are locked, with overflow to temporary files.
#>
function Add-LogTextWithRetry {
    [CmdletBinding()]
    param(
        [string] $Path,
        [Parameter(ValueFromPipeline = $true)][string[]] $Text,
        [ValidateScript( { $_ -is [System.Text.Encoding] })] $Encoding = [System.Text.Encoding]::UTF8,
        [int] $Timeout = 1,
        [switch] $Force
    )
    begin {
        $Retry = $true
        $Start = Get-Date
        $StreamWriter = $null
        do {
            try {
                $Locked = $false
                $StreamWriter = [IO.File]::AppendText($Path)
            }
            catch {
                $global:Error.Clear()
                if ($_.Exception.InnerException -and $_.Exception.InnerException.HResult -eq -2147024864) {
                    Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 500)
                    $Locked = $true
                }
                else {
                    $Retry = $false
                    $Force = $true
                }
            }
            if (((Get-Date) - $Start).TotalSeconds -gt $Timeout) {
                $Retry = $false
            }
        }while ((!$StreamWriter -or !$StreamWriter.BaseStream) -and $Retry)

        if ($StreamWriter -and $StreamWriter.BaseStream -and $global:Logging.$LogName._LogCache.Count) {
            while ($global:Logging.$LogName._LogCache.Count) {
                $CLine = $global:Logging.$LogName._LogCache.DeQueue()
                $StreamWriter.WriteLine($CLine)
            }
        }
    }
    process {
        foreach ($Line in $Text) {
            if (!$StreamWriter -or !$StreamWriter.BaseStream) {
                if ($Force -or !$Locked) {
                    throw "LogAppendText error"
                }
                else {
                    $global:Logging.$LogName._LogCache.EnQueue($Line)
                    if ($global:Logging.$LogName._LogCache.Count -gt $global:Logging.$LogName._MaxCacheSize) {
                        $tempfile = Join-Path -Path (Split-Path $Path) -ChildPath "_Templog-$(Get-Date -Format 'yyyy-MM-dd-HH-mm-ss-fffffff').log"
                        $global:Logging.$LogName._LogCache | Set-Content -Path $tempfile -Encoding ($Encoding.EncodingName -replace 'US-')
                        $global:Logging.$LogName._LogCache.Clear()
                    }
                }
            }
            else {
                $StreamWriter.WriteLine($Line)
            }
        }
    }
    end {
        if ($StreamWriter) {
            $StreamWriter.Close()
        }
    }
}

<#
.SYNOPSIS
    Creates a new entry in the log file.
.DESCRIPTION
    Main logging function that writes formatted log entries with timestamps, line numbers,
    entry types, and messages. Supports multiple log levels (Info, Warning, Error, etc.)
    and handles script termination when appropriate.
#>
function New-LogEntry {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)] [string] $Message,
        [Parameter()][ValidateSet('Info', 'Highlight', 'Warning', 'Error', 'Exit', 'Terminate', 'Unhandled', 'Progress', 'Debug', 'Header', 'Negative')]$Type = 'Info',
        [int] $IndentLevel,
        [switch] $UseAbsoluteIndent,
        [switch] $NoNewLine,
        [switch] $DisplayOnly,
        [string] $LogName,
        [switch] $IgnoreLog,
        [int] $ExitCode
    )
    begin {
        $LogName = GetLogName

        $RelativeLevel = 0

        $LocalVerbose = $null

        for ($i = 1; $i -lt $LogCallStack.Length; $i++) {
            if (!$RelativeLevel -and $LogCallStack[$i].ScriptName -ne $LogCallStack[0].ScriptName -and (!$LogName -or $LogCallStack[$i].Command -notin $global:Logging.$LogName._IgnoreCommand)) {
                $RelativeLevel = $i
            }

            if ($null -eq $LocalVerbose -and ($VerbosePreference -notin 'SilentlyContinue', 'Ignore' -or $LogCallStack[$i].InvocationInfo.BoundParameters.ContainsKey('Verbose'))) {
                $LocalVerbose = $LogCallStack[$i].InvocationInfo.BoundParameters.Verbose
            }
        }

        if (!$LogName) {
            $LogName = $null
            if ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation' -or $Host.Name -eq 'Default Host') {
                Write-Error "LogName '$LogName' is not valid"
                $global:Error.RemoveAt(0)
            }
            else {
                Write-Host "LogName '$LogName' is not valid" -ForegroundColor Red
            }
        }

        if ($null -eq $LocalVerbose) {
            $LocalVerbose = $global:Logging.$LogName._VerboseMode
        }

        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'existModuleName', Justification = 'variable is used in another scope')]
        $EnvironmentInvocation = $LogCallStack | Where-Object { $_.Location -notmatch ($global:Logging.$LogName._IgnoreLocation -join "|") -and $_.command -notmatch ($global:Logging.$LogName._IgnoreCommand -join "|") } | Select-Object -First 1 -ExpandProperty InvocationInfo

        $BaseIndent = [math]::Max($LogRealDepth - 1, 0)

        if ($IndentLevel) {
            $global:Logging.$LogName._BaseIndent = $IndentLevel
        }
        else {
            $global:Logging.$LogName._BaseIndent = $BaseIndent
        }

        if (!$UseAbsoluteIndent) {
            $IndentLevel = $IndentLevel + $BaseIndent
        }

        $LineNumber = $LogCallStack[$RelativeLevel].ScriptLineNumber

        switch ($Type) {
            'Info' { $Param = @{ForegroundColor = "Gray" } }
            'Highlight' { $Param = @{ForegroundColor = "Green" } }
            'Header' { $Param = @{ForegroundColor = "Green" } }
            'Debug' { $Param = @{ForegroundColor = "Cyan"; BackgroundColor = 'DarkGray' } }
            'Warning' { $Param = @{ForegroundColor = "Yellow"; BackgroundColor = 'DarkGray' }; $global:Logging.$LogName._WarningsLogged++ }
            'Error' { $Param = @{ForegroundColor = "Red" }; $global:Logging.$LogName._ErrorsLogged++ }
            'Negative' { $Param = @{ForegroundColor = "Red" } }
            'Exit' { $Param = @{ForegroundColor = "Green" } }
            'Terminate' { $Param = @{ForegroundColor = "Red"; BackgroundColor = 'Black' }; $global:Logging.$LogName._ErrorsLogged++ }
            'Unhandled' { $Param = @{ForegroundColor = "Red"; BackgroundColor = 'DarkGray' }; $global:Logging.$LogName._ErrorsLogged++ }
            'Progress' { $Param = @{ForegroundColor = "Magenta" } }
        }

        if ($Type -ne 'Unhandled') {
            Write-LogUnhandledErrors
        }
    }
    process {
        if ($LogName) {
            if ($global:Logging.$LogName._LastLine) {
                $Line = " $Message"
            }
            else {
                $Line = "[$(Get-Date -Format 'yyyy.MM.dd HH:mm:ss')],[$(([string]$LineNumber).PadLeft(6))],[$($Type.ToUpper().PadRight(9))]"
                if ($global:Logging.$LogName._AdditionalColumns) {
                    foreach ($c in $global:Logging.$LogName._AdditionalColumns) {
                        $Line += ",[{0,$(-([math]::Max($c.Width,$c.Name.Length)))}]" -f ($c.Rule.GetNewClosure().Invoke()[0])
                    }
                }
                $Line += ", »$(" " *$IndentLevel * 4)$Message"
            }

            if ($NoNewLine -or $global:Logging.$LogName._LastLine) {
                $global:Logging.$LogName._LastLine += $Line
            }

            if ($LogName -and !$NoNewLine -and !$DisplayOnly) {
                if ($global:Logging.$LogName._LastLine) {
                    #Add-Content -Path $global:Logging.$LogName.LogPath -Value $global:Logging.$LogName._LastLine
                    Add-LogTextWithRetry -Path $global:Logging.$LogName.LogPath -text $global:Logging.$LogName._LastLine
                    $global:Logging.$LogName._LastLine = ""
                }
                else {
                    #Add-Content -Path $global:Logging.$LogName.LogPath -Value $Line
                    Add-LogTextWithRetry -Path $global:Logging.$LogName.LogPath -text $Line
                }
            }
        }

        if ($DisplayOnly -or $LocalVerbose -or $Type -in 'Debug', 'Error', 'Terminate', 'Unhandled', 'Negative', 'Warning') {
            if ($global:Logging.$LogName._UseOutput) {
                if ($Type -in 'Error', 'Terminate', 'Unhandled') {
                    Write-Error $Line
                    $global:Error.RemoveAt(0)
                }
                elseif ($Type -eq 'Warning') {
                    Write-Warning $Line
                }
                elseif ($Type -match '^(Progress|Highlight)$' -and @($LogCallStack | Where-Object { $_.ScriptName -ne $LogCallStack[0].ScriptName }).Count -le 1) {
                    Write-Output $Line
                }
            }
            else {
                Write-Host -Object $Line @param -NoNewline:$NoNewLine
            }
        }
    }
    end {
        if ($Type -in 'Exit', 'Terminate') {
            if ($LogName) {

                New-LogFooter -LogName $LogName

                if ($null -eq $ExitCode -or $ExitCode -isnot [int]) {
                    if ($global:Logging.$LogName._ErrorsLogged) {
                        $ExitCode = 1
                    }
                    elseif ($global:Logging.$LogName._WarningsLogged) {
                        $ExitCode = 2
                    }
                    else {
                        $ExitCode = 0
                    }
                }

                if (!$IgnoreLog) {
                    if ($global:Logging.$LogName._Email -and $global:Logging.$LogName._SmtpServer) {
                        $Contents = ""
                        foreach ($Log in $global:Logging.Keys) {
                            if ($global:Logging.$Log._ErrorsLogged) {
                                $Contents += (Get-Content $global:Logging.$Log.LogPath -Encoding UTF8) -join "`r`n"
                                $Contents += "`r`n" + "`r`n" + ("-" * 200) + "`r`n"
                                $global:Logging.$Log._ErrorsLogged = 0
                            }
                        }

                        if ($Contents) {
                            Send-MailMessage -SmtpServer $global:Logging.$LogName._SmtpServer -To $global:Logging.$LogName._Email -Subject "PAMaaS Error Logs - $(Get-Date -Format 'yyyy.MM.dd HH.mm.ss')" -From "$($global:Logging.$LogName.ScriptName)@clearstream.com" -Body $Contents -Encoding UTF8
                        }
                    }
                }
                else {
                    Remove-Item -Path $global:Logging.$LogName.LogPath
                }

                if ($global:Logging.$LogName._UseOutput) {
                    Get-Content -Path $global:Logging.$LogName.LogPath -Encoding UTF8

                    if ($LogRealDepth -lt 1 -and ($global:Logging.$LogName._ParentProcess.Name -in 'explorer.exe', 'WindowsTerminal.exe' -or $Host.Name -match 'ISE|Visual Studio')) {
                        throw "$($Type)ing session with exit code $ExitCode"
                    }
                    else {
                        exit $ExitCode
                    }
                }
                elseif ($global:Logging.$LogName.ScriptName -ne 'Interactive') {
                    if ($global:Logging.$LogName._ParentProcess.Name -in 'explorer.exe', 'WindowsTerminal.exe' -or $Host.Name -match 'ISE|Visual Studio') {
                        if ($LogRealDepth -lt 1) {
                            throw "$($Type)ing session with exit code $ExitCode"
                        }
                        else {
                            exit $ExitCode
                        }
                    }
                    else {
                        [environment]::Exit($ExitCode)
                    }
                }
            }

            if ($LogCallStack.Count -le 3) {
                return
            }
            else {
                throw "Interactive exit: $ExitCode"
            }
        }
    }
}

<#
.SYNOPSIS
    Creates a footer section for the log file.
.DESCRIPTION
    Generates and logs summary information at the end of script execution including
    runtime, error counts, warning counts, and parent process information.
#>
function New-LogFooter {
    param([string]$LogName)

    if ($PSBoundParameters.ContainsKey('LogName') -and !$LogName) {
        return
    }

    $LogName = GetLogName

    if (!$LogName -or !$global:Logging.ContainsKey($LogName)) {
        $LogName = $null
        if ($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation' -or $Host.Name -eq 'Default Host') {
            Write-Error "LogName '$LogName' is not valid"
            $global:Error.RemoveAt(0)
        }
        else {
            Write-Host "LogName '$LogName' is not valid" -ForegroundColor Red
        }
    }

    $Seconds = [int] ((Get-Date) - $global:Logging.$LogName.LogStart).TotalSeconds

    $Footer = "LogName       : $LogName",
    "Runtime       : $([TimeSpan]::FromSeconds($Seconds).ToString())",
    "ErrorsLogged  : $($global:Logging.$LogName._ErrorsLogged)",
    "WarningsLogged: $($global:Logging.$LogName._WarningsLogged)",
    "ParentProcess : $($global:Logging.$LogName._ParentProcess.Name)"
    $Footer | FormatBorder | New-LogEntry -Type Header
}

<#
.SYNOPSIS
    Searches log files for specific entries.
.DESCRIPTION
    Imports and filters log entries from one or more log files based on custom filter criteria.
    Supports searching across multiple dates and sorting results.
#>
function Search-LogEntries {
    param(
        [string[]] $LogNames = $global:Logging.Keys,
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)] [string[]] $LogPath,
        [scriptblock] $FilterScript,
        [switch] $AllDates,
        [AllowNull()] [string[]] $SortBy,
        [switch] $Descending
    )
    begin {
        if ($LogPath) {
            if ($PSBoundParameters.ContainsKey('LogNames')) {
                $LogPath = Get-ChildItem -Path $LogPath -Include $LogNames -Recurse | Select-Object -ExpandProperty fullname
            }
            else {
                $LogPath = Get-ChildItem -Path $LogPath | Select-Object -ExpandProperty fullname
            }
        }
        elseif ($LogNames) {
            foreach ($LN in $LogNames) {
                $LogPath += $global:Logging.$LN.LogPath
            }
        }
    }
    process {
        foreach ($LP in $LogPath) {
            if ($AllDates) {
                $LP = $LP -replace "-\d{8,}(?=\.[^\.]+$)", '*'
            }

            if ($LP -notmatch "\.log") {
                $LP += "\*"
            }

            if (!$FilterScript) {
                $FilterScript = { $_.Line -match '^\[\s*\d+\]$' }
            }
            else {
                $FilterString = [string] $FilterScript
                $FilterString += ' -and $_.Line -match ''^\[\s*\d+\]$'''
                $FilterScript = [scriptblock]::Create($FilterString)
            }

            if ($SortBy) {
                Get-Item -Path $LP -PipelineVariable p -ErrorAction Ignore | ForEach-Object { $_.FullName } | Import-Csv -Encoding Default | Where-Object -FilterScript $FilterScript | Sort-Object -Property $SortBy -Descending:$Descending | select-object -Property @{n = "LogName"; e = { $p.Name } }, * | Format-LogStringTable
            }
            else {
                Get-Item -Path $LP -PipelineVariable p -ErrorAction Ignore | ForEach-Object { $_.FullName } | Import-Csv -Encoding Default | Where-Object -FilterScript $FilterScript | select-object -Property @{n = "LogName"; e = { $p.Name } }, * | Format-LogStringTable
            }
        }
    }
}

<#
.SYNOPSIS
    Checks if the current session is running with administrator privileges.
.DESCRIPTION
    Determines whether the current PowerShell session has administrative rights
    by checking the user's security principal group membership.
#>
function Get-LogIsAdministrator {
    $Identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object Security.Principal.WindowsPrincipal -ArgumentList $Identity
    $IsAdministrator = !!(($Principal.Identity.Groups | Select-Object -ExpandProperty value) -match "S-1-5-32-544")
    $IsAdministrator
}
#endregion Logging

#region PSData management

<#
.SYNOPSIS
    Resolves dynamic scriptblock expressions in PSData structures.
.DESCRIPTION
    Recursively processes PSData structures and evaluates scriptblocks to their actual values.
    Part of the PSData configuration management system.
#>
function ResolveDynamicData {
    param(
        $PSDataHive,
        [switch] $DontExpand
    )
    if ($PSDataHive -is [scriptblock]) {
        $PSDataHive = @{__PSDataScriptBlockArray = $PSDataHive }
    }
    elseif ($PSDataHive -isnot [System.Collections.IDictionary]) {
        return [PSCustomObject]@{
            UpdatedElement = $PSDataHive
            SkipAll        = $DontExpand
        }
    }

    $PSDataHiveKeys = $PSDataHive.Keys.ForEach({ $_ })

    foreach ($Key in ($PSDataHiveKeys | Sort-Object -Property {
                if ($_ -match '^Condition$') { "zz$($_)" }
                elseif ($_ -match '^ConfigAction') { "zzz$($_)" }
                elseif ($_ -match '^Conditional_') { "zzzz$($_)" }
                else { "__$($_)" }
            }
        )
    ) {
        if ($PSDataHive.$Key -is [System.Collections.IDictionary]) {
            ResolveDynamicData -PSDataHive $PSDataHive.$Key -DontExpand:$DontExpand
        }
        elseif ($PSDataHive.$Key -is [System.Object[]]) {
            for ($i = 0; $i -lt $PSDataHive.$Key.Count; $i++) {
                if ($PSDataHive.$Key[$i] -is [System.Collections.IDictionary]) {
                    ResolveDynamicData -PSDataHive $PSDataHive.$Key[$i] -DontExpand:$DontExpand
                }
                else {
                    $Result = ResolveDynamicData -PSDataHive $PSDataHive.$Key[$i] -DontExpand:$DontExpand
                    $PSDataHive.$Key[$i] = $Result.UpdatedElement
                    if ($Result.SkipAll) {
                        $DontExpand = $true
                        break
                    }
                }
            }
        }
        elseif ($PSDataHive.$Key -is [scriptblock] -and ($PSDataHive.Keys -notcontains 'Condition' -or $PSDataHive.Condition)) {
            [ref] $Errors = $null
            $Tokens = [System.Management.Automation.PSParser]::Tokenize($PSDataHive.$Key, $Errors)
            $Skip = $DontExpand

            if (!$Skip) {
                foreach ($Token in $Tokens) {
                    if ($Token.type -eq 'GroupStart') {
                        continue
                    }

                    if ($Token.Type -eq 'Comment' -and $Token.Content -match "DontExpand") {
                        if ($Token.Content -match "DontExpandAll") {
                            $DontExpand = $true
                        }

                        $Skip = $true
                        break
                    }
                    elseif ($Token.Type -ne 'NewLine') {
                        break
                    }
                }
            }

            if (!$Skip) {
                $ErrorHappened = $false
                $ErrorCount = $Error.Count
                try {
                    $PSDataHive.$Key = & $PSDataHive.$Key
                }
                catch {
                    $ErrorHappened = $true
                }

                if ($ErrorHappened -or $ErrorCount -gt $Error.Count) {
                    throw "PSData parsing error"
                }
            }

            if ($Key -eq '__PSDataScriptBlockArray') {
                [PSCustomObject]@{
                    UpdatedElement = $PSDataHive.$Key
                    SkipAll        = $DontExpand
                }
            }
        }
    }
}

<#
.SYNOPSIS
    Merges PSData configuration hives.
.DESCRIPTION
    Recursively merges configuration hashtables, combining nested structures
    while handling special configuration actions and conditions.
#>
function MergeHives {
    param(
        [System.Collections.IDictionary] $Hive,
        [System.Collections.IDictionary] $Target = $PSData
    )

    foreach ($HiveEnum in $Hive.GetEnumerator()) {
        if ($HiveEnum.Key -match '^Condition|^ConfigAction') {
            continue
        }
        elseif ($HiveEnum.Value -isnot [System.Collections.IDictionary]) {
            $Target.($HiveEnum.Key) = $HiveEnum.Value
        }
        elseif ($Target.Keys -notcontains $HiveEnum.Key) {
            $ConfigActions = @($HiveEnum.Value.Keys) -match '^ConfigAction'
            foreach ($CA in $ConfigActions) {
                $HiveEnum.Value.Remove($CA)
            }

            $Target.($HiveEnum.Key) = $HiveEnum.Value
        }
        else {
            try {
                MergeHives -Hive $HiveEnum.Value -Target $Target.($HiveEnum.Key)
            }
            catch {
            }
        }
    }
}

<#
.SYNOPSIS
    Imports PowerShell data configuration files.
.DESCRIPTION
    Loads and processes .data.ps1 configuration files with support for dynamic data,
    conditional sections, and automatic merging. Part of the configuration management system.
#>
function Import-PSData {
    [CmdletBinding()]
    param(
        [string[]]$PathsOrNames,
        [Parameter(Mandatory = $false)][System.Collections.IDictionary] $PSData,
        [switch] $PassThru
    )

    $InitiatePSConfig = $false
    if ($null -eq $PSData) {
        $PSData = @{}

        if (!(Get-Variable -Name PSConfig -Scope Global -ErrorAction Ignore)) {
            $InitiatePSConfig = $true
        }
    }

    $ScriptInvocation = (Get-PSCallStack)[-2].InvocationInfo

    if ($ScriptInvocation.MyCommand.Path) {
        $Basepath = $ScriptInvocation.MyCommand.Path
    }
    elseif ($ScriptInvocation.MyCommand.Module -and $ScriptInvocation.MyCommand.Module.Path) {
        $Basepath = $ScriptInvocation.MyCommand.Module.Path
    }

    if ($Basepath -match "\\\d+\.\d+\.\d+\\.*?ps(m)?1$") {
        $DefaultConfig = $ScriptInvocation.MyCommand.Path -replace "\\\d+\.\d+\.\d+\\(?!.*?\\)", "\Config\" -replace "\.ps(m)?1$", ".data.ps1"
    }
    else {
        $DefaultConfig = $Basepath -replace "\\(?!.*?\\)", "\Config\" -replace "\.ps(m)?1$", ".data.ps1"
    }

    if (!$PathsOrNames -and (!$DefaultConfig -or !(Test-Path -Path $DefaultConfig))) {
        if (Get-Module -Name "PSConfigs" -ErrorAction Ignore -ListAvailable) {
            Import-Module -Name PSConfigs -Force
            $DefaultConfig = Get-PSConfigs -ScriptName $ScriptInvocation.MyCommand.Name
        }
    }

    if ($DefaultConfig -and $PathsOrNames -notcontains $DefaultConfig -and (Test-Path $DefaultConfig)) {
        $PathsOrNames = @($DefaultConfig) + $PathsOrNames | Where-Object { $_ }
    }

    foreach ($Path in $PathsOrNames) {
        if ($Path -notlike "*.data.ps1") {
            throw "Name of the PS data file must end with '.data.ps1'"
        }

        if ($Path -notmatch "^\w+:|^\.") {
            $Path = Join-Path (Split-Path $ScriptInvocation.MyCommand.Path) "\Config\$Path"
        }

        if (!(Test-Path -Path $Path)) {
            Write-Error "No PS data file was found at '$Path'"
            continue
        }

        $Tokens = [System.Management.Automation.Language.Token[]]::New(1)
        $Errors = [System.Management.Automation.Language.ParseError[]]::New(1)

        $RealPath = Resolve-Path -Path $Path | Select-Object -ExpandProperty ProviderPath
        $AST = [System.Management.Automation.Language.Parser]::ParseFile(
            $RealPath,
            [ref] $Tokens,
            [ref] $Errors
        )

        if ($Errors) {
            throw "There are errors in PS data file '$Path'"
        }

        $TopLevelLayer = $AST.Find({ $true }, $false)

        $TopLevelExtentText = Get-Property -Object $TopLevelLayer -PropertyPath "[0].EndBlock.Extent.Text" -ValueOnly

        if (!$TopLevelExtentText -or $TopLevelExtentText.Trim() -notmatch "^(\[ordered\]\s*)?@\{") {
            throw "PS data file '$Path' must contain a single hash literal"
        }

        $AllCommands = @($AST.FindAll({ $args[0] -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or
                    $args[0] -is [System.Management.Automation.Language.CommandAst] -or
                    $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
                    $args[0] -is [System.Management.Automation.Language.CommandExpressionAst] }, $true))

        foreach ($Command in $AllCommands) {
            Update-Property -Object $Command.Parent -PropertyPath Children -Value $Command
        }

        $Errors = $false

        for ($i = 1; $i -lt $AllCommands.Count; $i++) {
            $Command = $AllCommands[$i]

            $CurrentLevel = $Command
            $PrevPrevPrev = $null
            $PrevPrev = $null
            $Prev = $null
            while ($CurrentLevel -and $CurrentLevel -isnot [System.Management.Automation.Language.HashtableAst]) {
                $PrevPrevPrev = $PrevPrev
                $PrevPrev = $Prev
                $Prev = $CurrentLevel
                $CurrentLevel = $CurrentLevel.Parent
            }

            if ($PrevPrevPrev -isnot [System.Management.Automation.Language.ScriptBlockExpressionAst] -and
                !($Command.Children -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or
                    $Command.Expression -is [System.Management.Automation.Language.HashtableAst] -or
                    $Command.Expression -is [System.Management.Automation.Language.ConstantExpressionAst] -or
                    $Command.Expression -is [System.Management.Automation.Language.ConvertExpressionAst] -or
                    $Command.Expression -is [System.Management.Automation.Language.ArrayLiteralAst] -or
                    $Command.Expression -is [System.Management.Automation.Language.BinaryExpressionAst] -or
                    $Command.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -or
                    $Command.Expression -is [System.Management.Automation.Language.ArrayExpressionAst])) {
                throw "Commands are allowed only in scriptblocks: $($Prev.extent)"
            }
        }

        try {
            $Config = & $Path
        }
        catch {
            throw $_
        }

        ResolveDynamicData -PSDataHive $Config

        $ConfigKeys = @($Config.Keys.Foreach({ $_ }))

        foreach ($Key in ($ConfigKeys -notmatch '^Condition' | Sort-Object)) {
            MergeHives -Hive $Config
        }

        foreach ($Key in ($ConfigKeys -match '^Conditional_' | Sort-Object)) {
            if ($Config.$Key.condition) {
                MergeHives -Hive $Config.$Key
                $Config.Remove($Key)
            }
        }
    }

    if ($InitiatePSConfig) {
        $global:PSConfig = $PSData
    }

    if ($PassThru) {
        $PSData
    }
}

<#
.SYNOPSIS
    Converts objects to PSData format strings.
.DESCRIPTION
    Serializes PowerShell objects to PSData literal syntax that can be saved to .data.ps1 files.
    Supports hashtables, arrays, custom objects, and various .NET types.
#>
function ConvertTo-PSData {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)] $Object,
        [Parameter(DontShow = $true)] [string] $Name,
        [switch] $Compress,
        [Parameter(DontShow = $true)] [int] $IndentLevel = 0
    )

    if ($Name) {
        if ($Name -match "\W" -and $Name -notmatch "^('|"").*\1$") {
            $Name = "'$Name'"
        }

        if ($Compress) {
            $Open = "$Name="
        }
        else {
            $Open = "$Name = "
        }
    }
    else {
        $Open = ""
    }

    if ($null -eq $Object) {
        $FullType = "NULL"
    }
    else {
        $FullType = $Object.GetType().FullName
    }

    if ($FullType -match "\[\]$" -or $Object -is [System.Collections.ArrayList]) {
        if ($FullType -match "^System\.Object") {
            $Open += "@("
            $Close = ")"
        }
        else {
            $Open += "[$($FullType)] @("
            $Close = ")"
        }

        if ($Compress) {
            $JoinChar = ","
        }
        else {
            $JoinChar = ", "
        }

        $Multiline = $false
        $StrElements = @()
        foreach ($Elem in $Object) {
            $StrElem = ConvertTo-PSData -Object $Elem -Compress:$Compress

            if ($Elem -is [System.Object[]]) {
                $StrElem = "," + $StrElem
            }

            $StrElements += $StrElem
            if (!$Multiline -and $StrElem -match '\n') {
                $Multiline = $true
            }
        }

        if (!$Compress -and $Multiline) {
            $JoinChar += "`r`n"
            $StrElements = @($Open) +
            (($StrElements | & { process {
                        $Parts = $_ -split "\r\n"
                        ($Parts | & { process { " " * 4 + $_ } }) -join "`r`n"
                    } }) -join $JoinChar) +
            $Close
            $StrElements | & { process {
                    $Parts = $_ -split "`r`n"
                    ($Parts | & { process { " " * $IndentLevel * 4 + $_ } }) -join "`r`n"
                } }
        }
        else {
            if ($Compress) {
                $Open + ($StrElements -join $JoinChar) + $Close
            }
            else {
                " " * $IndentLevel * 4 + $Open + ($StrElements -join $JoinChar) + $Close
            }
        }
    }
    else {
        switch ($FullType) {
            "NULL" {
                if ($Compress) {
                    $Open + '$null'
                }
                else {
                    " " * $IndentLevel * 4 + $Open + '$null'
                }
                break
            }

            "System.Collections.Hashtable" {
                $Open += "@{"

                if ($Compress) {
                    $Out = @($Open)
                }
                else {
                    $Out = @(" " * $IndentLevel * 4 + $Open)
                }

                foreach ($Key in $Object.Keys) {
                    $Out += ConvertTo-PSData -Object $Object.$Key -IndentLevel ($IndentLevel + 1) -Name $Key -Compress:$Compress
                }

                if ($Compress) {
                    "$($Out[0])" + ($Out[1..($Out.Count - 1)] -join ";") + "}"
                }
                else {
                    $Out += " " * $IndentLevel * 4 + "}"
                    $Out -join "`r`n"
                }
                break
            }

            "System.Collections.Specialized.OrderedDictionary" {
                if ($Compress) {
                    $Open += "[ordered]@{"
                    $Out = @($Open)
                }
                else {
                    $Open += "[ordered] @{"
                    $Out = @(" " * $IndentLevel * 4 + $Open)
                }

                foreach ($Key in $Object.Keys) {
                    $Out += ConvertTo-PSData -Object $Object.$Key -IndentLevel ($IndentLevel + 1) -Name $Key -Compress:$Compress
                }

                if ($Compress) {
                    "$($Out[0])" + ($Out[1..($Out.Count - 1)] -join ";") + "}"
                }
                else {
                    $Out += " " * $IndentLevel * 4 + "}"
                    $Out -join "`r`n"
                }
                break
            }

            "System.String" {
                if ($Compress) {
                    $Open + "'$Object'"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "'$Object'"
                }
                break
            }

            "System.Char" {
                if ($Compress) {
                    $Open + "[char]'$Object'"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[char] '$Object'"
                }
                break
            }

            "System.Version" {
                if ($Compress) {
                    $Open + "[version]'$Object'"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[version] '$Object'"
                }
                break
            }

            "System.Management.Automation.ScriptBlock" {
                if ($Compress) {
                    $Open + "{$Object}"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "{$Object}"
                }
                break
            }

            "System.DateTime" {
                if ($Compress) {
                    $Open + "[DateTime]'$(Get-Date -Date $Object -Format 'yyyy.MM.dd HH:mm:ss')'"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[DateTime] '$(Get-Date -Date $Object -Format 'yyyy.MM.dd HH:mm:ss')'"
                }
                break
            }

            "System.TimeSpan" {
                if ($Compress) {
                    $Open + "[TimeSpan]'$Object'"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[TimeSpan] '$Object'"
                }
                break
            }

            "System.Byte" {
                if ($Compress) {
                    $Open + "[byte]$Object"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[byte] $Object"
                }
                break
            }

            "System.Int16" {
                if ($Compress) {
                    $Open + "[System.Int16]$Object"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[System.Int16] $Object"
                }
                break
            }

            "System.Int32" {
                if ($Compress) {
                    $Open + "$Object"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "$Object"
                }
                break
            }

            "System.Int64" {
                if ($Compress) {
                    $Open + "[System.Int64]$Object"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[System.Int64] $Object"
                }
                break
            }

            "System.UInt16" {
                if ($Compress) {
                    $Open + "[System.UInt16]$Object"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[System.UInt16] $Object"
                }
                break
            }

            "System.UInt32" {
                if ($Compress) {
                    $Open + "[System.UInt32]$Object"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[System.UInt32] $Object"
                }
                break
            }

            "System.UInt64" {
                if ($Compress) {
                    $Open + "[System.UInt64]$Object"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[System.UInt64] $Object"
                }
                break
            }

            "System.Decimal" {
                if ($Compress) {
                    $Open + "[System.Decimal]$Object"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[System.Decimal] $Object"
                }
                break
            }

            "System.Double" {
                if ($Compress) {
                    $Open + "[System.Double]$Object"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[System.Double] $Object"
                }
                break
            }

            "System.Single" {
                if ($Compress) {
                    $Open + "[System.Single]$Object"
                }
                else {
                    " " * $IndentLevel * 4 + $Open + "[System.Single] $Object"
                }
                break
            }

            "System.Management.Automation.PSCustomObject" {

                if ($Compress) {
                    $Open += "[PSCustomObject]@{"
                    $Out = @($Open)
                }
                else {
                    $Open += "[PSCustomObject] @{"
                    $Out = @(" " * $IndentLevel * 4 + $Open)
                }

                foreach ($Prop in $Object.PSObject.Properties.Name) {
                    $Out += ConvertTo-PSData -Object $Object.$Prop -IndentLevel ($IndentLevel + 1) -Name $Prop -Compress:$Compress
                }

                if ($Compress) {
                    "$($Out[0])" + ($Out[1..($Out.Count - 1)] -join ";") + "}"
                }
                else {
                    $Out += " " * $IndentLevel * 4 + "}"
                    $Out -join "`r`n"
                }
                break
            }

            "System.Boolean" {
                if ($Object -eq $true) {
                    if ($Compress) {
                        $Open + '$true'
                    }
                    else {
                        " " * $IndentLevel * 4 + $Open + '$true'
                    }
                }
                else {
                    if ($Compress) {
                        $Open + '$false'
                    }
                    else {
                        " " * $IndentLevel * 4 + $Open + '$false'
                    }
                }
                break
            }

            default {
                $NameInMessage = $Name

                if (!$Name) {
                    $NameInMessage = Get-Variable -Name Name -ValueOnly -Scope 1 -ErrorAction Ignore
                }

                throw "Couldn't convert datatype at '$NameInMessage' : '$($Object.GetType().FullName)' - $Object"
            }
        }
    }
}

<#
.SYNOPSIS
    Exports objects to PSData files.
.DESCRIPTION
    Converts objects to PSData format and saves them to .data.ps1 files.
    Wrapper around ConvertTo-PSData with file writing functionality.
#>
function Export-PSData {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)] $Object,
        [Parameter(ValueFromPipeline = $false)] $Path
    )

    $PSDataString = ConvertTo-PSData -Object $Object
    Set-Content -Value $PSDataString -Path $Path -Encoding Default
}

<#
.SYNOPSIS
    Converts PSData format strings back to objects.
.DESCRIPTION
    Deserializes PSData literal syntax strings back into PowerShell objects.
    Inverse operation of ConvertTo-PSData.
#>
function ConvertFrom-PSData {
    param(
        [Parameter(ValueFromPipeLine = $true)] [string] $PSDataString
    )
    begin {
        $AllStrings = @()
    }
    process {
        $AllStrings += $PSDataString
    }
    end {
        if (!$AllStrings -or $AllStrings.Trim() -notmatch "^(\[ordered\]\s*)?@\{") {
            $Embed = $true
            $PSDataString = "@{PSDataEmbedding = $($PSDataString)}"
        }

        $ExportFile = Join-Path $env:TEMP 'tempPS.data.ps1'
        Set-Content -Path $ExportFile -Value $PSDataString
        $TempPSData = @{}
        Import-PSData -PathsOrNames $ExportFile -PSData $TempPSData
        Remove-Item -Path $ExportFile

        if ($Embed) {
            return $TempPSData.PSDataEmbedding
        }

        return $TempPSData
    }
}
#endregion PSData management

#region Miscellaneous functions

<#
.SYNOPSIS
    Creates dynamic parameters for PowerShell functions.
.DESCRIPTION
    Generates runtime-defined parameters with validation sets, conditions, and default values.
    Utility function for advanced parameter handling in PowerShell functions.
#>
function New-DynamicParameter {
    param(
        [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Mandatory = $true)] [string] $Name,
        [Parameter(ValueFromPipelineByPropertyName = $true)] [type]   $Type,
        [Parameter(ValueFromPipelineByPropertyName = $true)] [string[]] $ParameterSetName = "Default",
        [Parameter(ValueFromPipelineByPropertyName = $true)] $Mandatory,
        [Parameter(ValueFromPipelineByPropertyName = $true)] [scriptblock] $ValidationSet,
        [Parameter(ValueFromPipelineByPropertyName = $true)] [switch] $ValueFromPipeline,
        [Parameter(ValueFromPipelineByPropertyName = $true)] [switch] $ValueFromPipelineByPropertyName,
        [Parameter(ValueFromPipelineByPropertyName = $true)] $DefaultValue,
        [Parameter(ValueFromPipelineByPropertyName = $true)] [scriptblock] $Condition,
        [Parameter(ValueFromPipelineByPropertyName = $true)] [string[]] $Aliases,
        [int] $StartPosition = 0
    )
    begin {
        $ParamDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
        $Position = $StartPosition
    }
    process {
        if ($null -eq $Condition -or (&$Condition)) {
            $AttributeCollection = New-Object -TypeName System.Collections.ObjectModel.Collection[Attribute]

            foreach ($Psn in $ParameterSetName) {
                $Attribute = New-Object -TypeName System.Management.Automation.ParameterAttribute
                $Attribute.ParameterSetName = $Psn
                if ($PSBoundParameters.ContainsKey('startposition')) {
                    $Attribute.Position = $Position
                    $Position++
                }
                if ($Mandatory -is [scriptblock]) {
                    $Attribute.Mandatory = &$Mandatory
                }
                else {
                    $Attribute.Mandatory = $Mandatory
                }
                $Attribute.ValueFromPipeline = $ValueFromPipeline
                $Attribute.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName

                $AttributeCollection.Add($Attribute)
            }

            if ($ValidationSet) {
                $Vsa = New-Object -TypeName System.Management.Automation.ValidateSetAttribute -ArgumentList (&$ValidationSet)
                $Attribute.HelpMessage = "Possible values: $((&$ValidationSet) -join ', ')"
                $AttributeCollection.Add($Vsa)
            }

            if ($Aliases) {
                $Alias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList $Aliases
                $AttributeCollection.Add($Alias)
            }

            $Param = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList $Name, $Type, $AttributeCollection

            # Troubleshooting: It could be useful to temporarily store bound parameters
            # $global:psb = $PSBoundParameters

            if ($PSBoundParameters.ContainsKey('defaultValue') -and $null -ne $DefaultValue) {
                $CS = @(Get-PSCallStack)
                if ($DefaultValue -is [scriptblock]) {
                    $Param.Value = &$DefaultValue
                    $CS[1].InvocationInfo.BoundParameters.$Name = $Param.Value
                }
                else {
                    $Param.Value = $DefaultValue
                    $CS[1].InvocationInfo.BoundParameters.$Name = $DefaultValue
                }
            }
            $ParamDictionary.Add($Name, $Param)
        }
    }
    end {
        $ParamDictionary
    }
}

<#
.SYNOPSIS
    Searches PowerShell script files for patterns.
.DESCRIPTION
    Advanced search functionality for PowerShell scripts using AST (Abstract Syntax Tree) parsing
    or regex patterns. Can search in code elements like functions, variables, commands, or plain text.
#>
function Search-Script {
[CmdletBinding()]
param(
    [string] $Pattern,
    [Parameter(ValueFromPipeLine = $true, ValueFromPipelineByPropertyName = $true)][Alias('FullName')][string[]] $Path,
    [string[]] $Extension = ("ps1", "psm1"),
    [string[]] $Exclude = "wxyz",
    [string[]] $ExcludePath,
    [switch] $SortByDate,
    [switch] $CaseSensitive,
    [switch] $IncludeAll,
    [switch] $FirstLine,
    [int] $MaxLines = [int]::MaxValue
)
dynamicParam{
    $global:paramDef_ElementType | New-DynamicParameter
}
end{
    if(!$Path){
        if($allPowerShellFiles){
            $Path = $allPowerShellFiles.FullName
        }
        else{
            $Path = "."
        }
    }

    $elementType = $PSBoundParameters.ElementType

    if($Extension -ne "*"){
        $include = $Extension | ForEach-Object {$_ -replace "^(\*)?(\.)?","*." }
    }

    $Exclude = $Exclude | ForEach-Object {$_ -replace "^(\*)?(\.)?","*." }

    $selectedFiles = @()

    if($elementType -eq 'FileName'){
        foreach($p in $Path){
            Get-ChildItem -Path $p -Include $include -Exclude $Exclude -Recurse | &{process {
                    $dir = $_.DirectoryName
                    if(!($ExcludePath | &{process{if($dir -like $_){$_}}}) -and $_.name -match $Pattern){
                        Select-Object -Property FullName, LastWriteTime, LineNumber, Line -InputObject $_
                    }
                }}
        }
        return
    }

    if($Path[0] -is [string] -or $Path[0] -is [System.IO.DirectoryInfo]){
        foreach($p in $Path){
            $selectedFiles += Get-ChildItem -Path $p -Include $include -Exclude $Exclude -Recurse | &{process {
                    $dir = $_.DirectoryName
                    if(!($ExcludePath | &{process{if($dir -like $_){$_}}})){
                        $_
                    }
                }}
        }
    }
    else{
        $selectedFiles += $Path | &{process {
                    $dir = $_.DirectoryName
                    $file = $_.name
                    if(($include | &{process{if($file -like $_){$_}}}) -and !($ExcludePath | &{process{if($dir -like $_){$_}}}) -and !($ExcludePath | &{process{if($dir -like $_){$_}}})){
                        $_
                    }
                }}
    }

    if($elementType -eq 'String'){
        $SelectStringSplatting = @{}
        if($CaseSensitive){
            $SelectStringSplatting.CaseSensitive = $true
        }

        $SortParam = "Path", "LineNumber"
    }
    elseif($elementType -ne 'Comment'){
        $notPart = ""

        if($CaseSensitive){
            $Pattern = "(?-i)$Pattern"
        }

        if($IncludeAll -and $Global:astTypes.$elementType.NotPart){
            $notPart = "-and (!`$args[0].Parent -or `$args[0].Parent.GetType().fullname -ne ""System.Management.Automation.Language.$($Global:astTypes.$elementType.NotPart)Ast"")"
        }

        if($Global:astTypes.$elementType.ContainsKey('TypeOverride')){
            $queryStr = "`$args[0].GetType().fullname -eq ""System.Management.Automation.Language.$($Global:astTypes.$elementType.TypeOverride)Ast"" $notPart -and
                            (Get-Property -Object `$args[0] -PropertyPath $($Global:astTypes.$elementType.PropName -join ', ')).Value -match '$Pattern'"
        }
        else{
            $queryStr = "`$args[0].GetType().fullname -eq ""System.Management.Automation.Language.$($elementType)Ast"" $notPart -and
                            (Get-Property -Object `$args[0] -PropertyPath $($Global:astTypes.$elementType.PropName -join ', ')).Value -match '$Pattern'"
        }

        if($Global:astTypes.$elementType.ContainsKey('AdditionalCriteria')){
            $queryStr += " -and $($Global:astTypes.$elementType.AdditionalCriteria)"
        }

        if($Global:astTypes.$elementType.ContainsKey('Or')){
            $queryStr = "($queryStr) -or ($(& $Global:astTypes.$elementType.Or))"
        }

        $query = [scriptblock]::Create($queryStr)

        $SortParam = "Path", {if($_.LineNumber -match "-"){"  "}else{$_.LineNumber}}
    }

    if($SortByDate){
        $SortParam = @(@{e = {$_.LastWriteTime}; ascending = $false}) + $SortParam
    }

    $keepForSort = @()

    foreach($psf in $selectedFiles){
        if($elementType -ne 'String'){
            $tokens = [System.Management.Automation.Language.Token[]]::New(1)
            $errors = [System.Management.Automation.Language.ParseError[]]::New(1)

            $AST = [System.Management.Automation.Language.Parser]::ParseFile(
                $psf.fullname,
                [ref] $tokens,
                [ref] $errors
            )

            if($elementType -eq 'Comment'){
                $SelectStringSplatting = @{}

                if($CaseSensitive){
                    $SelectStringSplatting.CaseSensitive = $true
                }

                $SortParam = "Path", "LineNumber"

                $tokens | &{process{
                    if($_.kind -eq 'Comment' -and (
                            $res = $_.Extent.Text -split "\r?\n" | Select-String -Pattern $Pattern @SelectStringSplatting -Encoding default
                        )){
                            foreach($r in $res){
                                $return = [PSCustomObject]@{
                                        Path = $_.Extent.File
                                        LastWriteTime = $psf.LastWriteTime
                                        LineNumber = ($_.Extent.StartLineNumber + $r.LineNumber - 1)
                                        Line = $r.line
                                    }

                                    if(!$SortByDate){
                                        $return
                                    }
                                    else{
                                        $keepForSort += $return
                                    }
                            }
                        }
                }}
            }
            else{
                $toAdd = @($AST.FindAll($query, $true))
                foreach($ta in $toAdd){
                    $expression = if($ta.GetType().fullname -match 'VariableExpression'){
                                        if($ta.Parent.GetType().fullname -notmatch 'AssignmentStatement'){
                                            ($ast.Extent.Text -split "\r?\n")[$ta.Extent.StartLineNumber - 1].trim()
                                        }
                                        else{
                                            $ta.Parent.Extent.Text
                                        }
                                    }
                                    else{
                                        $currentBlock = $ta

                                        while($currentBlock.Parent -and ($currentBlock.Parent.Extent.StartLineNumber -eq $ta.Extent.StartLineNumber -or $currentBlock.Parent.Extent.EndLineNumber -eq $ta.Extent.StartLineNumber)){
                                            $currentBlock = $currentBlock.Parent
                                        }

                                        $ta.Extent.Text
                                    }

                    $expression = $expression -split '\r?\n'

                    $currentMaxLines = $MaxLines

                    for($i = 0; $i -lt $expression.count -and $currentMaxLines -gt 0; $i++){
                        $currentMaxLines--

                        $return = [PSCustomObject]@{
                                        Path = $ta.Extent.File
                                        LastWriteTime = $psf.LastWriteTime
                                        LineNumber = if($i -eq 0){$ta.Extent.StartLineNumber.toString().PadLeft(10,'-')}else{" +" + $i.ToString().PadLeft(8)}
                                        Line = $expression[$i]
                                    }

                        if(!$SortByDate){
                            $return
                        }
                        else{
                            $keepForSort += $return
                        }

                        if($FirstLine){
                            break
                        }
                    }
                }
            }
        }
        else{
            $return = $psf | Select-String -Pattern $Pattern @SelectStringSplatting -Encoding default |
                Select-Object -Property Path, @{n="LastWriteTime"; e = {(get-item -Path $_.Path).LastWriteTime}}, LineNumber, Line

            if($SortByDate){
                $keepForSort += $return
            }
            else{
                $return
            }
        }
    }

    if($keepForSort){
        $keepForSort | Sort-Object -Property $SortParam
    }
}
}

$astTypes = @{
    'AssignmentStatement' = @{
                                PropName = 'Left.VariablePath.UserPath', 'Left.Target.VariablePath.UserPath', 'Left.Child.VariablePath.UserPath', 'Left.Expression.VariablePath.UserPath', 'Left.Child.Child.VariablePath.UserPath'
                                File = 'Extent.File'
                                Line = 'Extent.StartLineNumber'
                                Or = {"`$args[0].GetType().fullname -eq 'System.Management.Automation.Language.ParameterAst' -and `$args[0].Name -match '$pattern' -and `$args[0].DefaultValue"}
                            }

    'Command' = @{
                                PropName = 'CommandElements[0].Value'
                                File = 'Extent.File'
                                Line = 'Extent.StartLineNumber'
                            }

    'ScriptInvocation' = @{
                                PropName = 'CommandElements[0].Value'
                                AdditionalCriteria = '($args[0].InvocationOperator -eq "Dot" -or $args[0].InvocationOperator -eq "Ampersand")'
                                File = 'Extent.File'
                                Line = 'Extent.StartLineNumber'
                                TypeOverride = 'Command'
                            }

    'FunctionDefinition' = @{
                                PropName = 'Name'
                                File = 'Extent.File'
                                Line = 'Extent.StartLineNumber'
                            }

    'VariableExpression' = @{
                                PropName = 'Extent.Text'
                                File = 'Extent.File'
                                Line = 'Extent.StartLineNumber'
                                NotPart = "AssignmentStatement"
                            }

    'Parameter' = @{
                                PropName = 'Name.VariablePath.UserPath'
                                File = 'Extent.File'
                                Line = 'Extent.StartLineNumber'
                            }

    'Comment'   = "Custom"

    'String'    = "Custom"

    'FileName'  = "Custom"
}

$paramDef_ElementType = [PSCustomObject]@{
            Name = 'ElementType'
            Type = [string]
            ValidationSet = {[string[]] $astTypes.Keys}
            DefaultValue = 'String'
        }

<#
.SYNOPSIS
    Converts between PSCustomObject and Hashtable types.
.DESCRIPTION
   This function takes all properties or keys of the Secondary object / hashtable into the Primary object or hashtable. By default only those properties / keys are merge that doesn't exist in the Primary object / hashtable.
   If the -Force switch is used then the properties / keys of the Secondary object / hashtable always merged to the Primary.
.EXAMPLE
    $o = @{ObjProp = [PSCustomObject] @{Prop1 = 1; Prop2 = 2}; HashProp = @{Key1 = 1; Key2 = 2}}; $Result = Convert-CustomObjectHash -Object $o

    Because parameter -To is not specified, the conversion will be from [PSCustomObject] to [hashtable], including all properties that are also [PSCustomObject].
.EXAMPLE
    $o = @{ObjProp = [PSCustomObject] @{Prop1 = 1; Prop2 = 2}; HashProp = @{Key1 = 1; Key2 = 2}}; $Result = Convert-CustomObjectHash -Object $o -to PSCustomObject

    Because the -To parameter is [PSCustomObject], only the HashProp of the input object will be converted to [PSCustomObject].
.INPUTS
   hashtables or PSCustomObjects
.OUTPUTS
   The converted input object
#>
function Convert-CustomObjectHash {
    [CmdletBinding()]
    param(
        # Object to convert.
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][AllowNull()] [object]$Object,
        # Force conversion to this datatype.
        [Parameter()] [ValidateSet('hashtable', 'PSCustomObject')] [AllowNull()] [string] $To,
        # Recursion depth, by default 5.
        [Parameter()][int] $Depth = 5,
        [Parameter(DontShow = $true)][int] $CurrentDepth = 0
    )
    process {
        if ($null -eq $Object) {
            return
        }

        if ($Object -isnot [System.Collections.IDictionary]) {
            return $Object
        }

        if ($CurrentDepth -gt $Depth) {
            return
        }

        if (!$PSBoundParameters.To) {
            if ($Object -is [System.Collections.IDictionary]) {
                $To = 'PSCustomObject'
            }
            elseif ($Object -is [System.Management.Automation.PSCustomObject]) {
                $To = 'hashtable'
            }
            else {
                return
            }
        }

        if ($To -eq 'hashtable') {
            $NewObject = @{}

            foreach ($Prop in $Object.PSObject.Properties) {
                $NewObject.($Prop.Name) = Convert-CustomObjectHash -Object $Prop.Value -To $To -CurrentDepth ($CurrentDepth + 1) -Depth $Depth
            }
            $NewObject
        }
        elseif ($To -eq 'PSCustomObject') {
            $Object = [PSCustomObject] $Object
            foreach ($Prop in $Object.PSObject.Properties) {
                $Object.($Prop.Name) = Convert-CustomObjectHash -Object $Prop.Value -To $To -CurrentDepth ($CurrentDepth + 1) -Depth $Depth
            }
            $Object
        }
    }
}

<#
.SYNOPSIS
    Updates configuration based on environment settings.
.DESCRIPTION
    Modifies global PSConfig by changing the environment setting and re-importing
    PSData configuration. Part of the configuration management system.
#>
Function Update-Config {
    param(
        [Parameter(Mandatory = $true)][string] $Environment,
        [Parameter(Mandatory = $true)]$Prefix
    )

    if ($PSBoundParameters.ContainsKey("Environment") -or !$global:PSConfig.ContainsKey("$($Prefix)Environment")) {
        $global:PSConfig."$($Prefix)Environment" = $Environment
    }

    if ((Get-Variable -Name PSConfig -Scope Global -ErrorAction Ignore) -and $global:PSConfig -is [System.Collections.IDictionary] -and $global:PSConfig.ContainsKey("$($Prefix)Config")) {
        $global:PSConfig.Remove("$($Prefix)Config")
    }
    Import-PSData -PSData $global:PSConfig
}
#endregion Miscellaneous functions

#region Property management

<#
.Synopsis
Updates properties of objects or values of hashtables.
.DESCRIPTION
This function creates or sets properties of objects or values of hashtables. If a property or key doesn't exist then the function will create that and assign the given value to it.
If the property or key exists then - depending on the type of its value - it's going to do one of the following actions:
- if the existing value is an integer and the new value is an integer then it adds the new value to the existing one
- in other cases the function converts the existing value to a collection if it's not already that and adds the new value as a new element to that collection. If the new value is already
among the existing elements then it will skip adding the new element to it.
- if the -Force switch is used then the existing value is going to be overwritten by the new value.

This function is meant to extend the scope and functionality of Add-Member.
.EXAMPLE
$Splatting = @{}; Update-Property -Object $Splatting -PropName DisplayName -Value 'Tibor Soos'; Update-Property -Object $Splatting -PropName Replace -Value @{proxyAddresses = "SMTP:Soos.Tibor@hotmail.com"}

In this example we prepare a hashtable $Splatting for splatting the Set-ADUser cmdlet to set the DisplayName and the proxyAddresses attribute of an AD user object.
.EXAMPLE
Update-Property -Object $Splatting -PropName Replace -Value @{proxyAddresses = "smtp:SoosTibor@hotmail.com"} ; $Splatting.Replace

In this example we add a secondary SMTP address to the splatting hashtable under its Replace key.
.EXAMPLE
Update-Property -Object $Splatting.Replace -PropName proxyAddresses -Value "smtp:tibor.soos@hotmail.com" -PassThru

In this example we add another secondary SMTP address to the splatting hashtable directly under its Replace.proxyAddresses key. Using the -PassThru switch we get back the updates hashtable under the Replace key.
.EXAMPLE
$Obj = [PSCustomObject] @{Prop1 = "Text"; Prop3 = "Obsolete"}; Update-Property -Object $Obj -PropName Prop2; Update-Property -Object $Obj -PropName Prop3 -Value Fresh -Force; Update-Property -Object $Obj -PropName Prop1 -Value NewText -PassThru

In this example we update an object in $Obj 3 times. First we create a new property Prop2, then we overwrite the property 'Prop3' to 'Fresh', then we extend the existing value of Prop1 by converting it to a collection and adding 'NewText' to it as a new element.
.INPUTS
hashtable or PSObject
.OUTPUTS
The updated input object if the -PassThru switch is used.
#>
function Update-Property {
    [CmdletBinding()]
    param(
        # Input object, either a hashtable or a PSObject
        [PSObject] $Object,
        # Name of the property or key to update
        [string]   $PropertyPath,
        # Do not expand dots (.) in -PropertyPath
        [switch] $LiteralPropertyName,
        # The new value to include in the update process. By default it's 1.
        [PSObject] $Value = 1,
        # Switch to output the update input object
        [switch]   $PassThru,
        # Switch to do an overwrite
        [switch]   $Force,
        [Parameter(DontShow = $true)] $ObjectToReturn = $Object
    )
    if (!$LiteralPropertyName -and $PropertyPath -match '\.|\[\w+\](?=(\.|$))') {
        $NextProp, $PropertyPath = $PropertyPath -split '\.|(?=\[\w+\]$)', 2

        if ($NextProp) {
            $NextObj = $Object.$NextProp
            Update-Property -Object $NextObj -PropertyPath $PropertyPath -Value $Value -PassThru:$PassThru -Force:$Force -objectToReturn $ObjectToReturn
            return
        }
    }

    $Index = $null

    if ($PropertyPath -match '^\[(\w+)\]$') {
        if ($Matches[1] -as [int]) {
            $Index = [int] $Matches[1]

            if ($Object -is [Collections.IList]) {
                $PropertyPath = $null
                if ($Object.Count -le $Index) {
                    if ($ErrorActionPreference -ne 'Ignore') {
                        Write-Error "Index property is out of range"
                    }
                    return
                }
            }
            else {
                $PropertyPath = $Index
                $Index = $null
            }
        }
        else {
            $PropertyPath = $Matches[1]
        }
    }

    $PropertyPath = $PropertyPath -replace '^[''"]|[''"]$'

    if ($null -eq $Object) {
        if ($ErrorActionPreference -ne 'Ignore') {
            Write-Error "No object"
        }
        return
    }

    if ($Object -is [hashtable] -and !$Object.ContainsKey($PropertyPath)) {
        $Object.$PropertyPath = $Value
    }
    elseif ($Object -isnot [hashtable] -and $Object -isnot [System.Collections.IList] -and $Object.PSObject.Properties.Name -notcontains $PropertyPath) {
        Add-Member -InputObject $Object -MemberType NoteProperty -Name $PropertyPath -Value $Value
    }
    elseif ($Force) {
        if ($null -eq $Index) {
            $Object.$PropertyPath = $Value
        }
        else {
            $Object[$Index] = $Value
        }
    }
    else {
        if ($null -eq $Index) {
            if ($Object.$PropertyPath -is [int] -and $Value -is [int]) {
                $Object.$PropertyPath += $Value
            }
            elseif ($Object.$PropertyPath -is [string]) {
                if ($Value -ne $Object.$PropertyPath) {
                    $Object.$PropertyPath = @($Object.$PropertyPath) + $Value
                }
            }
            elseif ($Object.$PropertyPath -is [Collections.IList]) {
                if ($Object.$PropertyPath.Count -gt 0 -and $Object.$PropertyPath[0] -is [hashtable]) {
                    if ($Value -is [Collections.IList] -and $Value.Count -gt 0 -and $Value[0] -is [hashtable]) {
                        $ExistingKeys = $Object.$PropertyPath | & { process { $_.Keys } }

                        if ($ExistingKeys -notcontains ($Value | & { process { $_.Keys } })) {
                            $Object.$PropertyPath += $Value
                        }
                        else {
                            foreach ($v in $Value) {
                                $EqualFound = $null

                                for ($i = 0; $i -lt $Object.$PropertyPath.Count; $i++) {
                                    $DiffFound = $false
                                    foreach ($k in $o.Keys) {
                                        if ($v.$k -ne $v.$k) {
                                            $DiffFound = $true
                                            break
                                        }
                                    }
                                    if (!$DiffFound) {
                                        $EqualFound = $i
                                        break
                                    }
                                }

                                if ($null -ne $EqualFound) {
                                    $Object.$PropertyPath += $v
                                }
                                else {
                                    $Object.$PropertyPath[$EqualFound] = $v
                                }
                            }
                        }
                    }
                }
                else {
                    $ToAdd = @()
                    foreach ($Elem in $Value) {
                        if ($Object.$PropertyPath -notcontains $Elem) {
                            $ToAdd += $Elem
                        }
                    }

                    if ($ToAdd) {
                        if ($Object.$PropertyPath -is [System.Collections.ArrayList]) {
                            $Object.$PropertyPath.AddRange($ToAdd)
                        }
                        else {
                            $Object.$PropertyPath += $ToAdd
                        }
                    }
                }
            }
            elseif ($Object.$PropertyPath -is [System.Collections.Hashtable] -and $Value -is [System.Collections.Hashtable]) {
                $Keys = [object[]] $Value.Keys
                foreach ($Key in $Keys) {
                    if ($Object.$PropertyPath.ContainsKey($Key)) {
                        if ($Object.$PropertyPath.$Key -notcontains $Value.$Key) {
                            if ($null -ne $Object.$PropertyPath.$Key) {
                                $Object.$PropertyPath.$Key = @($Object.$PropertyPath.$Key) + $Value.$Key
                            }
                            else {
                                $Object.$PropertyPath.$Key = $Value.$Key
                            }
                        }
                    }
                    else {
                        $Object.$PropertyPath.$Key = $Value.$Key
                    }
                }
            }
            elseif ($null -eq $Object.$PropertyPath) {
                $Object.$PropertyPath = $Value
            }
            else {
                $Object.$PropertyPath = @($Object.$PropertyPath) + $Value
            }
        }
        else {
            if ($Object[$Index] -is [int] -and $Value -is [int]) {
                $Object[$Index] += $Value
            }
            elseif ($Object[$Index] -is [string]) {
                if ($Value -ne $Object[$Index]) {
                    $Object[$Index] = @($Object[$Index]) + $Value
                }
            }
            elseif ($Object[$Index] -is [Collections.IList]) {
                if ($Object[$Index].Count -gt 0 -and $Object[$Index][0] -is [hashtable]) {
                    if ($Value -is [Collections.IList] -and $Value.Count -gt 0 -and $Value[0] -is [hashtable]) {
                        $ExistingKeys = $Object[$Index] | & { process { $_.Keys } }

                        if ($ExistingKeys -notcontains ($Value.Keys | & { process { $_.Keys } })) {
                            $Object[$Index] += $Value
                        }
                        else {
                            foreach ($v in $Value) {
                                $EqualFound = $null

                                for ($i = 0; $i -lt $Object[$Index].Count; $i++) {
                                    $DiffFound = $false
                                    foreach ($k in $o.Keys) {
                                        if ($v.$k -ne $v.$k) {
                                            $DiffFound = $true
                                            break
                                        }
                                    }
                                    if (!$DiffFound) {
                                        $EqualFound = $i
                                        break
                                    }
                                }

                                if ($null -ne $EqualFound) {
                                    $Object[$Index] += $v
                                }
                                else {
                                    $Object[$Index][$EqualFound] = $v
                                }
                            }
                        }
                    }
                }
                else {
                    $ToAdd = @()
                    foreach ($Elem in $Value) {
                        if ($Object.$PropertyPath -notcontains $Elem) {
                            $ToAdd += $Elem
                        }
                    }

                    if ($ToAdd) {
                        if ($Object.$PropertyPath -is [System.Collections.ArrayList]) {
                            $Object.$PropertyPath.AddRange($ToAdd)
                        }
                        else {
                            $Object.$PropertyPath += $ToAdd
                        }
                    }
                }
            }
            elseif ($Object[$Index] -is [System.Collections.Hashtable] -and $Value -is [System.Collections.Hashtable]) {
                $Keys = [object[]] $Value.Keys
                foreach ($Key in $Keys) {
                    if ($Object[$Index].ContainsKey($Key)) {
                        if ($Object[$Index].$Key -notcontains $Value.$Key) {
                            if ($null -ne $Object[$Index].$Key) {
                                $Object[$Index].$Key = @($Object[$Index].$Key) + $Value.$Key
                            }
                            else {
                                $Object[$Index].$Key = $Value.$Key
                            }
                        }
                    }
                    else {
                        $Object[$Index].$Key = $Value.$Key
                    }
                }
            }
            elseif ($null -eq $Object[$Index]) {
                $Object.$PropertyPath = $Value
            }
            else {
                $Object[$Index] = @($Object[$Index]) + $Value
            }
        }
    }

    if ($PassThru) {
        $ObjectToReturn
    }
}

function Search-Property {
    <#
.Synopsis
   Searches for patterns in properties of objects or keys of hashtables.
.DESCRIPTION
   This function primarily searches the regex pattern among properties of objects or keys of hashtables. If the -SearchInPropertyNames is specified then it searches among property names / keys as well.
   If the -ExcludeValues switch is used then it skips the search in values of properties / keys.
   If we want a literal search and not a regex pattern matching then the -LiteralSearch switch can be used. If we want to restrict search in certain properties / keys, then we can specify those names at the -Property parameter.
   If the pattern is in the form of '<name>', the the function searches for all the properties / keys where the value matches the value of property / key with name 'name'.
   If we want to skip certain properties / keys, then we can specify those at the -ExcludeProperty parameter.
   By default the search is case insensitive, we can make it case sensitive by specifying the -CaseSensitive switch.
   By default the search is done among those properties / keys which contain a collection of values. To skip searching in those properties we can specify the -IgnoreCollections switch.
   By default the search goes into the immediate properties / keys of the input objects. We can specify the search depth by assigning a value to the -Depth parameter.
   The result contains custom objects having an 'Object' property which is meant to be an identifier of the input objects. That is by default the result of the ToString() method invoking on the input object.
   If we want to have that identifier of one of the properties of the input object then we can specify that property name / key in the -ObjectNameProp parameter.
.EXAMPLE
   Get-Item -Path C:\Windows\notepad.exe | Search-Property -Pattern '<basename>' -Depth 2 -ObjectNameProp name -CaseSensitive -IgnoreCollections

   In this example we search the base name of the notepad.exe file object (notepad) among its properties and the properties of properties (-Depth 2) in a case sensitive way, so the VersionInfo.OriginalFilename property is not returned, because there the value is NOTEPAD.EXE.MUI.
   The first column of the result set contain the name of the file (notepad.exe) and not the full path, because we specified that the object name should be taken from property 'name'.
.EXAMPLE
   @{One = "MyValue"; KeyTwo = 'One'; Coll = 'one', 'two'; KeyThree = @{SubKey1 = 'One'; SubKey2 = [PSCustomObject]@{Prop1 = 'One'; Prop2One = 'Text'}}} | Search-Property -Pattern '^One$' -SearchInPropertyNames -Depth 3 -IgnoreCollections

   In this example we search for the exact string 'One' among all the keys of the hashtable specified in the command line max 3 levels deep. We skip the key 'Coll', because that contains a collection and we specified the -IgnoreCollections switch. The result also contains property 'Prop1' of the object under the key 'SubKey2'.
.INPUTS
   hashtable or PSObject
.OUTPUTS
   Collection of custom objects having an Object, Name and Value properties.
#>
    [CmdletBinding()]
    param(
        # Regex pattern to search for
        [parameter(Position = 0)][string] $Pattern = ".",

        # Input object or hashtable
        [parameter(ValueFromPipeline)][PSObject] $Object,

        # Extend the search to include property / key names
        [switch] $SearchInPropertyNames,

        # Skip searching among property / key values
        [switch] $ExcludeValues,

        # Use the pattern as a literal search (no regex metacharacters)
        [switch] $LiteralSearch,

        # Property / key names to search in (by default all all properties / keys are included)
        [string[]] $Property = "*",

        # Property / key names to exclude to search in
        [string[]] $ExcludeProperty,

        # Take the identifier of the object / hashtable from this property / key
        [string] $ObjectNameProp,

        # Make the search case-sensitive
        [switch] $CaseSensitive,

        # Ignore properties / keys that contain collection of values
        [switch] $IgnoreCollections,

        # Depth of the recursive search, by default 1 - shallow search
        [int] $Depth = 1,
        [Parameter(DontShow = $true)] [int] $_Depth = 1,
        [Parameter(DontShow = $true)] [string[]] $_ParentNames,
        [Parameter(DontShow = $true)] [string] $_ObjectName
    )
    begin {
        if ($LiteralSearch -and $Pattern -ne ".") {
            $Pattern = [regex]::Escape($Pattern)
        }

        if ($CaseSensitive) {
            $Pattern = "(?-i)$Pattern"
        }

        $OrigPattern = $Pattern
        $Pipeline = $false

        if (!$_ObjectName -and !$ObjectNameProp) {
            $Parts = [scriptblock]::Create($MyInvocation.Line).Ast.FindAll({ $true }, $true)

            for ($i = 0; $i -lt $Parts.Count; $i++) {
                if ($Parts[$i].ParameterName -eq 'Object') {
                    $_ObjectName = $Parts[$i + 1].Extent.Text

                    if ($_ObjectName -notmatch '^\(.*\)$' -and ($_ObjectName -notmatch '^\$' -or ($Parts[$i + 1].staticType -match "\[\]$" -and $_ObjectName -notmatch "^\("))) {
                        $_ObjectName = "($_ObjectName)"
                    }
                    break
                }
            }

            if (!$_ObjectName -and $Parts[2].GetType().FullName -match 'PipelineAst') {
                $Pipeline = $true
            }

            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', 'existModuleName', Justification = 'variable is used in another scope')]
            $ExcludeType = $SkipTypesDefault + $SkipTypesAdditional | & { process { $_ -replace "\[", '[[' -replace "\]", ']]' } }

            if (!$_ObjectName) {
                if ($Pipeline) {
                    $_ObjectName = '$Input'
                }
                else {
                    $_ObjectName = '$Object'
                }
            }

            $ObjectCount = 0
        }
    }
    process {
        $Type = $Object.GetType().FullName
        foreach ($o in $Object) {
            if ($null -eq $o) {
                continue
            }

            if ($_ObjectName) {
                $ObjectName = $_ObjectName
                if ($Pipeline -or ($Object -is [System.Collections.IList]) -and $_Depth -eq 1) {
                    $ObjectName = $ObjectName -replace "(\[\d+\])?$" -replace '$', "[$ObjectCount]"
                    $ObjectCount++
                }
            }
            elseif ($ObjectNameProp) {
                $ObjectName = $o.$ObjectNameProp
            }
            else {
                $ObjectName = $o.ToString()
            }

            if (!$IgnoreCollections -and $o -is [Collections.IList]) {
                $Index = 0

                foreach ($Elem in $o) {
                    $ParentNames = "$($_ParentNames -join '.')[$Index]"

                    if ($Elem.ToString() -ne $Elem.GetType().FullName -and $Elem -match $Pattern) {
                        $Out = [PSCustomObject]@{
                            Object       = $ObjectName
                            PropertyPath = $ParentNames
                            Type         = $Type
                            Value        = $Elem
                        }

                        $Out.PSTypeNames.Insert(0, 'ScriptTools.Property.Expand')
                        $Out
                    }

                    Search-Property -Object $Elem -Pattern $OrigPattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property:$Property -ExcludeProperty:$ExcludeProperty -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -_ParentNames $ParentNames -_ObjectName $ObjectName
                    $Index++
                }
            }
            else {
                if (!$LiteralSearch -and $OrigPattern -match "<[^>]+>") {
                    $Pattern = [regex]::Replace($OrigPattern, "<([^>]+)>", { [regex]::Escape($o.($args[0].Value -replace "<|>")) })
                }

                if ($o -is [System.Collections.IDictionary]) {
                    $Properties = $o.GetEnumerator() | Select-Object -Property Name, Value
                }
                else {
                    $Properties = $o.PSObject.Properties
                }

                foreach ($Prop in ($Properties | Sort-Object -Property Name)) {
                    $PropName = $Prop.Name

                    if ($PropName -eq 'loop') {
                        $Dummy = 0
                    }

                    if (
                        $Prop.MemberType -ne 'AliasProperty' -and
                        (
                            $(if (!$ExcludeValues) { $Prop.Value -as [string] -and $Prop.Value.ToString() -ne $Prop.Value.GetType().FullName -and $Prop.Value -match $Pattern }) -or
                            $(if ($SearchInPropertyNames) { $Prop.Name -as [string] -and $Prop.Name -match $Pattern })
                        ) -and
                        !($ExcludeProperty | & { process { if ($PropName -like $_) { $_ } } }) -and
                        ($Property | & { process { if ($PropName -like $_) { $_ } } }) -and
                        (!$IgnoreCollections -or $Prop.Value -isnot [Collections.IList])
                    ) {
                        $PropFullName = ($_ParentNames + $PropName) -join "."
                        if ($null -ne $Prop.Value) {
                            $Type = $Prop.Value.GetType().FullName
                        }
                        else {
                            $Type = $null
                        }

                        $Out = [PSCustomObject]@{
                            Object       = $ObjectName
                            PropertyPath = $PropFullName
                            Type         = $Type
                            Value        = $Prop.Value
                        }

                        $Out.PSTypeNames.Insert(0, 'ScriptTools.Property.Expand')
                        $Out
                    }

                    if ($Prop.Value -and $Prop.Value.GetType().FullName -notin 'system.string', 'system.int32' -and $_Depth -lt $Depth) {
                        if ($Prop.Value -is [Collections.IList]) {
                            Search-Property -Object (, $Prop.Value) -Pattern $Pattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property $Property -ExcludeProperty $ExcludeProperty -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -_ParentNames ($_ParentNames + $PropName) -_ObjectName $ObjectName
                        }
                        elseif ($Prop.Value -is [System.Management.Automation.PSReference]) {
                            $Obj = [PSCustomObject] @{Value = $Prop.Value.Value }
                            Search-Property -Object $Obj -Pattern $Pattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property $Property -ExcludeProperty $ExcludeProperty -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -_ParentNames ($_ParentNames + $PropName) -_ObjectName $ObjectName
                        }
                        else {
                            Search-Property -Object $Prop.Value -Pattern $Pattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property $Property -ExcludeProperty $ExcludeProperty -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -_ParentNames ($_ParentNames + $PropName) -_ObjectName $ObjectName
                        }
                    }
                }
            }
        }
    }
}

<#
.Synopsis
Compares properties of objects or keys of hashtables.
.DESCRIPTION
This function compares properties of two objects or keys of two hashtables recursively and returns a set of custom objects describing the differences.
.EXAMPLE
$f1 = Get-Item C:\Windows\notepad.exe; $f2 = Get-Item C:\Windows\System32\notepad.exe; Compare-Property -ReferenceObject $f1 -DifferenceObject $f2

This expression compares the properties of 2 notepad.exe files and returns all properties that are different.
.EXAMPLE
$f1 = Get-Item C:\Windows\notepad.exe; $f2 = Get-Item C:\Windows\System32\notepad.exe; Compare-Property -ReferenceObject $f1 -DifferenceObject $f2 -IncludeEqual -ExcludeDifferent -Exclude PS*

In this example we compare the properties of the two notepad.exe file objects, exclude the properties that are different but include properties that are equal. We also exclude all properties whose name start with PS.
.EXAMPLE
Compare-Property -ReferenceObject @{Name = 'First'; Number = 1; Array = 1,2; RefEmpty = $null} -DifferenceObject @{Name = 'Second'; Number = 2; Array = 2,3; DiffEmpty = @()} -Hide Empty -NameProperty Name -Exclude Name

In this example we compare the keys of two hashtables. We exclude those properties that contain 'empty' values ($null, empty array, empty hashtables, System.DBNull) in either input objects.
We also include in the column names the content of the Name property of the respective hashtables, but exclude the Name property from the differences.
.INPUTS
hashtable or PSObject
.OUTPUTS
Collection of custom objects having a Property, Relation and 'r:<reference object ID>', 'd:<difference object ID>' properties.
#>
function Compare-Property {
    [CmdletBinding()]
    param(
        # The reference object or hashtable
        [Parameter(Mandatory = $true)] [AllowNull()][PSObject] $ReferenceObject,
        # The difference object or hashtable
        [Parameter(Mandatory = $true)] [AllowNull()][PSObject] $DifferenceObject,
        # Include equal properties/keys in the result
        [switch] $IncludeEqual,
        # Exclude differences from the result
        [switch] $ExcludeDifferent,
        # Include properties/keys to compare
        [string[]] $Property = "*",
        # Exclude properties/keys to compare
        [string[]] $Exclude,
        # Use this property or the result of executing the scriptblock as the name for the objects
        [ValidateScript({ $_ -is [string] -or $_ -is [scriptblock] })] [PSObject] $NameProperty,
        # Hide certain type of empty properties
        [string] [ValidateSet('None', 'Empty', 'NonEmpty', 'BothEmpty')] $Hide = 'None',
        [Parameter(DontShow = $true)][int] $_Depth = 1,
        # Maximum depth of recursion, default is 5
        [int] $MaxDepth = 5
    )

    $Equal = $null
    $RefObjName = ''
    $DifObjName = ''

    if ($null -eq $ReferenceObject -and $null -eq $DifferenceObject) {
        $RefObjName = '$null'
        $DifObjName = '$null'
        $Equal = "=="
    }
    elseif ($null -eq $ReferenceObject -or $null -eq $DifferenceObject) {
        if ($null -eq $ReferenceObject) {
            $RefObjName = '$null'
            $Equal = "=>"
        }
        else {
            $DifObjName = '$null'
            $Equal = "<="
        }
    }
    elseif ($ReferenceObject.GetType().FullName -ne $DifferenceObject.GetType().FullName -and $PSBoundParameters.ContainsKey('_Depth')) {
        $Equal = "<>"
    }
    elseif ($ReferenceObject -is [scriptblock] -and $PSBoundParameters.ContainsKey('_Depth')) {
        if ($ReferenceObject.ToString() -eq $DifferenceObject.ToString()) {
            $Equal = "=="
        }
        else {
            $Equal = "<>"
        }
    }
    elseif ($ReferenceObject -is [datetime] -and $PSBoundParameters.ContainsKey('_Depth')) {
        if ($ReferenceObject -eq $DifferenceObject) {
            $Equal = "=="
        }
        else {
            $Equal = "<>"
        }
    }
    elseif ($ReferenceObject.GetType().FullName -in 'System.RuntimeType', 'System.Reflection.RuntimeAssembly') {
        return
    }
    elseif ($ReferenceObject -is [System.IO.FileSystemInfo] -and $PSBoundParameters.ContainsKey('_Depth')) {
        if ($ReferenceObject.FullName -eq $DifferenceObject.FullName) {
            $Equal = "=="
        }
        else {
            $Equal = "<>"
        }
    }
    elseif ($ReferenceObject -is [string]) {
        if ($ReferenceObject -eq $DifferenceObject) {
            $Equal = "=="
        }
        else {
            $Equal = "<>"
        }
    }
    elseif ($ReferenceObject -as [double] -and $DifferenceObject -as [double]) {
        if ($ReferenceObject -eq $DifferenceObject) {
            $Equal = "=="
        }
        else {
            $Equal = "<>"
        }
    }
    elseif ($ReferenceObject -is [System.Collections.IList]) {
        if ($ReferenceObject.PSBase.Count -ne $DifferenceObject.PSBase.Count) {
            $Equal = "<>"
        }
        else {
            $Equal = "=="
            for ($i = 0; $i -lt $ReferenceObject.PSBase.Count; $i++) {
                $Diff = Compare-Property -ReferenceObject $ReferenceObject[$i] -DifferenceObject $DifferenceObject[$i] -_Depth ($_Depth + 1)
                if ($Diff) {
                    $Equal = "<>"
                    break
                }
            }
        }
    }

    if ($NameProperty) {
        if ($NameProperty -is [string]) {
            if (!$RefObjName) {
                $RefObjName = $ReferenceObject.$NameProperty
            }
            if (!$DifObjName) {
                $DifObjName = $DifferenceObject.$NameProperty
            }
        }
        else {
            if (!$RefObjName) {
                $RefObjName = $ReferenceObject | & { process { & $NameProperty } }
            }
            if (!$DifObjName) {
                $DifObjName = $DifferenceObject | & { process { & $NameProperty } }
            }
        }
    }
    else {
        if (!$RefObjName) {
            $RefObjName = $ReferenceObject.ToString()
        }
        if (!$DifObjName) {
            $DifObjName = $DifferenceObject.ToString()
        }
    }
    $RS = "r:" + $RefObjName
    $DS = "d:" + $DifObjName

    if (!$Equal -and $MaxDepth -lt $_Depth) {
        if ($ReferenceObject.ToString() -eq $DifferenceObject.ToString()) {
            $Equal = "=="
        }
        else {
            $Equal = "<>"
        }
    }

    if ($Equal) {
        if ($Equal -ne '==') {
            [PSCustomObject] @{
                Property = "<value>"
                Relation = $Equal
                $RS      = $ReferenceObject
                $DS      = $DifferenceObject
            }
        }
    }
    else {
        if ($ReferenceObject -is [System.Collections.IDictionary]) {
            $ReferenceObject = [PSCustomObject] $ReferenceObject
            $DifferenceObject = [PSCustomObject] $DifferenceObject
        }

        if ($NameProperty) {
            if ($NameProperty -is [string]) {
                $RefObjName = $ReferenceObject.$NameProperty
                $DifObjName = $DifferenceObject.$NameProperty
            }
            else {
                $RefObjName = $ReferenceObject | & { process { & $NameProperty } }
                $DifObjName = $DifferenceObject | & { process { & $NameProperty } }
            }
        }
        else {
            $RefObjName = $ReferenceObject.ToString()
            $DifObjName = $DifferenceObject.ToString()
        }
        $RS = "r:" + $RefObjName
        $DS = "d:" + $DifObjName

        $RP = $ReferenceObject.PSObject.Properties |
        & { process { if ($_.MemberType -ne 'AliasProperty') { $_ } } } |
        Select-Object -ExpandProperty Name

        $AllProps = @($RP)

        $DP = $DifferenceObject.PSObject.Properties |
        & { process { if ($_.MemberType -ne 'AliasProperty') { $_ } } } |
        Select-Object -ExpandProperty Name

        foreach ($p in $DP) {
            if ($AllProps -notcontains $p) {
                $AllProps += $p
            }
        }

        $AllProps = $AllProps | & { process {
                $PP = $_
                if (($Property | & { process { if ($PP -like $_) { $_ } } }) -and !($Exclude | & { process { if ($PP -like $_) { $_ } } })) { $_ }
            } } | Sort-Object

        foreach ($p in $AllProps) {
            if ($RP -contains $p -and $DP -contains $p) {
                $RA = $ReferenceObject.$p
                $DA = $DifferenceObject.$p

                $Diff = Compare-Property -ReferenceObject $RA -DifferenceObject $DA -Property $Property -Exclude $Exclude -_Depth ($_Depth + 1)
                if ($Diff) {
                    $Equal = "<>"
                }
                else {
                    $Equal = "=="
                }
            }
            elseif ($RP -contains $P) {
                $Equal = "<="
                $RA = $ReferenceObject.$P
                $DA = $null
            }
            else {
                $Equal = "=>"
                $DA = $DifferenceObject.$P
                $RA = $null
            }

            $RAempty = $null -eq $RA -or
            '' -eq $RA -or
            (($RA -is [Collections.IList] -or $RA -is [Collections.IDictionary]) -and $RA.Count -eq 0) -or
            $RA -is [System.DBNull]

            $DAEmpty = $null -eq $DA -or
            '' -eq $DA -or
            (($DA -is [Collections.IList] -or $DA -is [Collections.IDictionary]) -and $DA.Count -eq 0) -or
            $RA -is [System.DBNull]

            if ((!$ExcludeDifferent -and $Equal -ne '==') -or ($IncludeEqual -and $Equal -eq '==')) {
                $Dummy = 0
                if (($Hide -eq 'BothEmpty' -and $RAempty -and $DAEmpty) -or
                    ($Hide -eq 'Empty' -and ($RAempty -or $DAEmpty)) -or
                    ($Hide -eq 'NonEmpty' -and (!$RAempty -or !$DAEmpty))) {
                    continue
                }

                [PSCustomObject] @{
                    Property = $p
                    Relation = $Equal
                    $RS      = $RA
                    $DS      = $DA
                }
            }
        }
    }
}

function Get-Property {
    <#
.Synopsis
   Returns the value of object(s) that is available under the path(s) specified.
.DESCRIPTION
   This function gets the value of a property or key under a hierarchy of properties and keys and/or under the index of collections.
.EXAMPLE
    Get-ChildItem C:\Windows\system32\*.exe | Get-Property -PropertyPath "VersionInfo.CompanyName", "PSDrive.Provider.Name" -ObjectNameProperty Name

    Gets the VersionInfo.CompanyName and PSDrive.Provider.Name properties of all EXE files under c:\windows\system32 folder. The result will have the Name of each files under the Object column.
.EXAMPLE
   $h = @{Name = "MyHashTable"; Array = @{n = 'First'; data = 'Text1'}, @{n = 'Second'; data = 'Text2'}}; Get-Property -Object $h -PropertyPath 'Array[1].data' -ValueOnly

   In this example we get the 'Text2' from hashtable $h. In this case the -PropertyPath contains an index as well and because we used the -ValueOnly switch only the value of 'data' is returned.
.INPUTS
   hashtables or PSObjects
.OUTPUTS
   Collection of custom objects having an Object, PropertyPath, PropertyExists and Value properties, or only the value of the addressed property if the -ValueOnly switch is used.
#>
    [CmdletBinding()]
    param(
        # Input object to get its property
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)] [PSObject] $Object,
        # Path(s) of the value to query. This path is the full path to the value, including property names and key names and indexes.
        [Parameter(Mandatory = $true)] [string[]] $PropertyPath,
        # Property or key that can be used to reference the object. If not specified then the result of the ToString() method will be used.
        [string] $ObjectNameProperty,
        # Return only the addressed property/key value, not the complete custom object.
        [switch] $ValueOnly
    )
    begin {
        if (!$ObjectNameProperty) {
            $Parts = $null
            try {
                $MI = $MyInvocation
                $Parts = [scriptblock]::Create($MI.Line).Ast.FindAll({ $true }, $true)

                for ($i = 0; $i -lt $Parts.Count; $i++) {
                    if ($Parts[$i].ParameterName -eq 'Object') {
                        $ObjectName = $Parts[$i + 1].Extent.Text

                        if ($ObjectName -notmatch '^\(.*\)$' -and ($ObjectName -notmatch '^\$' -or ($Parts[$i + 1].staticType -match "\[\]$" -and $ObjectName -notmatch "^\("))) {
                            $ObjectName = "($ObjectName)"
                        }
                        break
                    }
                }
            }
            catch {
                $global:Error.RemoveAt(0)
            }

            if (!$ObjectName -and $Parts -and $Parts[2].GetType().FullName -match 'PipelineAst') {
                $Pipeline = $true
            }

            if (!$ObjectName) {
                if ($Pipeline) {
                    $ObjectName = '$Input'
                }
                else {
                    $ObjectName = '$Object'
                }
            }

            $ObjectCount = 0
        }
        else {
            $Pipeline = $false
        }
    }
    process {
        if ($Pipeline -or $Object -is [System.Collections.IList]) {
            $ObjectName = $ObjectName -replace "\[\d+\]$" -replace '$', "[$ObjectCount]"
            $ObjectCount++
        }

        foreach ($Obj in $Object) {
            if ($null -eq $Obj) {
                continue
            }

            if ($ObjectNameProperty) {
                $ObjectName = $Object.$ObjectNameProperty
            }

            foreach ($PP in $PropertyPath) {
                $Props = $PP -split "\.|(?<=.)(?=\[)"

                $CurrentObj = $Obj

                $Exists = $true

                foreach ($p in $Props) {
                    if ($p -match "\[(\d+)\]") {
                        $Index = [int] $Matches[1]
                    }
                    elseif ($p -match '\[["'']([^"'']+)["'']\]') {
                        $p = $p -replace '\[["'']([^"'']+)["'']\]', '$1'
                        $Index = $null
                    }
                    else {
                        $Index = $null
                        if ($p -match '^([''"]).*\1$') {
                            $p = $p -replace "^.(.*).$", '$1'
                        }
                    }

                    if ($null -ne $Index) {
                        if ($CurrentObj.Count -gt $Index) {
                            $CurrentObj = $CurrentObj[$Index]
                        }
                        else {
                            $CurrentObj = $null
                            $Exists = $false
                            break
                        }
                    }
                    elseif ($null -ne $CurrentObj -and (($CurrentObj -is [System.Collections.IDictionary] -and $CurrentObj.ContainsKey($P)) -or ($CurrentObj.PSObject.Properties.Count -and $CurrentObj.PSObject.Properties.Name -contains $P))) {
                        $CurrentObj = $CurrentObj.$P
                        if ($null -eq $CurrentObj) {
                            $Exists = $false
                            break
                        }
                    }
                    else {
                        $Exists = $false
                        $CurrentObj = $null
                        break
                    }
                }

                if ($ValueOnly) {
                    $CurrentObj
                }
                else {
                    $Out = [PSCustomObject]@{
                        Object         = $ObjectName
                        PropertyPath   = $PP
                        PropertyExists = $Exists
                        Type           = $(if ($Exists) { $CurrentObj.GetType().FullName })
                        Value          = $(if ($Exists) { $CurrentObj })
                    }

                    $Out.PSTypeNames.Insert(0, 'ScriptTools.Property.Get')
                    $Out
                }
            }

            if ($Object -is [System.Collections.IList]) {
                $ObjectName = $ObjectName -replace "\[\d+\]$" -replace '$', "[$ObjectCount]"
                $ObjectCount++
            }
        }
    }
}

<#
.Synopsis
Merges properties / keys of the Secondary object / hashtable to the Primary object / hashtable.
.DESCRIPTION
This function takes all properties or keys of the Secondary object / hashtable into the Primary object or hashtable. By default only those properties / keys are merge that doesn't exist in the Primary object / hashtable.
If the -Force switch is used then the properties / keys of the Secondary object / hashtable always merged to the Primary.
.EXAMPLE
$p = @{one = 1; three = 3}; $s = [PSCustomObject]@{two = 2; three = 33; four = 4}; Merge-Property -Primary $p -Secondary $s -PassThru

Merges $s into $p. The updated hashtable will have its key 'three' remained to be 3.
.EXAMPLE
$p = @{one = 1; three = 3}; $s = [PSCustomObject]@{two = 2; three = 33; four = 4}; Merge-Property -Primary $p -Secondary $s -PassThru -Force

Merges $s into $p. The updated hashtable will have its key 'three' updated to be 33.
.INPUTS
hashtables or PSObjects
.OUTPUTS
None or the updated object of the Primary object if the -PassThru switch is used.
#>
function Merge-Property {
    [CmdletBinding()]
    param(
        # Primary object or hashtable to merge the properties of Secondary into.
        [Parameter(Mandatory = $true)][PSObject] $Primary,
        # Secondary object or hashtable whose properties or keys to be merged into Primary.
        [Parameter(Mandatory = $true)][PSObject] $Secondary,
        # If used then the updated primary objects is returned.
        [switch] $PassThru,
        # By default conflicting properties / keys are skipped. In case the -Force switch is used then conflicting properties / keys of Primary will be overwritten by properties / keys of Secondary.
        [switch] $Force
    )

    if ($Primary -is [System.Collections.IDictionary]) {
        if ($Secondary -is [System.Collections.IDictionary]) {
            foreach ($Key in $Secondary.Keys) {
                if ($Force -or !$Primary.ContainsKey($Key)) {
                    $Primary.$Key = $Secondary.$Key
                }
            }
        }
        else {
            foreach ($Prop in $Secondary.PSObject.Properties.Name) {
                if ($Force -or !$Primary.ContainsKey($Prop)) {
                    $Primary.$Prop = $Secondary.$Prop
                }
            }
        }
    }
    else {
        if ($Secondary -is [System.Collections.IDictionary]) {
            foreach ($Key in $Secondary.Keys) {
                if ($Force -or $Primary.PSObject.Properties.Name -notcontains $Key) {
                    Add-Member -InputObject $Primary -MemberType NoteProperty -Name $Key -Value $Secondary.$Key -Force
                }
            }
        }
        else {
            foreach ($Prop in $Secondary.PSObject.Properties.Name) {
                if ($Force -or $Primary.PSObject.Properties.Name -notcontains $Prop) {
                    Add-Member -InputObject $Primary -MemberType NoteProperty -Name $Prop -Value $Secondary.$Prop -Force
                }
            }
        }
    }

    if ($PassThru) {
        $Primary
    }
}

<#
.Synopsis
Expands all the properties or keys of the input object.
.DESCRIPTION
Recursively dumps all properties or keys of the input object. By default it goes 1 level deep, but with the -MaxDepth parameter you can allow deep search.
If the -Condensed switch is used, only the leaf properties are returned (properties that don't have any further properties or which are at the -MaxDepth).
.EXAMPLE
Expand-Property -Object $PSVersionTable -MaxDepth 2 -SkipTypesAdditional system.Version

Expands the properties of the $PSVersionTable object down to 2 level deep, but any [System.Version] type of property won't be expanded further.
.EXAMPLE
Expand-Property -Object $PSVersionTable -MaxDepth 2 -SkipTypesAdditional System.Version -Condensed

Expands only the last properties in the hierarchy of properties in the $PSVersionTable object down to 2 level deep, but any [System.Version] type of property won't be expanded further.
.INPUTS
hashtables or PSObjects
.OUTPUTS
Collection of custom objects having a PropertyPath, Type, and Value properties.
#>
function Expand-Property {
    [CmdletBinding(PositionalBinding = $false)]
    param(
        # Input object or hashtable
        [Parameter(ValueFromPipeline = $true)] $Object,
        # Maximum depth of recursion, default is 1
        [int] $MaxDepth = 1,
        [Parameter(DontShow = $true)]$ObjectName,
        [Parameter(DontShow = $true)]$PropertyPath,
        [Parameter(DontShow = $true)]$CurrentDepth = 1,
        # Only leaf properties / keys are returned
        [switch] $LeafOnly,
        # .NET types that are not expanded in properties / keys
        [string[]] $SkipTypesDefault = ('System.Int*', 'System.UInt*', 'System.Double', 'System.Decimal', 'System.String', 'System.DateTime', 'System.TimeSpan', 'System.RuntimeType',
            'System.Management.Automation.ScriptBlock', 'System.Management.Automation.PSModuleInfo', 'System.Version*', 'System.Object[]', 'System.Enum', 'System.Collections.ArrayList'),
        [string[]] $SkipTypesAdditional
    )

    begin {
        if (!$ObjectName) {
            $Parts = [scriptblock]::Create($MyInvocation.Line).Ast.FindAll({ $true }, $true)

            for ($i = 0; $i -lt $Parts.Count; $i++) {
                if ($Parts[$i].ParameterName -eq 'Object') {
                    $ObjectName = $Parts[$i + 1].Extent.Text

                    if ($ObjectName -notmatch '^\(.*\)$' -and ($ObjectName -notmatch '^\$' -or ($Parts[$i + 1].staticType -match "\[\]$" -and $ObjectName -notmatch "^\("))) {
                        $ObjectName = "($ObjectName)"
                    }
                    break
                }
            }

            if (!$ObjectName -and $Parts[2].GetType().FullName -match 'PipelineAst') {
                $Pipeline = $true
            }

            $ExcludeType = $SkipTypesDefault + $SkipTypesAdditional | & { process { $_ -replace "\[", '[[' -replace "\]", ']]' } }

            if (!$ObjectName) {
                if ($Pipeline) {
                    $ObjectName = '$Input'
                }
                else {
                    $ObjectName = '$Object'
                }
            }

            $ObjectCount = 0
        }
        else {
            $Pipeline = $false
        }

        $ExcludeType = $SkipTypesDefault + $SkipTypesAdditional | & { process { $_ -replace "\[", "[[" -replace "\]", "]]" } }
    }
    process {
        if ($Pipeline) {
            $DisplayPath = $ObjectName + "[$ObjectCount]"
            $ObjectCount++
        }
        else {
            $DisplayPath = $ObjectName
        }

        if ($null -eq $Object) {
            $r = [PSCustomObject] @{
                Object       = $DisplayPath
                PropertyPath = $PropertyPath
                Depth        = $CurrentDepth
                Type         = $null
                Value        = '$null'
            }
            $r.PSTypeNames.Insert(0, 'ScriptTools.Property.Expand')
            $r
            return
        }

        if ($Object -is [System.DBNull]) {
            $r = [PSCustomObject] @{
                Object       = $DisplayPath
                PropertyPath = $PropertyPath
                Depth        = $CurrentDepth
                Type         = 'System.DBNull'
                Value        = 'NULL'
            }
            $r.PSTypeNames.Insert(0, 'ScriptTools.Property.Expand')
            $r
            return
        }

        $Keys = $null

        if (!($ExcludeType | & { process { if ($Object.GetType().FullName -like $_ -or $Object.PSTypeNames -contains $_) { $_ } } })) {
            if ($Object -is [System.Collections.IDictionary]) {
                $Keys = $Object.Keys
            }
            else {
                $Keys = $Object.PSObject.Properties.Name
            }

            if ($Object.GetType().FullName -notmatch 'ordered') {
                $Keys = $Keys | Sort-Object
            }
        }

        if (!$LeafOnly -or (!$Keys -and ($Object -isnot [System.Collections.IList] -or $Object.Count -eq 0)) -or $CurrentDepth -gt $MaxDepth) {
            $r = [PSCustomObject] @{
                Object       = $DisplayPath
                PropertyPath = $PropertyPath
                Depth        = $CurrentDepth
                Type         = $(if ($null -ne $Object) { $Object.GetType().FullName })
                Value        = $Object
            }
            $r.PSTypeNames.Insert(0, 'ScriptTools.Property.Expand')
            $r

            if ($CurrentDepth -gt $MaxDepth) {
                return
            }
        }

        foreach ($Key in $Keys) {
            $DisplayKey = $Key
            if ($Key -match '\W') {
                $DisplayKey = "'$Key'"
            }

            Expand-Property -Object $Object.$Key -ObjectName $DisplayPath -MaxDepth $MaxDepth -LeafOnly:$LeafOnly -CurrentDepth ($CurrentDepth + 1) -SkipTypesDefault $SkipTypesDefault -SkipTypesAdditional $SkipTypesAdditional -PropertyPath $(if ($PropertyPath) { $PropertyPath + '.' + $DisplayKey }else { $DisplayKey })
        }

        if ($Object -is [System.Collections.IList] -and $CurrentDepth -lt $MaxDepth) {
            for ($i = 0; $i -lt $Object.Count; $i++) {
                Expand-Property -Object $Object[$i] -ObjectName $DisplayPath -MaxDepth $MaxDepth -LeafOnly:$LeafOnly -CurrentDepth ($CurrentDepth + 1) -SkipTypesDefault $SkipTypesDefault -SkipTypesAdditional $SkipTypesAdditional -PropertyPath ("$PropertyPath[$i]")
            }
        }
    }
}

#endregion Property management

New-Alias -Name Compare-ObjectProperty -Value Compare-Property -Force
New-Alias -Name Expand-PSData -Value Expand-Property -Force

Export-ModuleMember -Variable ScriptInvocation, astTypes, paramDef_ElementType -Function '*' -Alias Compare-ObjectProperty, Expand-PSData
