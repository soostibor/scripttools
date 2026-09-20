<#
   Author: Tibor Soos
   Version: 1.7.0 [2026.06.05]
#>

#region MSLogging
#####################################
### FormatBorder
#####################################

function FormatBorder {
<#
.SYNOPSIS
   Wraps string content in a hash border block.
.DESCRIPTION
    This function collects input strings, optionally prepends a title, applies indentation,
    and returns the content surrounded by top and bottom border lines. It is used to create
    consistent, readable framed sections in MSLogging output.
.EXAMPLE
    'Line 1', 'Line 2' | FormatBorder
    Returns the two lines wrapped inside a hash border.
.EXAMPLE
    'Server: host01' | FormatBorder -Title 'Header' -IndentLevel 1
   Adds a title and one indentation level before drawing the bordered block.
.INPUTS
   System.String[]
.OUTPUTS
   System.String[]
#>
param(
    # Input string lines to wrap inside the border (supports pipeline input).
    [Parameter(ValueFromPipeline=$true)][string[]] $Strings,
    # Optional title prepended inside the border block.
    [string] $Title,
    # Indentation level applied to each content line (4 spaces per level).
    [int] $IndentLevel
)
begin{
    $lines = @()
    if($Title) {
        $lines += $Title
    }
}
process{
    foreach($string in $Strings) {
        $lines += " " * $IndentLevel * 4 + $string
    }
}
end{
    $longest = $lines | Measure-Object -Property Length -Maximum | Select-Object -First 1 -ExpandProperty Maximum
    "#" * ($longest + 4)
    foreach($line in $lines) {
        "# $($line.padright($longest)) #"
    }
    "#" * ($longest + 4)
}
}

###########################################
######## Add-MSLogTextWithRetry
###########################################
function Add-MSLogTextWithRetry {
<#
.SYNOPSIS
    Appends log text with retry handling for temporarily locked files.
.DESCRIPTION
    This function appends one or more lines to a log file stream. If the file is temporarily locked,
    it retries until the timeout is reached. When writes cannot be completed and locking is detected,
    messages are queued in an in-memory cache and flushed when the stream becomes available again.
.EXAMPLE
    'Task started' | Add-MSLogTextWithRetry -Path 'C:\Logs\Job.log'
    Appends a single line to the target log file.
.EXAMPLE
    Add-MSLogTextWithRetry -Path 'C:\Logs\Job.log' -Text @('Line 1', 'Line 2') -Timeout 3
    Appends multiple lines and retries for up to 3 seconds when the file is locked.
.INPUTS
    System.String[]
.OUTPUTS
    None. This function does not emit output.
#>
[cmdletbinding()]
param(
    # Target log file path to append to.
    [string] $Path,
    # Text lines to append (supports pipeline input).
    [Parameter(ValueFromPipeline = $true)][string[]] $Text,
    # Encoding used when writing cached content to disk.
    [ValidateScript( { $_ -is [System.Text.Encoding] })] $Encoding = [System.Text.Encoding]::UTF8,
    # Maximum number of seconds to retry while file is locked.
    [int] $Timeout = 1,
    # Forces an error when write cannot be completed.
    [switch] $Force,
    # Active log context key for cache management.
    [string] $LogFileName
)
begin{
    $LogFileName = Get-MSLogFileName

    if(!$LogFileName -or !$global:logging -or !$global:logging.$LogFileName) {
        throw 'A valid LogFile Name and $global:logging context is required.'
    }

    $retry = $true
    $start = Get-Date
    $handle = $null
    $fileInUseHResult = -2147024864

    do {
        try {
            $locked = $false
            $handle = [io.file]::AppendText($path)
        }
        catch {
            $global:Error.RemoveAt(0)
            if($_.Exception.InnerException -and $_.Exception.InnerException.HResult -eq $fileInUseHResult) {
                Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 500)
                $locked = $true
            }
            else {
                $retry = $false
                $Force = $true
            }
        }
        if(((Get-Date) - $start).totalseconds -gt $Timeout) {
            $retry = $false
        }
    }while ((!$handle -or !$handle.BaseStream) -and $retry)

    if($handle -and $handle.BaseStream -and $global:logging.$LogFileName._LogCache.count) {
        while ($global:logging.$LogFileName._LogCache.Count) {
            $cline = $global:logging.$LogFileName._LogCache.dequeue()
            $handle.Writeline($cline)
        }
    }
}
process{
    foreach($line in $Text) {
        if(!$handle -or !$handle.BaseStream) {
            if($Force -or !$locked) {
                throw "LogAppendText error"
            }
            else {
                $global:logging.$LogFileName._LogCache.EnQueue($line)
                if($global:logging.$LogFileName._LogCache.Count -gt $global:logging.$LogFileName._MaxCacheSize) {
                        $tempDir  = Split-Path -Path $Path
                        $tempName = "_Templog-$(get-date -Format 'yyyy-MM-dd-HH-mm-ss-fffffff').log"
                        $tempfile = Join-Path -Path $tempDir -ChildPath $tempName
                        $global:logging.$LogFileName._LogCache |
                            Set-Content -Path $tempfile -Encoding ($Encoding.EncodingName -replace 'US-')
                    $global:logging.$LogFileName._LogCache.Clear()
                }
            }
        }
        else{
            $handle.Writeline($line)
        }
    }
}
end{
    if($handle) {
        try{
            $handle.Close()
        }
        catch{
            $global:Error.RemoveAt(0)
        }
   }
}
}

###########################################
######## Format-MSLogJSON
###########################################
function Format-MSLogJSON {
<#
.SYNOPSIS
    Formats objects as JSON lines for logging.
.DESCRIPTION
    This function collects pipeline input, normalizes hashtables into custom objects, selects the
    requested properties, and converts the result to JSON text. The output can optionally be wrapped
   with a border for consistent log presentation.
.EXAMPLE
    Get-Service Select-Object -First 2 | Format-MSLogJSON -Depth 3
   Converts service objects to JSON output lines.
.EXAMPLE
   @{ Name = 'Task'; Status = 'Running' } | Format-MSLogJSON -Bordered
   Converts a hashtable to JSON and applies bordered formatting.
.INPUTS
    System.Object
.OUTPUTS
   System.String[]
#>
[cmdletbinding()]
param(
    # Input object(s) to convert to JSON.
    [Parameter(ValueFromPipeline = $true)]$Object,
    # Property names/patterns to include.
    [object[]] $Property = "*",
    # Property names/patterns to exclude.
    [string[]] $ExcludeProperty = $null,
    # Wrap output lines with a visual border.
    [switch] $Bordered,
    # JSON serialization depth.
    [int] $Depth = 5
)

    $inputObjects = $input
    $convertedObjects = @()

    foreach($io in $inputObjects){
        if($io -is [hashtable]){
            $convertedObjects += [pscustomobject] $io
        }
        else{
            $convertedObjects += $io
        }
    }

    $sosplatting = @{}

    if($Property) {
        $sosplatting.Property = $Property
    }
    if($ExcludeProperty) {
        $sosplatting.ExcludeProperty = $ExcludeProperty
    }

    try{
            $json = $convertedObjects | Select-Object @sosplatting | ConvertTo-Json -Depth $depth -ErrorAction Stop
            $lines = $json -split [Environment]:: NewLine |
                Where-Object -FilterScript {$ -and $_.trim()}

        if($Bordered) {
            $lines | FormatBorder
        }
        else{
            $lines
        }
    }
    catch{
        throw $
    }
}

###########################################
######## Format-MSLogStringList
###########################################
function Format-MSLogStringList {
<#
.SYNOPSIS
    Formats objects as aligned name-value lines for log output.
.DESCRIPTION
    This function renders object properties into readable key-value text lines that are suitable for
    log files and console output. It supports include/exclude filters, sorting, indentation, optional
    separators, value masking for selected properties, and bordered formatting.
.EXAMPLE
    Get-Process | Select-Object -First 1 | Format-MSLogStringList
    Formats the first process object as aligned key-value lines.
.EXAMPLE
    @{ User = 'svc'; Password = 'secret' } | Format-MSLogStringList -Hide Property Password -Bordered
    Formats a hashtable and masks the Password value.
.INPUTS
    System.Object
.OUTPUTS
    System.String[]
#>
[cmdletbinding()]
param(
    # Input object(s) to format.
    [Parameter(ValueFromPipeline = $true)] $Object,
    # Property names/patterns to include.
    [string[]] $Property = "*",
    # Property names/patterns to exclude.
    [string[]] $ExcludeProperty = $null,
    # Adds a separator line after formatted output.
    [switch] $Divide,
    # Hides properties with null or empty values.
    [switch] $HideNulls,
    # Indentation level (4 spaces per level).
    [int] $IndentLevel,
    # Sorts selected properties before formatting.
    [switch] $Sort,
    # Property used to sort selected properties.
    $Sortby,
    # Wrap output lines with a visual border.
    [switch] $Bordered,
    # Property names/patterns whose values are masked.
    [string[]] $HideProperty
)
begin {
    $lines = @()
}
process{
    if($object -is [hashtable]){
        $Object = [pscustomobject] $Object
    }

    $selecttedprops = @()
    $longest = 0

    foreach ($prop in $Object.psobject.Properties) {
        if($ExcludeProperty | Where-Object -FilterScript {$prop.name -like $_ } | Select-Object -First 1){
            continue
        }
        $propMatch = $Property | Where-Object -FilterScript {$prop.name -like $_} | Select-Object -First 1
        if($propMatch -and (!$HideNulls -or $prop.value)) {
            $selecttedprops += $prop

            if($prop.name.length -gt $longest) {
                $longest = $prop.name.length + 1
            }
       }
    }

    if($object -is [string]) {
        $lines += " " * $IndentLevel * 4 + $0bject
    }
    elseif($selecttedprops) {
        if($Sort) {
            if(!$Sortby) {
                $Sortproperty = "name"
            }
            else{
                $Sortproperty = $Sortby
            }
        }
        else{
            $Sortproperty = "dummy"
        }

        foreach ($sp in ($selecttedprops | Sort-Object -Property $Sortproperty -Debug:$false)) {
            if($sp.value -as [string] -and ($HideProperty | Where-Object -FilterScript {$sp.name -like $_})) {
                $Value = '*' * ([string] $sp.value).length
            }
            else{
                $Value = $sp.value
            }
            $lines += " " * $IndentLevel * 4 + $sp.name.padright($longest) + ": " + $Value
        }
    }
    if($Divide) {
        $lines += "-" * 92
    }
}
end{
    if($Bordered){
        $lines | FormatBorder
    }
    else{
        $lines
    }
}
}

###########################################
######## Format-MSLogStringTable
###########################################
function Format-MSLogStringTable {
<#
.SYNOPSIS
    Formats objects as a table string for logging.
.DESCRIPTION
    This function gathers pipeline input, converts hashtables to custom objects, applies optional
    property selection and exclusion, and returns formatted table lines. Output can be wrapped in
    borders for consistent log presentation.
.EXAMPLE
   Get-Service | Select-Object -First 5 | Format-MSLogStringTable
    Renders selected service objects as table text.
.EXAMPLE
   @{ Name = 'Node1'; State = 'Online' } | Format-MSLogStringTable -Bordered
    Renders a hashtable as bordered table output.
.INPUTS
    System.Object
.OUTPUTS
    System.String[]
#>
[cmdletbinding()]
param(
    # Input object(s) to format.
    [Parameter(ValueFromPipeline = $true)] $Object,
    # Property names/patterns to include.
    [object[]] $Property = "*",
    # Property names/patterns to exclude.
    [string[]] $ExcludeProperty = $null,
    # Wrap output lines with a visual border.
    [switch] $Bordered
)
    $inputObjects = $input
    $convertedObjects = @()

    foreach($io in $inputObjects){
        if($io -is [hashtable]){
            $convertedObjects += [pscustomobject] $io
        }
        else{
            $convertedObjects += $io
        }
    }

    $ftsplatting = @{}

    if($Property){
       $ftsplatting.Property = $Property
    }

    if($ExcludeProperty) {
        $ftsplatting.ExcludeProperty = $ExcludeProperty
    }

    $tableString = $convertedObjects | Select-Object @ftsplatting | Format-Table -AutoSize | Out-String
    $lines = $tableString -split [Environment]:: NewLine |
       Where-Object -FilterScript {$_ -and $_.trim()}

    if($Bordered){
        $lines | FormatBorder
    }
    else{
        $lines
    }
}

###########################################
######## Get-MSLogFileName
###########################################
function Get-MSLogFileName {
<#
.SYNOPSIS
   Resolves the active MSLogging log file name from runtime context.
.DESCRIPTION
    This function determines the current log file name by inspecting global logging state,
    call stack bound parameters, and fallback global variables. It also computes filtered
    call stack metadata and sets helper variables used by other logging functions.
.EXAMPLE
    Get-MSLogFileName
    Returns the current active log file name when one can be resolved.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    System.String
#>
[CmdletBinding()]
param(
    # Optional switch to ignore errors when no log file name can be resolved.
    [switch] $IgnoreNoLogFileName
)

    $LogFileName = $null

    if(Get-Variable -Name logging -Scope global -ErrorAction Ignore){
       $cs = @(Get-PSCallStack | Where-Object -FilterScript {
            $_.Command -ne '<ScriptBlock>' -and
            $_.Location -ne '<No file>' -and
            $_.scriptname -notmatch 'Pester\.psm?1$'
        })

        if(!$LogFileName) {
            for ($iter = 1; $iter -lt $cs.Length; $iter++){
                if(!$LogFileName -and $cs[$iter].InvocationInfo.BoundParameters.ContainsKey('logfilename')) {
                    if($cs[$iter].InvocationInfo.BoundParameters.logfilename) {
                        $LogFileName = $cs[$iter].InvocationInfo.BoundParameters.logfilename
                        break
                    }
                }
            }
        }

        if(!$LogFileName -and (Get-Variable -Name logfilename -Scope Global -ErrorAction Ignore)) {
            $LogFileName = $global:logfilename
        }

        if($LogFileName){
            $ignorePattern = @($global:logging.$LogFileName._IgnoreCommand) -join '|'
            $realstack = @($cs | Where-Object -FilterScript {$_.command -notmatch $ignorePattern})

            if(!$realstack) {
                $realstack = $cs[-1]
            }
            $invInfo = $realstack[0].InvocationInfo
            $invName = $invInfo.MyCommand.Name
            Add-Member -InputObject $invInfo -MemberType NoteProperty -Name LogInvocationName -Value $invName -Force

            $cs[1].InvocationInfo.BoundParameters.logcallstack = $realstack
            $cs[1].InvocationInfo.BoundParameters.logrealdepth = $realstack.Count

            $LogFileName
        }
    }

    if(!$LogFileName -and !$IgnoreNoLogFileName) {
        throw 'No log file name could be resolved from the current context.'
    }
}

###########################################
######## Get-MSLogIsAdministrator
###########################################
function Get-MSLogIsAdministrator {
<#
.SYNOPSIS
    Returns whether the current identity is a local administrator.
.DESCRIPTION
    This function inspects the current Windows identity group SIDS and checks for membership
    in the built-in Administrators group.
.EXAMPLE
   Get-MSLogIsAdministrator
    Returns True when the current user token includes local Administrators group membership.
.INPUTS
   None. This function does not accept pipeline input.
.OUTPUTS
   System.Boolean
#>
    $builtinAdministratorsSID = 'S-1-5-32-544'

    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $user
    $groupSIDs = $principal.Identity.Groups | Select-Object -ExpandProperty value
    $IsAdministrator = [bool] ($groupSIDS -match $builtinAdministratorsSID)
    $IsAdministrator
}

###########################################
######## Initialize-MSLogging
###########################################

function Initialize-MSLogging {
<#
.SYNOPSIS
    Initializes a logging context and creates or opens a log file.
.DESCRIPTION
    This function prepares global logging state, determines environment-specific defaults,
    creates the log file, configures formatting columns, and writes initial header information.
    It returns the resolved log key that downstream logging functions use.
.EXAMPLE
    $LogFileName = Initialize-MS Logging -Title 'Patch Run' -Name 'Patch.log' -Path 'C:\Logs'
    Initializes logging and returns the active log key.
.EXAMPLE
    Initialize-MSLogging -Simulate Runbook -Name 'Runbook.log'
    Initializes logging with runbook simulation behavior and temporary log storage.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    System.String
#>
[CmdletBinding()]
param(
    # Display title written to the log header.
    [string] $Title,
    # Base log file name.
    [string] [Alias('scriptName')] $Name,
    # Folder path for log file creation.
    [string] [Alias('LogPath')]    $Path,
    # Additional commands to ignore when resolving script call stack.
    [string[]] $IgnoreCommand,
    # Default command patterns to ignore in call stack analysis.
    [string[]] $DefaultIgnoredCommands = ('-MSLog\w+$', '<ScriptBlock>'),
    # Number of days to keep old log files.
    [int]    [Alias('DaysToKeep')] $KeepDays = 90,
    # Seconds between progress bar refreshes.
    [int]    $ProgressBarSec = 1,
    # Seconds before first progress log message.
    [int]    $ProgressLogFirst = 60,
    # Minutes between subsequent progress log messages.
    [int]    $ProgressLogMin = 5,
    # Existing log key to merge into.
    [string] $MergeTo,
    # Email recipients for error log notifications.
    [string[]] $EmailTo,
    # Sender email address for notifications.
    [string] $EmailFrom,
    # Email subject for notifications.
    [string] $EmailSubject,
    # SMTP server used for notifications.
    [string] $SMTPServer,
    # Creates date-based daily log files.
    [switch] $Daily,
    # Explicit date suffix for log file naming.
    [string] $DatePart,
    # Simulates runbook environment behavior.
    [switch] $SimulateRunbook,
    # Windows Event Log source name.
    [string] $EventLogSource,
    # Windows Event Log name.
    [string] $EventLog,
    # Width for the Function column in log lines.
    [int] $FunctionColumnWidth = 26,
    # Name of bound parameter used for Resource column.
    [string] $ResourceName
)
    if($MergeTo){
        return $MergeTo
    }

    (Get-Variable -Name Error -Scope global -ValueOnly).Clear()

    $allcs = Get-PSCallStack

    $IgnoreCommand = $IgnoreCommand + $DefaultIgnoredCommands

    $csIgnorePattern = @($IgnoreCommand) -join '|'
    $cs = @($allcs | Where-Object -FilterScript {
        $_.command -notmatch $csIgnorePattern -and
        $_.scriptname -notmatch 'Pester\.psm?1$'
    })

    if($cs) {
        $scriptinvocation = $cs[-1].InvocationInfo
    }
    else{
        $scriptinvocation = $null
    }

    $version = "0.0.0"
    $releasedate = ""

    $additionalColumns = @(@{
        Name = 'Function'
        Rule = {$environmentInvocation.LogInvocationName}
        width = $FunctionColumnWidth
    })

    $debugEnabled = ($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters.Debug)
    $mergeDebug   = ($MergeTo -and $global:logging.$MergeTo._DebugMode)
    if($debugEnabled -or $mergeDebug) {
        $additionalColumns += @{
            Name = 'Resource'
            Rule =  {$environmentInvocation.BoundParameters.($global:logging.$logfilename._ResourceName)}
            width = 20
        }
    }

    if($scriptinvocation) {
        $scriptname = $scriptinvocation.MyCommand.Name
        
        $scriptpath = Split-Path -Path $scriptinvocation.MyCommand.path

        if(Get-Member -InputObject $scriptinvocation.MyCommand -Name scriptcontents -ErrorAction Ignore){
            $scripttext = $scriptinvocation.MyCommand.scriptcontents
            $versionPattern = 'Version\s*:\s*(?<version>\d+\.\d+(\.\d+)*)(\s*\((?<releasedate>\d{4}\.\d{2}\.\d{2})\))?'
            $versionfound = $scripttext -match $versionPattern
            if($versionfound) {
                $releasedate = $Matches.releasedate
                $version = $Matches.version
           }
       }
    }
    elseif($allcs[0].InvocationInfo.ScriptName){
        $scriptinvocation = $allcs[0].InvocationInfo

        $scriptpath = Split-Path -Path $allcs[0].InvocationInfo.ScriptName
        $scriptname = Split-Path -Path $allcs[0].InvocationInfo.ScriptName -Leaf

        Add-Member -InputObject $scriptinvocation -Member Type NoteProperty -Name LogInvocationName -Value $scriptname -Force

        $scripttext = get-content -Path $allcs[0].Invocation Info.ScriptName
        $versionPattern = 'Version\s*:\s*(?<version>\d+\.\d+(\.\d+)*)(\s*\((?<releasedate>\d{4}\.\d{2}\.\d{2})\))?'
        $versionfound = $scripttext -match $versionPattern
        if($versionfound) {
            $releasedate = $Matches.releasedate
            $version = $Matches.version
        }
    }
    else{
        $scriptname = "Interactive"
        $scriptpath = "Interactive"
    }

    $environment = $host.Name
    $UseOutput = $false

    if($SimulateRunbook){
        $Path = $env:TEMP
        $environment = 'Simulated Runbook'
        $baseScriptName = 'SimulatedRunbook'
        $Daily = $false
        $UseOutput = $true
    }
    elseif($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation') {
        $Path = $env:TEMP
        $baseScriptName = 'AzureAutomation'
        $environment = $env:AZUREPS_HOST_ENVIRONMENT
        $Daily = $false
        $UseOutput = $true
    }
    elseif($host.name -eq 'Default Host') {
        $Path = $env:TEMP
        $baseScriptName = 'HybridWorker'
        $environment = "Hybrid Worker"
        $Daily = $false
        $UseOutput = $true
    }
    elseif(!$Path) {
        if($Name) {
            $baseScriptName = $Name -replace '(?<=.)\.[^]+$', ''
        }
        else{
            $baseScriptName = $scriptname -replace '(?<=.)\.[^. ]+$', ''
        }

        if(Test-Path -path $env:SYSADMINROOT\Log) {
            $Path = "$env:SYSADMINROOT\Log\$baseScriptName"
        }
        elseif(!(test-path -Path $Path) -or (Test-Path -Path $Path -PathType Container)){

        }
        else{
            $Path = Join-Path -path $env:TEMP -ChildPath "Log\$baseScriptName"
        }
    }

    $columns = @('"DateTime"             ','"Line"   ','"Type"     ')
    if($additionalColumns) {
        $columns += $additionalColumns | ForEach-Object -Process {
            "{0,$(-([math]::max($_.width, $_.name.length)+2))}" -f """$($_.name)"""
        }
    }
    $columns += '"Message"'

    if(!$Name) {
        $LogFileName = "$($baseScriptName).log"
    }
    else{
       $LogFileName = ($Name -replace "\.log$") + ".log"
    }

    if(!(Get-Variable -Name logging -Scope Global -ErrorAction Ignore) -or $global:logging -isnot [hashtable]){
        $global:logging = @{}
    }

    $logFile = New-MSLogFile -name $LogFileName -path $Path -keepdays $KeepDays -Daily:$Daily -datepart $DatePart

    if($scriptpath -eq "Interactive"){
        $global:logfilename = $logFile.name
    }
    else{
        $scriptinvocation.BoundParameters.logfilename = $logFile.name
    }

    $parentprocess = $null
    $myprocess = Get-CimInstance -ClassName Win32_process -Filter "ProcessID = '$PID'" -Verbose:$false
    if($myprocess.ParentProcessId) {
        $parentprocess = Get-CimInstance -ClassName Win32_process -Filter "ProcessID = '$($myprocess.ParentProcessId)'" -Verbose:$false
    }

    if($parentprocess -and $parentprocess.Name -in 'explorer.exe', 'code.exe') {
        $localVerbose = $true
    }
    else{
        $localVerbose = $false
    }

    $global:logging.$($logFile.Key) = [pscustomobject] @{
            Title = $Title
            ScriptName = $scriptname
            ScriptPath = $scriptpath
            ScriptVersion = "$version $(if($releasedate){"($releasedate)"})"
            RunBy = "$env:USERDOMAIN\$env:USERNAME"
            IsAdministrator = Get-MSLogIsAdministrator
            Computer  = $env:COMPUTERNAME
            LogPath   = $logFile.fullname
            LogFolder = $logFile.DirectoryName
            LogStart  = Get-Date
            Environment = $environment
            EventLogSource = $EventLogSource
            EventLog       = $EventLog
            _IndentOffset  = $cs.count
            _LastLine      = ""
            _WarningsLogged = 0
            _ErrorsLogged = 0
            _UnhandledErrors = 0
            _VerboseMode    = $(
                if($PSBoundParameters.ContainsKey('verbose')){$PSBoundParameters.verbose}else{$localVerbose}
            )
            _DebugMode      = $(if($PSBoundParameters.ContainsKey('Debug')){$PSBoundParameters.Debug})
            _Progress = [PSCustomObject] @{
                    ArrayID = 0
                    Counter = 0
                    Start   = $null
                    BarSec  = $ProgressBarSec
                    BarNext = $null
                    LogFirst = $ProgressLogFirst
                    LogNext  = $null
                    LogMin = $ProgressLogMin
                }
            _AdditionalColumns = $additionalColumns
            _IgnoreCommand  = $IgnoreCommand
            _emailTo        = $EmailTo
            _emailFrom      = $EmailFrom
            _emailSubject   = $EmailSubject
            _smtpserver     = $SMTPServer
            _baseindent     = 0
            _LogCache       = [System.Collections.Queue] @()
            _MaxCacheSize   = 1000
            _UseOutput      = $UseOutput
            _parentProcess = $parentprocess
            _FunctionColumnWidth = $FunctionColumnWidth
            _ResourceName  = $ResourceName
        }

    if($EventLogSource){
        $sourceExists = [System.Diagnostics.EventLog]::SourceExists($EventLogSource)
        if(-not $sourceExists -and $global:logging.$($logFile.Key).IsAdministrator){
            try{
                New-EventLog -LogName $EventLog -Source $EventLogSource -ErrorAction Stop
            }
            catch{
               $global:logging.$($logFile.Key).EventLogSource = $null
                if($ErrorActionPreference -eq 'Stop') {
                    throw $_
                }
                elseif($ErrorActionPreference -eq 'Continue'){
                   Write-Error Message $_.exception.message
                }
                elseif($ErrorActionPreference -eq 'Ignore') {
                    $global:Error.RemoveAt(0)
                }
            }
        }
    }

    if($logFile.new) {
        Set-Content -Path $logFile.Fullname Value ($columns -join ",")
    }

    $global:logging.$($logFile.Key) |
        Format-MSLogStringList -excludeProperty
        FormatBorder |
        New-MSLogEntry -type Header -LogFileName $logFile.key

    if($scriptinvocation -and $scriptinvocation.BoundParameters.keys.where({$_ -ne 'logfilename'}).count) {
        [PSCustomObject] [hashtable] $scriptinvocation.BoundParameters |
            Format-MSLogStringList -excludeproperty LogFileName |
            FormatBorder -title "Bound Parameters:" -indent level 1 |
                New-MSLogEntry -indentlevel 1 -LogFileName $logFile.key
    }

    if($ScriptImplicitParams = Get-Variable -Name ScriptImplicitParams -Scope Global -ErrorAction Ignore -ValueOnly) {
        [PSCustomObject] $ScriptImplicitParams | Format-MSLogStringList |
            FormatBorder -title "Parameters with defaults:" -indentlevel 1 |
                New-MSLogEntry -indent level 1 -LogFileName $logFile.key
   }
   $logFile.DelayedLogEntries | New-MSLogEntry -indentlevel 1 -LogFileName $logFile.key

   return $logFile.key
}

################################
#####        New-MSLogEntry
################################

function New-MSLogEntry {
<#
.SYNOPSIS
   Writes one or more entries to the active MS log.
.DESCRIPTION
   This function formats log lines with metadata, writes to log storage, optionally writes
   to host/output streams, and can emit Windows Event Log entries. It also supports special
   entry types such as Header, Footer, Progress, Exit, and Terminate behaviors.
.EXAMPLE
   New-MSLogEntry -Message 'Starting job' -Type Info
   Writes an informational entry to the active log.
.EXAMPLE
    'Step complete' | New-MSLogEntry -Type Highlight -IndentLevel 1
   Writes a highlighted entry from pipeline input with indentation.

.INPUTS
    System.String[]
.OUTPUTS
    None. This function does not emit output.
#>
[cmdletbinding()]
param(
    # Log message text lines (supports pipeline input).
    [Parameter(ValueFromPipeline = $true)] [string[]] $Message,
    # Entry type controlling formatting and behavior.
    [Parameter()] [ValidateSet('0', '1', '2', '3', '4', '5',
        'Info', 'Highlight', 'Warning', 'Error', 'Exit', 'Terminate',
        'Unhandled', 'Progress', 'Debug', 'Header', 'Footer', 'Negative')] [string] $Type = 'Info',
    # Relative or absolute indentation level.
    [int] $IndentLevel,
    # Uses indentation level as absolute depth.
    [switch] $UseAbsoluteIndent,
    # Keeps current line open without newline.
    [switch] $NoNewLine,
   # Controls how line continuation is handled. (Use -NoNewLine, this parameter is only for backwards compatibility)
    [ValidateSet('nonew', 'extend')] [string] $Modifier = 'extend',
    # Displays output without writing to log file.
    [switch] $DisplayOnly,
    # Target log context key.
    [string] $LogFileName,
    # Event log ID when writing Windows events.
    [int] $EventId,
    # Windows Event Log name override.
    [string] $EventLog,
    # Windows Event Log source override.
    [string] $EventLogSource,
    # Removes log file on exit/terminate flow.
    [switch] $IgnoreLog,
    # Explicit process exit code.
    [int] $ExitCode,
   # Do not write log entry to StatusMessages parameter of the parent script/function
    [switch] $SkipWriteToStatusMessages
)
begin{
    $LogFileName = Get-MSLogFileName

    if(!$LogFileName) {
        $LogFileName = Initialize-MSLogging

        $LogFileName = Get-MSLogFileName
    }

    if($null -eq $LogFileName) {
        throw 'A valid LogFile Name and $global: logging context is required.'
    }

    $relativelevel = 0
    $localverbose = $null

    if($PSBoundParameters.ContainsKey('logcallstack')){
        # This variable can be used in scripts generating content for by additional columns for the log entry
        $environmentInvocation = @($PSBoundParameters.logcallstack)[0].InvocationInfo

        for($iter = 0; $iter -lt $PSBoundParameters.logcallstack.Length; $iter++){
            $stackScriptName = $PSBoundParameters.logcallstack[$iter].ScriptName
            $firstScriptName = $PSBoundParameters.logcallstack[0].ScriptName
            if(!$relativelevel -and $stackScriptName -ne $firstScriptName -and !$LogFileName) {
                $relativelevel = $iter
            }

            $stackVerbose = $PSBoundParameters.logcallstack[$iter].InvocationInfo.BoundParameters.ContainsKey('Verbose')
            $notSilent    = $VerbosePreference -notin 'SilentlyContinue', 'Ignore'
            if($null -eq $localverbose -and ($notSilent -or $stackVerbose)){
                $localverbose = $PSBoundParameters.logcallstack[$iter].InvocationInfo.BoundParameters.Verbose
            }
        }

        if($environmentInvocation.MyCommand.Parameters.ContainsKey('StatusMessages') -and !$SkipWriteToStatusMessages) {
           $saveToStatusMessages = $true
        }
    }
    else{
        $environmentInvocation = [pscustomobject]@{MyCommand = @{Name = 'Interactive'}}
    }
                                                          
    $baseindent = [math]::Max($PSBoundParameters.logrealdepth - 1, 0)

    if($null -eq $localverbose) {
        $localverbose = $global:logging.$LogFileName._VerboseMode
    }

    if($IndentLevel){
        $global:logging.$LogFileName._BaseIndent = $IndentLevel
    }
    else{
        $global:logging.$LogFileName._BaseIndent = $baseindent
    }

    if(!$localverbose -and $PSBoundParameters.ContainsKey('Verbose') -and $PSBoundParameters.Verbose) {
       $localverbose = $true
    }

    if(!$UseAbsoluteIndent){
        $IndentLevel = $IndentLevel + $baseindent
    }

    if($PSBoundParameters.logcallstack){
        $linenumber = $PSBoundParameters.logcallstack[$relativelevel].ScriptLineNumber
    }
    else{
        $linenumber = 0
    }

    switch($Type) {
        'Info'           {$param = @{ForegroundColor = "Gray"}; $eventType = 'Information'}
        '0'           {$param = @{ForegroundColor = "Gray"}; $eventType = 'Information'}
        '5'           {$param = @{ForegroundColor = "DarkGray"}; $eventType = 'Information'}
        'Highlight'      {$param = @{ForegroundColor = "Green"}; $eventType = 'Information'}
        '3'           {$param = @{ForegroundColor = "Green"}; $eventType = 'Information'; $Type = 'Highlight'}
        '4'           {$param = @{ForegroundColor = "Magenta"}; $eventType = 'Information'; $Type = 'Highlight'}
        'Header'         {$param = @{ForegroundColor = "Green"}; $eventType = 'Skip'}
        'Footer'         {$param = @{ForegroundColor = "Green"}; $eventType = 'Skip'}
        'Debug'     {$param = @{ForegroundColor = "Cyan"; BackgroundColor = 'DarkGray'}; $eventType = 'Information'}
        'Warning' {
            $param = @{ForegroundColor  = "Yellow"; BackgroundColor = 'DarkGray'}
            $global:logging.$LogFileName._WarningsLogged++
            $eventType = 'Warning'
        }
        '1' {
            $param = @{ForegroundColor = "Yellow"; BackgroundColor = 'DarkGray'}
            $global:logging.$LogFileName._WarningsLogged++
            $eventType = 'Warning'
            $Type = "Warning"
        }

        'Error' {
            $param = @{ForegroundColor = "Red"}
            $global:logging.$LogFileName._ErrorsLogged++
            $eventType = 'Error'
        }
        '2' {$param = @{ForegroundColor = "Red"}; $global:logging.$LogFileName._ErrorsLogged++; $eventType = 'Error'}
        'Negative'       {$param = @{ForegroundColor = "Red"}; $eventType = 'Error'; $Type = "Warning"}
        'Exit'           {$param = @{ForegroundColor = "Green"}; $eventType = 'Skip'}
        'Terminate' {
            $param = @{ForegroundColor = "Red"; BackgroundColor = 'Black' }
            $global:logging.$LogFileName._ErrorsLogged++
            $eventType = 'Error'
        }
        'Unhandled' {
            $param = @{ForegroundColor = "DarkRed"; BackgroundColor = 'DarkGray'}
            $global:logging.$LogFileName._ErrorsLogged++
            $eventType = 'Skip'
        }
        'Progress'       {$param = @{ForegroundColor = "Magenta"}; $eventType = 'Skip'}
    }


    if($Type -ne 'Unhandled') {
        Write-MSLogUnhandledErrors -LogFileName $LogFileName
    }
}
process{
    foreach ($mess in $Message) {
        if($LogFileName) {
            if($global:logging.$LogFileName._LastLine) {
                $line = " $mess"
            }
            else{
                $ts = Get-Date -Format 'yyyy.MM.dd HH:mm:ss'
                $line = "[$ts], [$(([string] $linenumber).PadLeft(6))], [$($Type.toupper().padright(9))]"
                if($global:logging.$LogFileName._additionalColumns) {
                    foreach ($col in $global:logging.$LogFileName._additionalColumns){
                        $colVal = $col.Rule.GetNewClosure().invoke()[0]
                        $line += ",[{0,$(-([math]::max($col.width, $col.name.length)))}]" -f $colVal
                    }
                }
                $line += ", >$(" " * $IndentLevel * 4)$mess"
            }

            if($NoNewLine -or $Modifier -eq 'NoNew' -or $global:logging. $LogFileName._LastLine){
                $global:logging.$LogFileName._LastLine += $line
            }

            if($LogFileName -and !$NoNewLine -and !$DisplayOnly) {
                if($global:logging.$LogFileName._LastLine) {
                    Add-MSLogTextWithRetry -path $global:logging.$LogFileName.LogPath -text $global:logging.$LogFileName._LastLine
                    $global:logging.$LogFileName._LastLine = ""
                }
                else{
                    Add-MSLogTextWithRetry -path $global:logging.$LogFileName.LogPath -text $line
                }
            }
        }

        if($saveToStatusMessages) {
            $lineToStatusMessages = "[$($Type.toupper().padright(9))] $mess"
            Update-Property -Object $environmentInvocation.BoundParameters -PropertyPath StatusMessages -Value $lineToStatusMessages
        }

        $alwaysShow = $Type -in 'Debug', 'Error', 'Terminate', 'Unhandled', 'Negative', 'Warning', '2'
        if($DisplayOnly -or $localverbose -or $alwaysShow) {
            if($global:logging.$LogFileName._UseOutput) {
                if($Type -in 'Error', 'Terminate', 'Unhandled', '2'){
                    Write-Error -Message $line
                    $global:Error.RemoveAt(0)
                }
                elseif($Type -in 'Warning', '1'){
                   Write-Warning -Message $line
                }
                elseif($Type -match '^(Progress | Highlight) $' -and
                   @($PSBoundParameters.logcallstack | Where-Object -FilterScript {
                       $_.ScriptName -ne $PSBoundParameters.logcallstack[0].ScriptName
                    }).Count -le 1) {
                    Write-Output -InputObject $line
                }
            }
           else{
               Write-Host -Object $line @param -NoNewline: $NoNewLine
            }
        }
    }

    if($PSBoundParameters.ContainsKey('EventId') -and $eventType -ne 'Skip'){
        if(!$EventLog) {
            $EventLog = $global:logging.$LogFileName.EventLog
        }

        if(!$EventLogSource) {
            $EventLogSource = $global:logging.$LogFileName.EventLogSource
        }

        $newEventSplat = @{
            EventId        = $EventId
            Message        = $Message -join "`r`n"
            EventLog       = $EventLog
            EventLogSource = $EventLogSource
            Туре           = $eventType
        }
        New-MSLogEvent @newEventSplat
    }
}
end{
    if($Type -in 'Exit', 'Terminate'){
        if($LogFileName) {
            New-MSLogFooter -LogFileName $LogFileName

            if($null -eq $ExitCode -or $ExitCode -isnot [int]){
                if($global:logging.$LogFileName._ErrorsLogged){
                    $ExitCode = 1
                }
                elseif($global:logging.$LogFileName._WarningsLogged) {
                    $ExitCode = 2
                }
                else{
                    $ExitCode = 0
                }
            }

            if(!$IgnoreLog) {
                $emailCfg = $global:logging.$LogFileName
                if($emailCfg._emailTo -and $emailCfg._smtpserver -and
                    $emailCfg._emailFrom -and $emailCfg._emailSubject){
                    $contents = ""
                    foreach($log in $global:logging.Keys) {
                        if($global:logging.$log._ErrorsLogged) {
                            $contents += (Get-Content -path $global:logging.$log.LogPath -Encoding utf8) -join "`r`n"
                            $contents += "`r`n" + "`r`n" + ("-" * 200) + "`r`n"
                            $global:logging.$log._ErrorsLogged = 0
                        }
                    }

                    if($contents){
                        $sendMailSplatting = @{
                            SmtpServer = $global:logging.$LogFileName._smtpserver
                            To = $global:logging.$LogFileName._EmailTo
                            Subject = $global:logging.$LogFileName._emailSubject
                            From = $global:logging.$LogFileName._emailFrom
                            Body = $contents
                            Encoding = 'utf8'
                            Attachments = $global:logging.$LogFileName.LogPath
                        }
                        Send-MailMessage @sendMailSplatting
                    }
               }
            }
            else{
                Remove-Item -Path $global:logging.$LogFileName.LogPath
            }

            if($global:logging.$LogFileName._UseOutput) {
                get-content -Path $global:logging.$LogFileName.LogPath -encoding utf8

                $parentName = $global:logging.$LogFileName._parentprocess.Name
                $isGui = $parentName -in 'exporer.exe', 'WindowsTerminal.exe' -or $Host.Name -match 'ISE|Visual Studio'
                if($PSBoundParameters.logrealdepth -lt 1 -and $isGui){
                    throw "$($Type)ing session with exit code $ExitCode"
                }
                else{
                    exit $ExitCode
                }
            }
            elseif($global:logging.$LogFileName.ScriptName -ne 'Interactive'){
                if($parentName -in 'exporer.exe', 'WindowsTerminal.exe' -or $Host.Name -match 'ISE|Visual Studio') {
                    exit $ExitCode
                }
                else{
                    [environment]:: Exit($ExitCode)
                }
            }
        }

        if($PSBoundParameters.logrealdepth -eq 0){
            return
        }
        else{
            throw "Interactive exit: $ExitCode"
        }
    }
}
}

##########################################
######## New-MSLogEvent
##########################################

function New-MSLogEvent {
<#
.SYNOPSIS
   Writes an event entry to the Windows Event Log.
.DESCRIPTION
   This function resolves event log settings from explicit parameters or the current logging
   context and writes a Windows Event Log record with the requested type and message.
.EXAMPLE
   New-MSLogEvent -EventId 1001 -Message 'Job started' -Type Information
   Writes an informational event with ID 1001.
.EXAMPLE
   New-MSLogEvent -EventId 9001 -Message @('Failure detected', 'See log for details') -Type Error
   Writes a multi-line error event.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    None. This function does not emit output.
#>
param(
    # Windows Event ID to write.
    [Parameter(Mandatory = $true)][int] $EventId,
    # Event message lines.
    [Parameter(Mandatory = $true)][string[]] $Message,
    # Target Windows Event Log name.
    [string] $EventLog,
    # Target Windows Event Log source.
    [string] $EventLogSource,
    # Windows event entry type.
    [ValidateSet('Information', 'Warning', 'Error', 'FailureAudit', 'SuccessAudit')][string] $Type = 'Information',
    # Target log context key.
    [string] $LogFileName
)
    if($PSBoundParameters.ContainsKey('logfilename') -and !$LogFileName) {
        return
    }

    $LogFileName = Get-MSLogFileName

    if(!$EventLog) {
        $EventLog = $global:logging.$LogFileName.EventLog
    }

    if(!$EventLogSource){
        $EventLogSource = $global:logging.$LogFileName.EventLogSource
    }

    $sourceExists = [System.Diagnostics.EventLog]::SourceExists($EventLogSource)
    if(-not $sourceExists -and $global:logging.$LogFileName.IsAdministrator) {
        try{
            New-EventLog -LogName $EventLog -Source $EventLogSource -ErrorAction Stop
        }
        catch{
            throw $_
        }
    }
    
    $eventParameters = @{
        LogName = $EventLog
        Source = $EventLogSource
        EventId = $EventId
        EntryType = $Type
        Message = $message-join "`r`n"
        Category = 0
    }
    try{
        Write-EventLog @eventParameters -ErrorAction Stop
    }
    catch{
        throw $
   }
}

##############################################################
####         New-MSLogFile
##############################################################

function New-MSLogFile {
<#
.SYNOPSIS
   Creates or resolves a timestamped log file.
.DESCRIPTION
   This function ensures the target log directory exists, computes the file name based on
    date and time by default or date-only when Daily is used, removes obsolete log files according to retention,
    and returns file metadata including a log key and delayed log entries.
.EXAMPLE
    New-MSLogFile -Name 'Job.log' -Path 'C:\Logs -KeepDays 30
    Creates or resolves today's log file and applies 30-day retention cleanup.
.EXAMPLE
    New-MSLogFile -Name 'Job.log' -Path 'C:\Logs -Daily -Overwrite
   Creates a date-only log file and overwrites any existing file with the same name.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
   System.IO.FileInfo
#>
[cmdletbinding()]
param(
    # Base file name to be created 'Demo.log'. The actual file will have a date_time inserted: Demo_20260630_145940.log.
    [string] $Name,
    # Destination folder path.
    [string] $Path,
    # Number of days to keep older logs.
    [int]    $KeepDays = 90,
    # Uses daily date granularity for file names, no hour-minue-seconds in the file name.
    [switch] $Daily,
    # Overwrites existing file if present.
    [switch] $Overwrite,
    # Explicit date suffix used in file name, instead of the date_time.
    [string] $DatePart,
    # Active log context key for defaults.
    [string] $LogFileName
)
    if(!$Path) {
        $LogFileName = Get-MSLogFileName -IgnoreNoLogFileName

        $Path = $global:logging.$LogFileName.LogFolder
    }

    if(!(Test-Path -Path $Path -PathType Container)) {
        [void] (New-Item -Path $Path -ItemType Directory -ErrorAction Stop)
    }

    if(!$Daily -and !$DatePart){
        $DatePart = Get-Date -Format 'yyyyMMdd_HHmmss'
    }
    elseif(!$DatePart){
        $DatePart = Get-Date -Format 'yyyyMMdd'
    }

    $filename = $Name -replace "(?=\.(?!.*?\.))", "_$DatePart"

    if($PSBoundParameters.ContainsKey('datepart')){
        $key = $filename
    }
    else{
        $key = $Name
    }

    if($LogFileName) {
        $delayedLogEntries = Remove-MS LogObsolete File -KeepDays $KeepDays -LogFileName $LogFileName
    }
    else{
        $delayedLogEntries = Remove-MS LogObsoleteFile -BaseFileName $Name -Path $Path -KeepDays $KeepDays
    }

    if($Overwrite -or (!(Test-Path -Path (Join-Path -Path $Path -ChildPath $filename)))){
        $file = New-Item -Path $Path -Name $filename -ItemType file -Force: $Overwrite |
            Add-Member -Member Type NoteProperty -Name New -Value $true -Pass Thru -ErrorAction Stop
    }
    else{
        $file = Get-Item -Path (Join-Path -Path $Path -ChildPath $filename) |
            Add-Member -Member Type NoteProperty -Name New -Value $false -PassThru
    }

    if(!$file){
        throw "Couldn't create log file at '$(Join-Path -Path $Path -ChildPath $filename)'"
    }

    Add-Member -InputObject $file -MemberType NoteProperty -Name Key -Value $key
    Add-Member -InputObject $file -MemberType Note Property -Name Delayed LogEntries -Value $delayed LogEntries -Pass Thru
}

###########################################
######## New-MSLogFooter
###########################################

function New-MSLogFooter {
<#
.SYNOPSIS
    Writes a summary footer entry for the active log.
.DESCRIPTION
    This function validates the target log name, computes runtime duration, and writes
    footer details including total errors, warnings, and parent process information.
.EXAMPLE
    New-MSLogFooter -LogFileName 'Job.log'
    Writes a footer summary to the specified log context.
.EXAMPLE
    New-MSLogFooter
    Writes a footer summary to the current active log context.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    None. This function does not emit output.
#>
param(
    # Target log context key.
    [string] $LogFileName
)
    if($PSBoundParameters.ContainsKey('logfilename') -and !$LogFileName) {
        return
    }

    $LogFileName = Get-MSLogFileName

    if(!$LogFileName -or !$global:logging.ContainsKey($LogFileName)) {
        $LogFileName = $null
        if($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation' -or $host.name -eq 'Default Host'){
            Write-Error -Message "LogFileName $LogFileName' is not valid"
            $global:Error.RemoveAt(0)
        }
        else{
           Write-Host -Object "LogFileName '$LogFileName' is not valid" -ForegroundColor Red
        }
    }

    $seconds = [int] ((Get-Date) - $global:logging.$LogFileName.LogStart).totalseconds

    if($LogFileName) {
        $footer =   "LogFileName   : $LogFileName",
                    "Runtime       : $([timespan]:: FromSeconds($seconds).tostring())",
                    "Errors Logged : $($global:logging.$LogFileName._ErrorsLogged)",
                    "WarningsLogged: $($global:logging.$LogFileName._WarningsLogged)",
                    "ParentProcess : $($global:logging.$LogFileName._parentprocess.name)"
   }
   else{
        $footer =   "LogFileName   : <none>",
                    "Runtime       : $([timespan]::FromSeconds($seconds).tostring())",
                    "ErrorsLogged  : <unknown>",
                    "WarningsLogged: <unknown>",
                    "ParentProcess : <unknown>"
   }

   $footer | FormatBorder | New-MSLogEntry -type Footer
}

###########################################
######## Remove-MS LogObsoleteFile
###########################################

function Remove-MSLogObsoleteFile {
<#
.SYNOPSIS
   Removes log files older than the specified retention period.
.DESCRIPTION
   This function scans the target folder for dated log files matching the given base name,
   and deletes any file whose last write time exceeds the retention threshold. When no active
   log context is available, removal messages are collected as delayed log entries and returned
   for later logging.
.EXAMPLE
   Remove-MSLogObsolete File -BaseFileName 'Job.log' -Path 'C:\Logs -KeepDays 30
   Deletes all date-stamped Job log files older than 30 days from C:\Logs.
.EXAMPLE
   Remove-MSLogObsolete File -BaseFileName 'Job.log' -Path 'C:\Logs -KeepDays 0
   Skips retention cleanup (KeepDays 0 disables removal).
.INPUTS
   None. This function does not accept pipeline input.
.OUTPUTS
   System.String[]
   Returns delayed log entry strings when no active log context exists at call time.
#>
[cmdletbinding (DefaultParameterSetName = 'ByFile')]
param(
    # Name of the files to be purged without the timestamp pattern, if the files have this name pattern 'DemoLog_20260630_132442.log' then the -BaseFileName is 'DemoLog.log'.
    [Parameter(Mandatory = $true, ParameterSetName = 'ByFile')] [Alias('ScriptName')] [string] $BaseFileName,
    # Folder path containing files to be purged.
    [Parameter(Mandatory = $true, ParameterSetName = 'ByFile')] [string] $Path,
    # Number of days to retain old log files.
    [Alias('DaysToKeep')] [int]    $KeepDays = 90,
    # Active log context key for inline logging.
    [Parameter(Mandatory = $true, ParameterSetName = 'ByLog')] [string] $LogFileName
)

    $delayedLogEntries = @()

    if($KeepDays){
        if($PSCmdlet.ParameterSetName -eq 'ByLog') {
           $LogFileName = Get-MSLogFileName
           $Path = $global:logging.$LogFileName.LogPath
           $BaseFileName = $LogFileName -replace '_[^.]+(?=\.\w+$)'
        }

        $extension = $BaseFileName -replace '.*?(\.[^.]+)?$', '$1'

        if(!$extension) {
           $extension = '.log'
        }

        $searchname = ($BaseFileName -replace "\.[^,]+$") + "_*" + $extension

        Get-ChildItem -Path $Path -Filter $searchname -ErrorAction Ignore |
            Where-Object -FilterScript {((get-date) - $_.LastWriteTime).totaldays -gt $KeepDays} |
            ForEach-Object -Process {
                $loggingVar = Get-Variable -name logging -scope Global -erroraction Ignore

                try{
                    Remove-Item -Path $_.FullName -ErrorAction Ignore
                    if(!$LogFileName -or !$loggingVar -or !$global:logging.$LogFileName) {
                       $delayedLogEntries += "Removing obsolete file: '$($_.FullName)*"
                    }
                    else{
                        $entryParams = @{
                            message     = "Removing obsolete file: '$($_.FullName)*"
                            indentlevel = 1
                            LogFileName = $LogFileName
                        }
                        New-MSLogEntry @entryParams
                   }
                }
                catch{
                    $global:Error.RemoveAt(0)
                    if(!$LogFileName -or !$loggingVar -or !$global:logging.$LogFileName) {
                        $delayedLogEntries += "Failed to remove obsolete file: '$($_.FullName)'"
                    }
                    else{
                       $entryParams = @{
                            message     = "Failed to remove obsolete file: '$($_.FullName)'"
                            indentlevel = 1
                            LogFileName = $LogFileName
                        }
                        New-MSLogEntry @entryParams
                    }
                }
            }
    }

    $delayedLogEntries
}

###########################################
######## Search -MSLogEntries
###########################################

function Search-MSLogEntries {
<#
.SYNOPSIS
    Searches and formats entries from one or more log files.
.DESCRIPTION
    This function resolves log paths from active log names or explicit paths, imports log files
    as CSV records, applies an optional filter script, and returns formatted table output.
    It can search across all date-stamped files and supports sorting.
.EXAMPLE
    Search -MSLogEntries -LogFileNames 'Job.log'
    Returns default filtered entries for the specified log name.
.EXAMPLE
    Search -MSLogEntries -LogPath 'C:\Logs -AllDates -FilterScript { $_.Type -eq 'ERROR' }
    Searches all dated logs in the folder and returns only error entries.
.INPUTS
    System.String[]
.OUTPUTS
    System.String[]
#>
param(
    # Log context keys to search.
    [string[]] $LogFileNames = $global:logging.Keys,
    # One or more file or folder paths to search.
    [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)] [string[]] $LogPath,
    # Filter applied to imported CSV log entries.
    [scriptblock] $FilterScript,
    # Includes all date-suffixed log files.
    [switch] $AllDates,
    # Properties used for sorting results.
    [AllowNull()] [string[]] $SortBy,
    # Sort results in descending order.
    [switch] $Descending
)
begin{
    if($LogPath) {
        if($PSBoundParameters.ContainsKey('logfilenames')) {
            $LogPath = Get-ChildItem -Path $LogPath -Include $LogFileNames -Recurse |
                Select-Object -ExpandProperty fullname
        }
        else{
            $LogPath = Get-ChildItem -Path $LogPath | Select-Object -ExpandProperty fullname
        }
    }
    elseif($LogFileNames) {
        foreach ($1n in $LogFileNames) {
            $LogPath += $global:logging.$1n.LogPath
        }
    }
}
process{
    $DefaultFilterScript = { $_.Line -match '^\[\s*\d+\]$' }

    foreach ($1p in $LogPath) {
        if($AllDates) {
            $lp = $1p -replace "-\d{8,}(?=\.[^\.]+$)", '*'
        }
        if($lp -notmatch "\.log"){
            $lp += "\*"
        }

        if($SortBy) {
            if($FilterScript){
               Get-Item -Path $lp -PipelineVariable path -ErrorAction Ignore | ForEach-Object -Process {$_.fullname} |
                    Import-Csv -Encoding Default |
                       Where-Object -FilterScript $DefaultFilterScript |
                       Where-Object -FilterScript $FilterScript |
                           Sort-Object -Property $SortBy -Descending:$Descending |
                            select-object -Property @{n="LogFileName"; e={$path.name}}, * |
                        Format-MSLogStringTable
            }
            else{
               Get-Item -Path $lp -PipelineVariable path -ErrorAction Ignore | ForEach-Object -Process {$_.fullname} |
                    Import-Csv -Encoding Default |
                        Where-Object -FilterScript $DefaultFilterScript |
                        Sort-Object -Property $SortBy -Descending:$Descending |
                        select-object -Property @{n="LogFileName"; e={$path.name}}, * |
                        Format-MSLogStringTable
            }
       }
       else{
            if($FilterScript) {
               Get-Item -Path $lp -PipelineVariable path -ErrorAction Ignore |
                    ForEach-Object -Process {$_.fullname} |
                    Import-Csv -Encoding Default |
                    Where-Object -FilterScript $DefaultFilterScript |
                    Where-Object -FilterScript $FilterScript |
                    select-object -Property @{n="LogFileName"; e={$path.name}}, * | Format-MSLogStringTable
            }
            else{
               Get-Item -Path $lp -PipelineVariable path -Error Action Ignore |
                    ForEach-Object -Process {$_.fullname} |
                    Import-Csv -Encoding Default |
                    Where-Object -FilterScript $DefaultFilterScript |
                    select-object -Property @{n="LogFileName"; e={$path.name}}, * | Format-MSLogStringTable
           }
        }
    }
}
}

#############################################
######        Write-MSLogProgress
#############################################

function Write-MSLogProgress {
<#
.SYNOPSIS
   Updates progress bar and periodic progress log entries.
.DESCRIPTION
   This function tracks progress for an input collection, updates interactive progress display,
   and periodically writes progress snapshots to the log. It preserves progress state in the
   active log context and supports explicit percent completion.
.EXAMPLE
   Write-MSLogProgress -InputArray $Servers -Activity 'Processing servers'
   Updates progress based on current counter state for the provided array.
.EXAMPLE
   Write-MSLogProgress -InputArray $Items -Activity 'Deploying' -Percent 45
   Logs and displays progress using an explicit completion percentage.
.INPUTS
   None. This function does not accept pipeline input.
.OUTPUTS
   None. This function does not emit output.
#>
[cmdletbinding()]
    param(
        # Collection being processed for progress tracking.
        $InputArray,
        # Activity name shown in progress output.
        [string] [Alias('Action')] $Activity,
        # Explicit percent completion override.
        [int] $Percent,
        # Target log context key.
        [string] $LogFileName,
        # Seconds before first progress log message.
        [int] $ProgressLogFirst
   )

    if(!$inputarray -or !$inputarray.count){
        return
    }

    if($PSBoundParameters.ContainsKey('logfilename') -and !$LogFileName) {
       return
    }

    $LogFileName = Get-MSLogFileName

    if(!$LogFileName -or !$global:logging.ContainsKey($LogFileName)) {
        $LogFileName = $null
        if($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation') {
            Write-Error -Message "LogFileName $LogFileName' is not valid"
            $global:Error.RemoveAt(0)
        }
        else{
            Write-Host -Object "LogFileName $LogFileName' is not valid" -ForegroundColor Red
        }
        return
    }

    if($ProgressLogFirst -eq 0){
        $ProgressLogFirst = $global:logging.$LogFileName._Progress.LogFirst
    }

    if(-not (Get-Member -InputObject $global:logging.$LogFileName._Progress -Name ArrayRef -ErrorAction Ignore)) {
        Add-Member -InputObject $global:logging.$LogFileName._Progress -MemberType NoteProperty -Name ArrayRef -Value $null
    }

    if(-not [object]:: ReferenceEquals($inputarray, $global:logging.$LogFileName._Progress.ArrayRef)) {
       $global:logging.$LogFileName._Progress.ArrayRef = $inputarray
       $global:logging.$LogFileName._Progress.Start = get-date
       $global:logging.$LogFileName._Progress.BarNext = get-date
       $global:logging.$LogFileName._Progress.Counter = 0
       $global:logging.$LogFileName._Progress.LogNext = (get-date).AddSeconds($ProgressLogFirst)
    }

    $progress = $global:logging.$LogFileName.Progress
    $verboseActive = $global:logging.$LogFileName._VerboseMode -or $PSBoundParameters.verbose
    if((Get-Date) -ge $progress.BarNext -and $verboseActive) {
        if(!$PSBoundParameters.ContainsKey('percent')){
           $percent = $progress.Counter / $inputarray.count * 100
        }

        if($percent -gt 100){
            $percent = 100
        }

        if($progress.Counter -eq 0) {
            $timeleft = [int]::MaxValue
        }
        else{
            $elapsed = ((Get-Date) - $progress.Start).totalseconds
            $timeleft = $elapsed * ($inputarray.Count - $progress.Counter) / $progress.Counter
        }

        $done = "{0,$("$($inputarray.Count)".Length)}" -f $progress.Counter
        $left = "{0,$("$($inputarray.Count)".Length)}" -f ($inputarray.Count - $progress.Counter)
        $wpSplat = @{
           Activity          = $Activity
           Status            = "All: $($inputarray.Count) Done: $done Left: $left"
           PercentComplete   = $percent
           SecondsRemaining  = $timeleft
        }
        Write-Progress @wpSplat
        $progress.BarNext = (get-date).AddSeconds($progress.BarSec)
    }

    if((Get-Date) -ge $progress.LogNext) {
        if($progress.Counter -eq 0) {
           $timeleft = [int]::MaxValue
        }
        else{
           $elapsed = ((Get-Date) - $progress.Start).totalseconds
           $timeleft = [int] ($elapsed * ($inputarray.Count - $progress.Counter) / $progress.Counter)        
        }

        $timeleft = [timespan]::FromSeconds($timeleft).tostring()

        $done = "{0,$("$($inputarray.Count)".Length)}" -f $progress.Counter
        $left = "{0,$("$($inputarray.Count)".Length)}" -f ($inputarray.Count - $progress.Counter)

        $progressMsg = "All: $($inputarray.Count) Done: $done Left: $left Estimated time left: $timeleft"
        New-MSLogEntry -message $progressMsg -type Progress

        $progress.LogNext = (get-date). AddMinutes($progress.LogMin)
    }

    $progress.Counter++
}

###########################################
######## Write-MS LogUnhandled Errors
###########################################

function Write-MSLogUnhandledErrors {
<#
.SYNOPSIS
   Logs unhandled errors from the global error collection.
.DESCRIPTION
   This function copies and reverses entries from the global Error collection, clears the
   original collection, writes each error as an Unhandled log entry, and increments the
   unhandled error counter in the current log context.
.EXAMPLE
   Write-MSLogUnhandledErrors
    Flushes currently unhandled errors into the active log.
.INPUTS
   None. This function does not accept pipeline input.
.OUTPUTS
   None. This function does not emit output.
#>
param(
    # Target log context key.
    [string] $LogFileName
)
    $LogFileName = Get-MSLogFileName

    $scripterror = Get-Variable -Name Error -Scope Global -ValueOnly

    if($scripterror) {
        $err2 = $scripterror.clone()
        $err2.reverse()
        foreach($err in $err2){
            if($err.FullyQualifiedErrorId -in 'PesterAssertionFailed', 'PesterTestSkipped'){
                continue
            }

            $errMsg = "$($err.ScriptStackTrace): $($err.Exception.Message)"
            New-MSLogEntry -message $errMsg -type Unhandled -LogFileName $LogFileName
            $global:logging.$LogFileName._UnhandledErrors++
        }

        $global:Error.Clear()
    }
}

#endregion

#region PSData management
function ResolveDynamicData {
param(
    $PSDatahive,
    [switch] $dontexpand
)
    if($PSDatahive -is [scriptblock]){
        $PSDatahive = @{__PSDataScriptBlockArray = $PSDatahive}
    }
    elseif($PSDatahive -isnot [System.Collections.IDictionary]){
        return [pscustomobject]@{
                    UpdatedElement = $PSDatahive
                    SkipAll = $dontexpand
                }
    }

    $PSDataHiveKeys = $PSDatahive.Keys.ForEach({$_})

    foreach($key in ($PSDataHiveKeys | Sort-Object -Property {
                if($_ -match '^Condition$'){"zz$($_)"}
                elseif($_ -match '^ConfigAction'){"zzz$($_)"}
                elseif($_ -match '^Conditional_'){"zzzz$($_)"}
                else{"__$($_)"}
            }
        )
   ){
        if($PSDatahive.$key -is [System.Collections.IDictionary]){
            ResolveDynamic Data -PSDatahive $PSDatahive.$key -dontexpand:$dontexpand
        }
        elseif($PSDatahive.$key -is [System.Object[]]){
            for($i = 0; $i -lt $PSDatahive.$key.count; $i++){
                if($PSDatahive.$key[$i] -is [System.Collections.IDictionary]){
                    ResolveDynamicData -PSDatahive $PSDatahive.$key[$i] -dontexpand: $dontexpand
                }
                else{
                    $result = ResolveDynamicData -PSDatahive $PSDatahive.$key[$i] -dontexpand:$dontexpand
                    $PSDatahive.$key[$i] = $result.UpdatedElement
                    if($result.SkipAll){
                        $dontexpand = $true
                        break
                    }
               }
           }
        }
        elseif($PSDatahive.$key -is [scriptblock] -and ($PSDatahive.Keys -notcontains 'Condition' -or $PSDatahive.Condition)) {
            [ref] $errors = $null
            $tokens = [System.Management.Automation.PSParser]::Tokenize($PSDatahive.$key, $errors)
            $skip = $dontexpand

            if(!$skip){
                foreach($token in $tokens) {
                    if($token.type -eq 'GroupStart') {
                        continue
                    }
                    if($token.Type -eq 'Comment' -and $token.Content -match "DontExpand"){
                        if($token.Content -match "DontExpandAll") {
                            $dontexpand = $true
                        }

                        $skip = $true
                        break
                    }
                    elseif($token.Type -ne 'NewLine'){
                        break
                    }
                }
            }

            if(!$skip){
                $errorhappened = $false
                $errorcount = $Error.Count
                try{
                    $PSDatahive.$key = & $PSDatahive.$key
                }
                catch{
                    $errorhappened = $true
                }

                if($errorhappened -or $errorcount -gt $error.Count) {
                    throw "PSData parsing error"
                }
            }

            if($key -eq '__PSDataScriptBlockArray'){
                [pscustomobject]@{
                    UpdatedElement = $PSDatahive.$key
                    SkipAll = $dontexpand
               }
            }
        }
    }
}

function MergeHives {
    param(
        [System.Collections.IDictionary] $hive,
        [System.Collections.IDictionary] $target = $PSData
    )

    foreach ($h in $hive.Getenumerator()) {
        if($h.key -match '^Condition|^ConfigAction'){
            continue
        }
    }
    elseif($h.value -isnot [System.Collections.IDictionary]){
        $target.($h.key) = $h.value
    }
    elseif($target.Keys -notcontains $h.key) {
        $configActions = @($h.value.keys) -match '^ConfigAction'
        foreach ($ca in $configActions){
            $h.value.remove($ca)
        }

        $target. ($h.key) = $h.value
    }
    else{
        try{
            MergeHives -hive $h.value -target $target.($h.key)
        }
        catch{
        }
    }
}

function Import-PSData {
[cmdletbinding()]
param(
    [string[]]$PathsOrNames,
    [Parameter(Mandatory = $false)] [System.Collections.IDictionary] $PSData,
    [switch] $PassThru
)

    $initiatePSConfig = $false
    if($null -eq $PSData) {
        $PSData = @{}
        
        if(!(Get-Variable -Name PSConfig -Scope Global -ErrorAction Ignore)) {
            $initiatePSConfig = $true
        }
    }

    $scriptinvocation = Get-PSCallStack | Where-Object {$_.Location -notlike 'ScriptTools.psm1*'} | Select-Object -First 1 -ExpandProperty Invocation Info
    
    if($scriptinvocation.mycommand.path) {
        $basepath = $scriptinvocation.mycommand.path
    }
    elseif($scriptinvocation.MyCommand.Module -and $scriptinvocation.MyCommand.Module.Path) {
        $basepath = $scriptinvocation.MyCommand.Module.Path
    }

    if($basepath -match "\\\d+\.\d+\.\d+\\.*?ps(m)?1$"){
        $defaultconfig = $scriptinvocation.mycommand.path -replace "\\\d+\.\d+\.\d+\\(?!.*?\\)", "\Config\" -replace "\.ps(m)?1$", ".data.ps1"
    }
    else{
        $defaultconfig = $basepath -replace "\\(?!.*?\\)", "\Config\" -replace "\.ps(m)?1$", ".data.ps1"
    }

    if(!$PathsOrNames -and (!$defaultconfig -or !(test-path -path $defaultconfig))){
        if(get-module -Name "PSConfigs" -ErrorAction Ignore -ListAvailable){
            Import-Module -Name PSConfigs -Force
            $defaultconfig = Get-PSConfigs -ScriptName $scriptinvocation.MyCommand.Name
        }
    }

    if($defaultconfig -and $PathsOrNames -notcontains $defaultconfig -and (Test-Path $defaultconfig)){
        $PathsOrNames = @($defaultconfig) + $PathsOrNames | Where-Object {$_}
    }

    foreach ($Path in $PathsOrNames) {
        if($Path -notlike "*.data.ps1"){
            throw "Name of the PS data file must end with '.data.ps1'"
        }

        if($Path -notmatch "^\w+:|^\.|^\\\\"){\
            $Path = Join-Path (split-path $scriptinvocation.mycommand.path) "\Config\$Path"
        }

        if(!(Test-Path -Path $Path)){
            Write-Error "No PS data file was found at '$Path'"
            continue
        }

        $realPath = Resolve-Path -Path $Path | Select-Object -ExpandProperty ProviderPath

        $authenticode = Get-AuthenticodeSignature -FilePath $realPath -ErrorAction Ignore

        if(!$authenticode -or $authenticode.Status -notin 'Valid', 'NotSigned'){
            throw "Signature is not valid on data file '$realPath"
        }

        $tokens = [System.Management.Automation.Language.Token[]]::new(1)
        $errors = [System.Management.Automation.Language.ParseError[]]::new(1)

        $AST = [System.Management.Automation.Language.Parser]:: ParseFile(
                    $realPath,
                    [ref] $tokens,
                    [ref] $errors
                )

        if($errors) {
            throw "There are errors in PS data file '$Path'"
        }

        $topLevelLayer = $AST.Find({$true}, $false)

        $topLevelExtentText = Get-Property -Object $topLevelLayer -PropertyPath '[0].EndBlock.Extent.Text' -ValueOnly

        if(!$topLevelExtentText -or $topLevelExtentText.trim() -notmatch '^(\[(ordered|pscustomobject|System\.Management\.Automation\.PSCustomObject)\]\s*)?\s*@\{'){
            throw "PS data file '$Path' must contain a single hash literal"
        }

        $allCommands = @($AST.FindAll({$args[0] -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or
                                        $args[0] -is [System.Management.Automation.Language.CommandAst] -or
                                        $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or
                                        $args[0] -is [System.Management.Automation.Language.CommandExpressionAst]}, $true))

        foreach($command in $allCommands) {
            Update-Property -Object $command.Parent -PropertyPath Children -Value $command
        }

        $errors = $false

        for($i=1; $i -lt $allCommands.count; $i++){
            $command = $allCommands[$i]

            $currentLevel = $command
            $prevprevprev = $null
            $prevprev = $null
            $prev = $null
            while($currentLevel -and $currentLevel -isnot [System.Management.Automation.Language.HashtableAst]){
                $prevprevprev = $prevprev
                $prevprev = $prev
                $prev = $currentLevel
                $currentLevel = $currentLevel.Parent
            }

            if($prevprevprev -isnot [System.Management.Automation.Language.ScriptBlockExpressionAst] -and
                !($command.Children -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or
                $command.Expression -is [System.Management.Automation.Language.HashtableAst] -or
                $command.Expression -is [System.Management.Automation.Language.ConstantExpressionAst] -or
                $command.Expression -is [System.Management.Automation.Language.ConvertExpressionAst] -or
                $command.Expression -is [System.Management.Automation.Language.ArrayLiteralAst] -or
                $command.Expression -is [System.Management.Automation.Language.BinaryExpressionAst] -or
                $command.Expression -is [System.Management.Automation.Language.VariableExpressionAst] -or
                $command.Expression -is [System.Management.Automation.Language.ArrayExpressionAst])){
                    throw "Commands are allowed only in scriptblocks: $($prev.extent)"
            }
        }
        try{
            $Config = & $Path
        }
        catch{
            throw $_
        }

        ResolveDynamicData -PSDatahive $Config

        $ConfigKeys = @($Config.Keys.foreach({$_}))

        foreach($key in ($ConfigKeys -notmatch '^Condition' | Sort-Object)){
            MergeHives -hive $Config
        }

        foreach($key in ($ConfigKeys -match '^Conditional_' | Sort-Object)){
            if($Config.$key.condition){
                MergeHives -hive $Config.$key
                $Config.Remove($key)
            }
        }
    }

    if($initiatePSConfig) {
        $global:PSConfig = $PSData
    }

    if($PassThru){
        $PSData
    }
}

function ConvertTo-PSData {
[cmdletbinding()]
param(
    [Parameter(ValueFromPipeline = $true)] $Object,
    [Parameter(DontShow = $true)] [string] $Name,
    [switch] $Compress,
    [Parameter(DontShow = $true)] [int] $IndentLevel = 0
)
    if($Name) {
        if($Name -match "\W" -and $Name -notmatch "^('|"").*\1$"){
            $Name = "'$Name'"
        }

        if($Compress) {
            $open = "$Name="
        }
        else{
            $open = "$Name = "
        }
    }
    else{
        $open = ""
    }

    if($null -eq $object) {
        $fullType = "NULL"
        $shortType = "NULL"
    }
    else{
        $fullType = $Object.gettype().fullname
        $originalType = $Object.gettype().fullname
        $shortType = $Object.gettype().name
        $brackets = ''

        if($fullType -match '\[\]$'){
            $brackets = '[]'
        }

        if($object -is [System.Enum]){
            $fullType = "System.Enum$($brackets)"
            $shortType = $Object.gettype().fullname + $brackets
        }
        elseif($fullType -notmatch '\.'){\
            $fullType = 'System.Management.Automation.PSCustomObject' + $brackets
        }
    }

    if($fullType -match "\[\]$" -or $Object -is [System.Collections.IList]){
        if($fullType -match "^System\.Object"){
            $open += "@("
            $close = ")"
        }
        else{
            if($Compress){
               $open += "[$($originalType)]@("
            }
            else{
               $open += "[$($originalType)] @("
            }
            $close = ")"
        }

        if($Compress) {
            $joinchar = ","
        }
        else{
            $joinchar = ", "
        }

       $multiline = $false
       $strelements = @()
       foreach($elem in $object) {
            $strelem = ConvertTo-PSData -Object $elem -Compress:$Compress
            
            if($elem -is [System.Object[]]){
               $strelem = "," + $strelem
            }

            $strelements += $strelem
            if(!$multiline -and $strelem -match '\n'){
               $multiline = $true
            }
        }

        if(!$Compress -and $multiline) {
            $joinchar += "`r`n"
            $strelements = @($open) +
                            (($strelements | &{process{
                                $parts = $_ -split "\r\n"
                                ($parts | &{process{" " * 4 + $_}}) -join "`r`n"
                           }}) -join $joinchar) +
                           $close

            $strelements | &{process{
                        $parts = $_ -split "`r`n"
                        ($parts | &{process{"" * $IndentLevel * 4 + $_}}) -join "`r`n"
                    }}
        }
        else{
            if($Compress){
                $open + ($strelements -join $joinchar) + $close
            }
            else{
                " " * $IndentLevel * 4 + $open + ($strelements -join $joinchar) + $close
            }
        }
    }
    else{
        switch ($fullType) {
            "NULL" {
                        if($Compress) {
                           $open + '$null'
                        }
                        else{
                           " " * $IndentLevel * 4 + $open + '$null'
                        }
                        break
                   }

           "System.Collections.Hashtable" {
                                    $open += "@{"
                                    
                                    if($Compress) {
                                        $out = @($open)
                                    }
                                    else{
                                       $out = @(" " * $IndentLevel * 4 + $open)
                                    }

                                    foreach($key in $Object.keys) {
                                       $out += ConvertTo-PSData -Object $0bject.$key -IndentLevel ($IndentLevel + 1) -Name $key -Compress:$Compress
                                    }

                                    if($Compress) {
                                        "$($out[0])" + ($out[1..($out.count -1)] -join ";") + "}"
                                    }
                                    else{
                                        $out += " " * $IndentLevel * 4 + "}"
                                        $out -join "r`n"
                                    }
                                    break
                                }

           "System.Collections.Specialized.OrderedDictionary" {
                                    if($Compress) {
                                        $open += "[ordered]@{"
                                        $out = @($open)
                                    }
                                    else{
                                        $open += "[ordered] @{"
                                        $out = @(" " * $IndentLevel * 4 + $open)
                                    }

                                    foreach($key in $Object.keys) {
                                        $out += ConvertTo-PSData -Object $Object.$key -IndentLevel ($IndentLevel + 1) -Name $key -Compress:$Compress
                                    }

                                    if($Compress) {
                                        "$($out[0])" + ($out[1..($out.count -1)] -join ";") + "}"
                                    }
                                    else{
                                        $out += " " * $IndentLevel * 4 + "}"
                                        $out -join "`r`n"
                                    }
                                    break
                                }

            "System.String" {
                                    if($Compress) {
                                        $open + "'$($Object -replace "'", "''")'"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "'$($Object -replace "'","''")'"
                                    }
                                    break
                                }

            "System.Char" {
                                    if($Compress) {
                                        $open + "[char]'$Object'"
                                    }
                                    else{
                                        " " + $IndentLevel * 4 + $open + "[char] '$Object'"
                                    }
                                    break
                                }

            "System.Version" {
                                    if($Compress) {
                                        $open + "[version]'$Object'"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[version] '$Object'"
                                    }
                                    break
                                }

            "System.Management.Automation.ScriptBlock" {
                                    if($Compress) {
                                        $open + "{$object}"
                                    }
                                    else{
                                          " " * $IndentLevel * 4 + $open + "{$object}"
                                    }
                                    break
                                }

            "System.DateTime" {
                                    if($Compress) {
                                        $open + "[DateTime]'$(get-date -Date $Object -Format 'yyyy.MM.dd HH:mm:ss')'"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[DateTime] '$(get-date -Date $Object -Format 'yyyy.MM.dd HH:mm:ss')'"
                                    }
                                    break
                                }

            "System.TimeSpan" {
                                    if($Compress) {
                                        $open + "[TimeSpan]'$Object'"
                                    }
                                    else{
                                         " " * $IndentLevel * 4 + $open + "[TimeSpan] '$Object'"
                                    }
                                    break
                                }

            "System.Byte" {
                                    if($Compress) {
                                        $open + "[byte]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[byte] $Object"
                                    }
                                    break
                                }

            "System.Int16" {
                                    if($Compress) {
                                        $open + "[System.Int16]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.Int16] $Object"
                                    }
                                    break
                                }

            "System.Int32" {
                                    if($Compress) {
                                        $open + "$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "$Object"
                                    }
                                    break
                                }

            "System.Int64" {
                                    if($Compress) {
                                        $open + "[System.Int64]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.Int64] $Object"
                                    }
                                    break
                                }

            "System.UInt16" {
                                    if($Compress) {
                                        $open + "[System.UInt16] $0bject"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.UInt16] $Object"
                                    }
                                    break
                                }

            "System.UInt32" {
                                    if($Compress) {
                                        $open + "[System.UInt32] $0bject"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.UInt32] $Object"
                                    }
                                    break
                                }

            "System.UInt64" {
                                    if($Compress) {
                                        $open + "[System.UInt64]$0bject"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.UInt64] $Object"
                                    }
                                    break
                                }

            "System.Decimal" {
                                    if($Compress) {
                                        $open + "[System.Decimal]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.Decimal] $Object"
                                    }
                                    break
                                }

            "System.Double" {
                                    if($Compress) {
                                        $open + "[System.Double]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.Double] $Object"
                                    }
                                    break
                                }

            "System.Single" {
                                    if($Compress) {
                                        $open + "[System.Single]$0bject"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.Single] $Object"
                                    }
                                    break
                                }

            "System.Enum" {
                                    if($Compress) {
                                        $open + "[$shortType]'$Object'"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[$shortType] '$Object'"
                                    }
                                    break
                                }

            "System.Management.Automation.PSCustomObject" {
                                    if($Compress) {
                                        $open += "[$shortType]@{"
                                        $out = @($open)
                                    }
                                    else{
                                        $open += "[$shortType] @{"
                                        $out = @(" " * $IndentLevel * 4 + $open)
                                    }

                                    foreach($prop in $Object.psobject.properties.name){
                                        $out += ConvertTo-PSData -Object $Object.$prop -IndentLevel ($IndentLevel + 1) -Name $prop -Compress:$Compress
                                    }

                                    if($Compress) {
                                        "$($out[0])" + ($out[1..($out.count -1)] -join ";") + "}"
                                    }
                                    else{
                                        $out += " " * $IndentLevel * 4 + "}"
                                        $out -join "`r`n”
                                    }
                                    break
                                }

            "System.Boolean" {
                                    if($Object -eq $true){
                                        if($Compress) {
                                            $open + '$true'
                                        }
                                        else{
                                            " " * $IndentLevel * 4 + $open + '$true'
                                        }
                                    }
                                    else{
                                        if($Compress) {
                                            $open + '$false'
                                        }
                                        else{
                                            " " * $IndentLevel * 4 + $open + '$false'
                                        }
                                    }
                                    break
                                }

            default {
                $nameInMessage = $Name

                if(!$Name) {
                    $nameInMessage = Get-Variable -Name Name ValueOnly -Scope 1 -ErrorAction Ignore
                }

                throw "Couldn't convert datatype at '$nameInMessage': '$($Object.gettype().fullname)' - $Object"
            }
        }
    }
}

function Export-PSData {
[cmdletbinding()]
param(
    [Parameter(ValueFromPipeline = $true)] $Object,
    [Parameter(ValueFromPipeline = $false)] $Path
)
    $PSDataString = ConvertTo-PSData -Object $Object
    $resolvedPath = resolve-path -Path (split-path -path $Path) | Select-Object -ExpandProperty ProviderPath
    $leaf = Split-Path -Path $Path -Leaf
    Set-Content -Value $PSDataString -Path (Join-Path -Path $resolved Path -Child Path $leaf) -Encoding Default
}

function ConvertFrom-PSData {
param(
    [Parameter(ValueFromPipeline = $true)] [string] $PSDataString
)
begin{
    $allStrings = @()
}
process{
    $allStrings += $PSDataString
}
end{
    if(!$allStrings -or $allStrings.Trim() -notmatch "^(\[ordered\]\s*)?@\{"){
        $embed = $true
        $PSDataString = "@{PSDataEmbedding = $($PSDataString)}"
    }
                
    $exportFile = Join-Path $env:TEMP 'tempPS.data.ps1'
    Set-Content -Path $exportFile -Value $PSDataString
    $tempPSData = @{}
    Import-PSData -PathsOrNames $exportFile -PSData $tempPSData
    Remove-Item -Path $exportFile

    if($embed){
        return $tempPSData.PSDataEmbedding
    }
    return $tempPSData
}
}
#endregion

#region Miscellaneous functions
function New-DynamicParameter {
param(
    [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Mandatory = $true)] [string] $Name,
    [Parameter(ValueFromPipelineByPropertyName = $true)] [type]  $Type,
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
begin{
    $paramDictionary = new-object-TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
    $position = $StartPosition
}
process{
    if($null -eq $Condition -or (&$Condition)) {
        $attributeCollection = new-object -TypeName System.Collections.ObjectModel.Collection[Attribute]

        foreach($psn in $ParameterSetName){
            $attribute = new-object -TypeName System.Management.Automation.ParameterAttribute
            $attribute.ParameterSetName = $psn
            if($PSBoundParameters.ContainsKey('startposition')) {
                $attribute.Position = $position
                $position++
            }
            if($Mandatory -is [scriptblock]){
                $attribute.Mandatory = &$Mandatory
            }
            else{
                $attribute.Mandatory = $Mandatory
            }
            $attribute.ValueFromPipeline = $ValueFromPipeline
            $attribute.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName

            $attributeCollection.Add($attribute)
        }

        if($ValidationSet) {
            $vsa = New-Object -TypeName System.Management.Automation.ValidateSetAttribute -ArgumentList (&$ValidationSet)
            $attribute.HelpMessage = "Possible values: $((&$ValidationSet) -join ', ')"
            $attributeCollection.Add($vsa)
        }

        if($Aliases) {
            $alias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList $Aliases
            $attributeCollection.Add($alias)
        }

        $param = new-object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList $Name, $Type, $attributeCollection

        $global:psb = $PSBoundParameters # defined for troubleshooting
        if($PSBoundParameters.ContainsKey('defaultValue') -and $null -ne $DefaultValue){
            $si = Get-PSCallStack
            if($DefaultValue -is [scriptblock]){
                $param.Value = &$DefaultValue
                $si[1].InvocationInfo.BoundParameters.$Name = $param.Value
            }
            else{
                $param.Value = $DefaultValue
                $si[1].InvocationInfo.BoundParameters.$Name = $DefaultValue
            }
        }
        $paramDictionary.Add($Name, $param)
    }
}
end{
    $paramDictionary
}
}

function Search-Script {
[cmdletbinding()]
param(
    [string] $Pattern,
    [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)] [Alias('FullName')] [string[]] $Path,
    [string[]] $Extension = ("ps1", "psm1"),
    [string[]] $Exclude = "wxyz",
    [string[]] $ExcludePath,
    [switch] $SortByDate,
    [switch] $CaseSensitive,
    [switch] $IncludeAll,
    [switch] $Firstline,
    [int] $MaxLines = [int]::MaxValue
)
dynamicParam{
    $global:paramDef_ElementType | New-Dynamic Parameter
}
end{
    if(!$Path) {
        if($allPowerShellFiles) {
            $Path = $allPowerShellFiles.FullName
        }
        else{
            $Path = "."
        }
    }

    $elementType = $PSBoundParameters.ElementType

    if($Extension -ne "*"){
        $include = $Extension | ForEach-Object {$_ -replace "^(\*)?(\.)?","*."}
    }

    $Exclude = $Exclude | ForEach-Object {$ -replace "^(\*)?(\.)?","*." }

    $selectedFiles = @()

    if($elementType -eq 'FileName') {
        foreach($p in $Path) {
            Get-ChildItem -Path $p -Include $include -Exclude $Exclude -Recurse | &{process {
                    $dir = $_.DirectoryName
                    if(!($ExcludePath | &{process{if($dir -like $_){$_}}}) -and $_.name -match $Pattern) {
                        Select-Object -Property FullName, LastWriteTime, LineNumber, Line -InputObject $_
                    }
                }}
        }
        return
    }

    if($Path[0] -is [string] -or $Path[0] -is [System.IO.DirectoryInfo]){
        foreach($p in $Path) {
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

    if($elementType -eq 'String') {
        $selectstringsplatting = @{}
        if($CaseSensitive) {
            $selectstringsplatting.CaseSensitive = $true
        }
        $Sortparam = "Path", "LineNumber"
    }
    elseif($elementType -ne 'Comment'){
        $notpart = ""
    
        if($CaseSensitive) {
            $Pattern = "(?-i)$Pattern"
        }

        if($IncludeAll -and $Global:astTypes.$elementType.NotPart){
            $notpart = "-and (!`$args[0].parent or `$args[0].parent.gettype().fullname -ne ""System.Management.Automation.Language.$($Global:astTypes.$elementType.NotPart)Ast"")"
        }

        if($Global:astTypes. $elementType.ContainsKey('TypeOverride')) {
            $querystr = "`$args[0].gettype().fullname -eq ""System.Management.Automation.Language.$($Global:astTypes.$elementType.TypeOverride)Ast"" $notpart -and
                            (Get-Property -Object `$args[0] -PropertyPath $($Global:astTypes.$elementType.PropName -join ', ')).Value -match '$Pattern'"
        }
        else{
            $querystr = "`$args[0].gettype().fullname -eq ""System.Management.Automation.Language.$($elementType)Ast"" $notpart -and
                            (Get-Property -Object `$args[0] -PropertyPath $($Global:astTypes.$elementType.PropName -join ', ')).Value -match '$Pattern'"
        }

        if($Global:astTypes.$elementType.containskey('Additional Criteria')) {
            $querystr += " -and $($Global:astTypes.$elementType.AdditionalCriteria)"
        }
        if($Global:astTypes.$elementType.containskey('Or')){
            $querystr = "($querystr) -or ($(& $Global:astTypes.$elementType.Or))"
        }

        $query = [scriptblock]::Create($querystr)

        $Sortparam = "Path", {if($_.LineNumber -match "-"){"  "}else{$_.LineNumber}}
    }

    if($SortByDate){
        $Sortparam = @(@{e = {$_.LastWriteTime}; ascending = $false}) + $Sortparam
    }

    $keepForSort = @()

    foreach($psf in $selectedFiles) {
        if($elementType -ne 'String') {
            $tokens = [System.Management.Automation.Language.Token[]]::new(1)
            $errors = [System.Management.Automation.Language.ParseError[]]::new(1)

            $AST = [System.Management.Automation.Language.Parser]::ParseFile(
                $psf.fullname,
                [ref] $tokens,
                [ref] $errors
            )

            if($elementType -eq 'Comment'){
                $selectstringsplatting = @{}

                if($CaseSensitive) {
                   $selectstringsplatting.CaseSensitive = $true
                }

                $Sortparam = "Path", "LineNumber"

                $tokens | &{process{
                    if($_.kind -eq 'Comment' -and (
                            $res = $_.Extent.Text -split "\r\n" | Select-String -Pattern $Pattern @selectstringsplatting -Encoding default
                       )) {
                            foreach($r in $res) {
                                $return = [pscustomobject]@{
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
               foreach ($ta in $toAdd) {
                    $expression = if($ta.gettype().fullname -match 'VariableExpression') {
                                        if($ta.parent.GetType().fullname -notmatch 'AssignmentStatement') {
                                            ($ast.Extent.Text -split "\r\n")[$ta.extent.StartLineNumber - 1].trim()
                                        }
                                        else{
                                            $ta.Parent.Extent.Text
                                        }
                                    }
                                    else{
                                        $currentBlock = $ta

                                        while($currentBlock.Parent -and ($currentBlock.parent.extent.startlinenumber -eq $ta.extent.startlinenumber -or $currentBlock.parent.extent.endlinenumber -eq $ta.extent.startlinenumber)){
                                            $currentBlock = $currentBlock.parent
                                        }

                                        $ta.extent.Text
                                    }

                    $expression = $expression -split '\r\n'

                    $currentMaxLines = $MaxLines

                    for($i = 0; $i -lt $expression.count -and $currentMaxLines -gt 0; $i++){
                        $currentMaxLines--

                        $return = [pscustomobject]@{
                                        Path = $ta.extent.File
                                        LastWriteTime = $psf.LastWriteTime
                                        LineNumber = if($i -eq 0){$ta.extent.StartLineNumber.toString().padleft(10,'-')}else{" +" + $i.ToString().PadLeft(8)}
                                        Line = $expression[$i]
                                    }

                        if(!$SortByDate) {
                            $return
                        }
                        else{
                            $keepForSort += $return
                        }

                        if($FirstLine) {
                            break
                        }
                    }
                }
            }
        }
        else{
            $return = $psf | Select-String -Pattern $Pattern @selectstringsplatting -Encoding default |
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
        $keepForSort | Sort-Object -Property $Sortparam
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

    'Comment'  = "Custom"

    'String'   = "Custom"

    'FileName' = "Custom"
}

$paramDef_ElementType = [pscustomobject]@{
            Name = 'ElementType'
            Type = [string]
            ValidationSet = {[string[]] $astTypes.Keys}
            DefaultValue = 'String'
        }

function Convert-CustomObjectHash {
<#
.Synopsis
   Merges properties / keys of the Secondary object hashtable to the Primary object hashtable.
.DESCRIPTION
   This function takes all properties or keys of the Secondary object / hashtable into the Primary object or hashtable. By default only those properties / keys are merge that doesn't exist in the Primary object / hashtable.
   If the -Force switch is used then the properties / keys of the Secondary object / hashtable always merged to the Primary.
.EXAMPLE
    $o = @{ObjProp = [pscustomobject] @{Prop1 = 1; Prop2 = 2}; HashProp = @{Key1 = 1; Key2 = 2}}; $result = Convert-CustomObjectHash -Object $0
    Because parameter -To is not specified, the conversion will be from [pscustomobject] to [hashtable], including all properties that are also [pscustomobject].
.EXAMPLE
    $0 = @{ObjProp = [pscustomobject] @{Prop1 = 1; Prop2 = 2}; HashProp = @{Key1 = 1; Key2 = 2}}; $result = Convert-CustomObjectHash -Object $0 -to pscustomobject
    Because the -To parameter is [pscustomobject], only the HashProp of the input object will be converted to [PScustomobject].
.INPUTS
   hashtables or pscustomobjects
.OUTPUTS
   The converted input object
#>
[cmdletbinding()]
param(
    # Object to convert.
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)] [AllowNull()] [object]$Object,
    # Force conversion to this datatype.
    [Parameter()] [ValidateSet('hashtable', 'pscustomobject')] [AllowNull()] [string] $To,
    # Recursion depth, by default 5.
    [Parameter()] [int] $Depth = 5,
    [Parameter(DontShow = $true)] [int] $_currentdepth = 0
)
process{
    if($null -eq $Object) {
        return
    }

    if($_currentdepth -gt $Depth){
        return $Object
    }

    if(!$PSBoundParameters.to){
        if($object -is [System.Collections.IDictionary]){
            $To = 'pscustomobject'
        }
        elseif($object -is [System.Management.Automation.PSCustomObject]){
            $To = 'hashtable'
        }
        else{
            return
        }
    }

    if($Object -isnot [System.Collections.IDictionary] -and $Object -isnot [System.Management.Automation.PSCustomObject]){
        return $Object
    }

    if($To -eq 'hashtable'){
        $newObject = @{}

        foreach($prop in $Object.psobject.properties){
            $newObject.($prop.name) = Convert-CustomObjectHash -Object $prop.value -To $To -_currentdepth ($_currentdepth + 1) -Depth $Depth
        }
        $newObject
    }
    elseif($To -eq 'pscustomobject') {
        $Object = [pscustomobject] $Object
        foreach($prop in $Object.psobject.properties) {
            $Object.($prop.name) = Convert-CustomObjectHash -Object $prop.value -To $To -_currentdepth ($_currentdepth + 1) -Depth $Depth
        }
        $Object
    }
}
}

function Get-DomainNetBIOSName {
# Windows PowerShell / PowerShell
$rootDse = [ADSI] "LDAP://RootDSE"
$defaultNc = [string] $rootDse.defaultNamingContext
$configNc  = [string] $rootDse.configurationNamingContext

$searchRoot = [ADSI]("LDAP://CN=Partitions," + $configNc)
$searcher   = New-Object -TypeName System.DirectoryServices.DirectorySearcher -ArgumentList $searchRoot

$searcher.Filter = "(&(objectClass-crossRef)(nCName=$defaultNc))"
$null = $searcher.PropertiesToLoad.Add("nETBIOSName")
$null = $searcher.PropertiesToLoad.Add("dnsRoot")

$result = $searcher.FindOne()

if($result -and $result.Properties["netbiosname"].Count -gt 0) {
    $netbios = $result.Properties["netbiosname"][0]
    $dnsRoot = $result.Properties["dnsroot"][0]
    [pscustomobject]@{
        NetBIOSName = $netbios
        DnsRoot     = $dnsRoot
    }
} 
else {
    Write-Warning "Could not resolve NetBIOS name from crossRef."
}
}

function Get-DomainNetBIOSNameComputer {
    try {
        $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain()
        $rootDse = [ADSI] "LDAP://RootDSE"
        $configNc = $rootDse.configurationNamingContext
        $domainDn = ($domain.GetDirectoryEntry()).distinguishedName
        
        $searcher = New-Object System.DirectoryServices.DirectorySearcher(
                        [ADSI]"LDAP://$configNc"
                    )

        $searcher.Filter = "(&(objectClass-crossRef)(nCName=$domainDn))"
        $searcher.PropertiesToLoad.Add("nETBIOSName") | Out-Null

        $result = $searcher.FindOne()
        return $result.Properties["netbiosname"][0]
    }
    catch {
        return $null
    }
}

function Get-StrictMode {
    $innerField = [System.Management.Automation.SessionState].GetField(
        'sessionState',
        [System.Reflection.BindingFlags] 'Instance, NonPublic'
    )

    $inner = $innerField.GetValue($ExecutionContext.SessionState)
    $scopeProp = $inner.GetType().GetProperty(
        'CurrentScope',
        [System.Reflection.BindingFlags] 'Instance, NonPublic, Public'
    )
    $scope = $scopeProp.GetValue($inner, $null)
    $strictProp = $scope.GetType().GetProperty(
        'StrictModeVersion',
        [System.Reflection.BindingFlags] 'Instance, NonPublic, Public'
    )
    $version = $strictProp.GetValue($scope, $null)

    if($null -eq $version) { 'Off' } else { $version.ToString() }
}

Function Update-Config {
param(
    [Parameter(Mandatory = $true)] [string] $Environment,
    [Parameter(Mandatory = $true)]$prefix,
    [switch] $Force
)

    $cs = Get-PSCallStack

    if($cs.count -ge 2 -and !$Force){
        $Force = $cs[1].InvocationInfo.BoundParameters.ContainsKey("$($prefix)Environment") -and $cs[1].InvocationInfo.BoundParameters."$($prefix)Environment"
    }

    if($PSBoundParameters.ContainsKey("Environment") -and (!$global:psconfig.ContainsKey("$($prefix)Environment") -or $Force)) {
        $global:psconfig."$($prefix)Environment" = $Environment
    }

    if((Get-Variable -Name psconfig -Scope Global -ErrorAction Ignore) -and $global:psconfig -is [System.Collections.IDictionary] -and $global:psconfig.ContainsKey("$($prefix)Config")){
        $global:psconfig.Remove("$($prefix)Config")
    }

    Import-PSData -PSData $global:psconfig
}
#endregion

#region Property management
function Update-Property {
<#
.Synopsis
Updates properties of objects or values of hashtables.
.DESCRIPTION
This function creates or sets properties of objects or values of hashtables. If a property or key doesn't exist then the function will create that and assign the given value to it.
If the property or key exists then - depending on the type of its value - it's going to do one of the following actions:
- if the existing value is an integer and the new value is an integer then it adds the new value to the existing one
in other cases the function converts the existing value to a collection if it's not already that and adds the new value as a new element to that collection. If the new value is already
among the existing elements then it will skip adding the new element to it.
- if the -Force switch is used then the existing value is going to be overwritten by the new value
This function is meant to extend the scope and functionality of Add-Member.
.EXAMPLE
$splatting @{}; Update-Property -Object $splatting -PropName DisplayName Value 'Tibor Soos'; Update-Property -Object $splatting -PropName Replace Value @{proxyAddresses = "SMTP: Soos.Tibor@hotmail.com"}
In this example we prepare a hashtable $splatting for splatting the Set-ADUser cmdlet to set the displayname and the proxyAddresses attribute of an AD user object.
.EXAMPLE
Update-Property -Object $splatting -PropName Replace Value @{proxyAddresses = "smtp:Soos Tibor@hotmail.com"}; $splatting.Replace
In this example we add a secondary SMTP address to the splatting hashtable under its Replace key.
.EXAMPLE
Update-Property -Object $splatting. Replace -PropName proxyAddresses -Value "smtp:tibor.soos@hotmail.com" -Pass Thru
In this example we add another secondary SMTP address to the splatting hashtable directly under its Replace.proxyAddresses key. Using the -Pass Thru switch we get back the updates hashtable under the Replace key.
.EXAMPLE
$obj = [pscustomobject] @{Prop1 = "Text"; Prop3 = "Obsolete"}; Update-Property -Object $obj -PropName Prop2; Update-Property -Object $obj -PropName Prop3 -Value Fresh -Force; Update-Property -Object $obj -PropName Prop1 -Value NewText -PassThru
In this example we update an object in $obj 3 times. First we create a new property Prop2, then we overwrite the property 'Prop3' to 'Fresh', then we extend the existing value of Prop1 by converting it to a collection and adding 'NewText' to it as a new element.
.INPUTS
hashtable or psobject
.OUTPUTS
The updated input object if the -PassThru switch is used.
#>
[cmdletbinding(PositionalBinding=$false)]
param(
    # Input object, either a hashtable or a PSObject
    [Parameter(Position = 0, Mandatory = $true)] [psobject] $Object,
    # Name of the property or key to update
    [Parameter(Position = 1, Mandatory = $true)] [string] $PropertyPath,
    # Do not expand dots (.) in -PropertyPath
    [Parameter()] [switch] $LiteralPropertyName,
    # The new value to include in the update process. By default it's 1.
    [Parameter()] [psobject] $Value = 1,
    # Overwrite existing value by the -Value
    [Parameter()] [psobject] $OverwriteValue,
    # Switch to output the update input object
    [Parameter()] [switch] $PassThru,
    # Switch to do an overwrite
    [Parameter()] [switch] $Force,
    [Parameter(Dontshow = $true)] $objectToReturn = $Object
)

    if(!$LiteralPropertyName -and $PropertyPath -match '\.|\[\w+\](?=(\.|$))'){
        $nextProp, $PropertyPath = $PropertyPath -split '\.|(?=\[\w+\]$)', 2

        if($nextProp) {
            $testProp = Get-Property -Object $Object -PropertyPath $nextProp

            if(!$testProp.PropertyExists) {
                if($Force) {
                    $nextProp2, $PropertyPath2 = $PropertyPath -split '\.|(?=\[\w+\]$)', 2
                    $value2 = @{$nextProp2 = $null}

                    if($object -isnot [system.collections.iDictionary]){
                        $value2 = [pscustomobject] $value2
                    }

                    Update-Property -Object $Object -PropertyPath $nextProp -Value $value2
                }
                else{
                    Write-Error -Message "Property '$nextProp' doesn't exist on object '$Object'"
                    return
                }
            }

            $nextObj = $Object.$nextProp
            Update-Property -Object $nextObj -PropertyPath $PropertyPath -Value $Value -PassThru:$PassThru -Force:$Force -objectToReturn $objectToReturn
            return
        }
    }

    $indx = $null

    if($PropertyPath -match '^\[(\w+)\]$'){
        if($null -ne ($Matches[1] -as [int])) {
            $indx = [int] $Matches[1]

            if($object -is [collections.ilist]){
                $PropertyPath = $null
                if($object.count -le $indx) {
                    if($ErrorActionPreference -ne 'Ignore') {
                        Write-Error "Index property is out of range"
                    }
                    return
                }
            }
            else{
                $PropertyPath = $indx
                $indx = $null
            }
        }
        else{
            $PropertyPath = $Matches[1]
        }
    }

    $PropertyPath = $PropertyPath -replace '^[''"]|[''"]$'

    if($null -eq $Object){
        if($ErrorActionPreference -ne 'Ignore') {
            Write-Error "No object"
        }
        return
    }

    if($Object -is [System.Collections.IDictionary] -and !$Object.containskey($PropertyPath)){
        $Object.$PropertyPath = $Value
    }
    elseif($object -isnot [System.Collections.IDictionary] -and $Object -isnot [system.collections.ilist] -and (!@($Object.psobject.Properties).count -or $Object.psobject.Properties.Name -notcontains $PropertyPath)){
        Add-Member -InputObject $0bject -MemberType NoteProperty -Name $PropertyPath -Value $Value
    }
    elseif($Force){
        if($null -eq $indx) {
            if($object -isnot [psobject] -or $Object.psobject.properties.name -notcontains $PropertyPath) {
                Add-Member -InputObject $Object -MemberType NoteProperty -Name $PropertyPath -Value $Value
            }
            else{
                $Object.$PropertyPath = $Value
            }
        }
        else{
            $Object[$indx] = $Value
        }
    }
    else{
        if($null -eq $indx) {
            if($PSBoundParameters.ContainsKey('OverwriteValue')) {
                $Object.$PropertyPath = $Object.$PropertyPath | Where-Object {$OverwriteValue -ne $_}
            }

            if(($object.$PropertyPath -is [int] -or $Object.$PropertyPath -is [double] -or $Object.$PropertyPath -is [decimal] -or $Object.$PropertyPath -is [System.Int64]) -and ($Value -is [int] -or $Value -is [double] -or $Value -is [decimal] -or $Value -is [System.Int64]) ) {
                    $Object.$PropertyPath += $Value
            }
            elseif($object.$PropertyPath -is [string]) {
                if($Value -ne $0bject.$PropertyPath) {
                    $Object.$PropertyPath = @($object.$PropertyPath) + $Value
                }
            }
            elseif($object.$PropertyPath -is [collections.ilist]){
                if($object.$PropertyPath.count -gt 0 -and $Object.$PropertyPath[0] -is [System.Collections.IDictionary]){
                    if($Value -is [collections.ilist] -and $Value.count -gt 0 -and $Value[0] -is [System.Collections.IDictionary]){
                        $existingKeys = $Object.$PropertyPath | &{process{$_.Keys}}

                        if($existingKeys -notcontains ($Value | &{process{$_.Keys}})){
                            $Object.$PropertyPath += $Value
                        }
                        else{
                            foreach ($v in $Value) {
                                $equalfound = $null

                                for($i = 0; $i -lt $Object.$PropertyPath.count; $i++){
                                    $difffound = $false
                                    foreach($k in $o.keys) {
                                        if($v.$k -ne $v.$k) {
                                            $difffound = $true
                                            break
                                        }
                                    }
                                    if(!$difffound) {
                                        $equalfound = $i
                                        break
                                    }
                                }

                                if($null -ne $equalfound) {
                                    $Object.$PropertyPath += $v
                                }
                                else{
                                    $Object.$PropertyPath[$equalfound] = $v
                                }
                            }
                        }
                    }
                }
                else{
                    $toadd = @()
                    foreach ($elem in $Value){
                        if($object.$PropertyPath -notcontains $elem) {
                            $toadd + $elem
                        }
                    }

                    if($toadd){
                        if($object.$PropertyPath -is [System.Collections.ArrayList]){
                           $Object.$PropertyPath.addrange($toadd)
                        }
                        elseif($object -isnot [psobject]){
                           Add-Member -InputObject $Object -MemberType NoteProperty -Name $PropertyPath -Value $toadd
                        }
                        else{
                            $Object.$PropertyPath += $toadd
                        }
                    }
                }
            }
            elseif($object.$PropertyPath -is [System.Collections.IDictionary] -and $Value -is [System.Collections.IDictionary]){
                $keys = [object[]] $Value.keys

                foreach($key in $keys) {
                    if($object.$PropertyPath.containskey($key)) {
                        if($object.$PropertyPath.$key -notcontains $Value.$key) {
                            if($null -ne $Object.$PropertyPath.$key){
                                $Object.$PropertyPath.$key = @($Object.$PropertyPath.$key) + $Value.$key
                            }
                            else{
                                $Object.$PropertyPath.$key = $Value.$key
                            }
                        }
                    }
                    else{
                        $Object.$PropertyPath.$key = $Value.$key
                    }
                }
            }
        }
        elseif($null -eq $Object.$PropertyPath) {
            $Object.$PropertyPath = $Value
        }
        elseif($object.$PropertyPath -ne $Value) {
            $Object.$PropertyPath = @($object.$PropertyPath) + $Value
        }
    }
    else{
        if($PSBoundParameters.ContainsKey('OverwriteValue')) {
            $Object[$indx] = $Object[$indx] | Where-Object {$OverwriteValue -ne $_}
        }

        if($Object[$indx] -is [int] -and $Value -is [int]) {
           $Object[$indx] += $Value
        }
        elseif($object[$indx] -is [string]) {
            if($Value -ne $Object[$indx]) {
               $Object[$indx] = @($Object[$indx]) + $Value
            }
        }
        elseif($object[$indx] -is [collections.ilist]){
            if($object[$indx].count -gt 0 -and $Object[$indx][0] -is [System.Collections.IDictionary]){
                if($Value -is [collections.ilist] -and $Value.count -gt 0 -and $Value[0] -is [System.Collections.IDictionary]){
                    $existingKeys = $Object[$indx] | &{process{$_.Keys}}

                    if($existingKeys -notcontains ($Value.keys | &{process{$_.Keys}})){
                        $Object[$indx] += $Value
                    }
                    else{
                        foreach($v in $Value) {
                            $equalfound = $null
                            for($i = 0; $i -lt $Object[$indx].count; $i++){
                                $difffound = $false
                                foreach($k in $o.keys) {
                                    if($v.$k -ne $v. $k) {
                                        $difffound = $true
                                        break
                                    }
                                }
                                if(!$difffound) {
                                    $equalfound = $i
                                    break
                                }
                            }

                            if($null -ne $equalfound) {
                                $Object[$indx] += $v
                            }
                            else{
                                $Object[$indx][$equalfound] = $v
                            }
                        }
                    }
                }
            }
            else{
                $toadd = @()
                foreach($elem in $Value) {
                    if($object. $PropertyPath -notcontains $elem) {
                        $toadd = $elem
                    }
                }

                if($toadd) {
                    if($object. $PropertyPath -is [System.Collections.ArrayList]){
                        $Object.$PropertyPath.addrange($toadd)
                    }
                    elseif($object -isnot [psobject]){
                        Add-Member -InputObject $Object -Member Type NoteProperty -Name $PropertyPath -Value $toadd
                    }
                    else{
                        $Object.$PropertyPath += $toadd
                    }
                }
            }
        }
        elseif($object[$indx] -is [System.Collections.IDictionary] -and $Value -is [System.Collections.IDictionary]){
            $keys = [object[]] $Value.keys
            foreach ($key in $keys) {
                if($Object[$indx].containskey($key)) {
                    if($Object[$indx].$key -notcontains $Value.$key){
                        if($null -ne $Object[$indx].$key) {
                            $Object[$indx].$key = @($Object[$indx].$key) + $Value.$key
                        }
                        else{
                            $Object[$indx].$key = $Value.$key
                        }
                    }
                }
                else{
                    $Object[$indx].$key = $Value.$key
                }
            }
        }
        elseif($null -eq $Object[$indx]){
                $Object.$PropertyPath = $Value
        }
        elseif($Object[$indx] -ne $Value){
            $Object[$indx] = @($Object[$indx]) + $Value
        }
    }
    if($PassThru){
        $objectToReturn
    }
}

function Search-Property {
<#
.Synopsis
Searches for patterns in properties of objects or keys of hashtables.
.DESCRIPTION
   This function primarily searches the regex pattern among properties of objects or keys of hashtables. If the -SearchInPropertyNames is specified then it searches among property names / keys as well.
   If the -ExcludeValues switch is used then it skips the search in values of properties / keys.
   If we want a literal search and not a regex pattern matching then the -LiteralSearch switch can be used. If we want to restrict search in certain properties / keys, then we can specify those names at the -Propery parameter.
   If the pattern is in the form of '<name>', the the function searches for all the properties / keys where the value matches the value of property / key with name   'name'.
   If we want to skip certain properties / keys, then we can specify those at the -Exclude Property parameter.
   By default the search is case insensitive, we can make it case sensitive by specifying the -CaseSensitive switch.
   By default the search is done among those properties / keys which contain a collection of values. To skip searching in those properties we can specify the -IgnoreCollections switch.
   By default the search goes into the immediate properties / keys of the input objects. We can specify the search depth by assigning a value to the -Depth parameter.
   The result contains custom objects having an 'Object' property which is meant to be an identifyer of the input objects. That is by default the result of the ToString() method invoking on the input object.
   If we want to have that identifier of one of the properties of the input object then we can specify that property name / key in the -ObjectNameProp parameter.
.EXAMPLE
   Get-Item -Path C:\Windows\notepad.exe | Search-Property -Pattern '<basename>' -Depth 2 -ObjectNameProp name -CaseSensitive -IgnoreCollections
   In this example we search the base name of the notepad.exe file object (notepad) among its properties and the properties of properties (-Depth 2) in a case sensitive way, so the VersionInfo. OriginalFilename property is not returned, because there the value is NOTEPAD.EXE.MUI.
   The first column of the result set contain the name of the file (notepad.exe) and not the full path, because we specified that the object name should be taken from property 'name'.
.EXAMPLE
   @{One = "MyValue"; KeyTwo = 'One'; Coll = 'one', 'two'; KeyThree = @{SubKey1 = 'One'; SubKey2 = [pscustomobject]@{Prop1 = 'One'; Prop20ne = 'Text'}}} | Search-Property -Pattern '^One$' -SearchInPropertyNames -Depth 3 -IgnoreCollections
   In this example we search for the exact string 'One' among all the keys of the hashtable specified in the command line max 3 levels deep. We skip the key 'Coll', because that contains a collection and we specified the -IgnoreCollections switch. The result also contains property 'Prop1' of the object under the
key 'Subkey2'.
.INPUTS
   hashtable or psobject
.OUTPUTS
   Collection of custom objects having an Object, Name and Value properties.
#>
[cmdletbinding (PositionalBinding=$false)]
param(
    # Regex pattern to search for
    [parameter(Position=0)][string] $Pattern = ".",
    # Input object or hashtable
    [Parameter(ValueFromPipeline, Position = 1)] [psobject] $Object,
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
    # Ignore properties / keys that contain collection of values.
    [switch] $IgnoreCollections,
    # Depth of the recursive search, by default 1 - shallow search
    [int] $Depth = 1,
    [Parameter(DontShow = $true)] [int] $_Depth = 1,
    [Parameter(DontShow = $true)] [string[]] $_ParentNames,
    [Parameter(DontShow = $true)] [string] $_ObjectName
)
begin{
    if($LiteralSearch -and $Pattern -ne "."){
        $Pattern = [regex]:: Escape($Pattern)
    }

    if($CaseSensitive){
        $Pattern = "(?-i) $Pattern"
    }

    $origpattern = $Pattern
    $pipeline = $false

    if(!$_ObjectName -and !$ObjectNameProp) {
        $parts = [scriptblock]::Create($MyInvocation.Line).ast.findall({$true}, $true)

        for($i = 0; $i -lt $parts.count; $i++) {
            if($parts[$i].psobject.Properties.Name -contains 'ParameterName' -and $parts[$i].ParameterName -eq 'Object') {
                $_ObjectName = $parts[$i+1].Extent.Text

                if($_ObjectName -notmatch '^\(.*\)$' -and ($_ObjectName -notmatch '^\$' -or ($parts[$i+1].staticType -match "\[\]$" -and $_ObjectName -notmatch "^\("))){
                    $_ObjectName = "($_ObjectName)"
                }
                break
            }
        }

        if(!$_ObjectName -and $parts[2].gettype().fullname -match 'PipelineAst'){
            $pipeline = $true
        }

        if(!$_ObjectName){
            if($pipeline) {
                $_ObjectName = '$Input'
            }
            else{
                $_ObjectName = '$Object'
            }
        }

        $objectCount = 0
    }
}
process{
    $type = $Object.gettype().fullname
    foreach($o in $object) {
        if($null -eq $o){
            continue
        }

        if($_ObjectName) {
            $objectName = $_ObjectName
            if($pipeline -or ($object -is [System.Collections.Ilist]) -and $_Depth -eq 1){
                $objectName = $ObjectName -replace "(\[\d+\])?$" -replace '$', "[$objectCount]"
                $objectCount++
            }
        }
        elseif($ObjectNameProp) {
            $objectName = $o.$ObjectNameProp
        }
        else{
           $objectName = $o.ToString()
        }

        if(!$IgnoreCollections -and $o -is [collections.ilist]){
            $index = 0

            foreach($elem in $o) {
                $parentNames = "$($_ParentNames -join '.') [$index]"

                if($elem.tostring() -ne $elem.gettype().fullname -and $elem -match $Pattern) {
                   $out = [pscustomobject]@{
                       Object = $objectName
                       PropertyPath = $parentNames
                       Type = $type
                       Value = $elem
                   }

                   $out.pstypenames.insert(0, 'ScriptTools.Property.Expand')
                   $out
                }

                if($elem -is [scriptblock]){
                   $elem = [string] $elem
                }

                Search-Property -Object $elem -Pattern $origpattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property:$Property -ExcludeProperty:$Exclude Property -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -_ParentNames $parentNames -_ObjectName $objectName
                $index++
            }
        }
        else{
            if(!$LiteralSearch -and $origpattern -match "<[^>]+>"){
                $Pattern = [regex]::Replace(
                                            $origpattern, "<([^>]+)>", {
                                                [regex]::Escape(
                                                    (get-property -Object $o -PropertyPath ($args[0].value -replace "^<|>$") -ValueOnly)
                                                )
                                            }
                                        )
            }

            if($o -is [System.Collections.IDictionary]){
                $properties = $o.getenumerator() | Select-Object -Property Name, Value
            }
            else{
                $properties = $o.psobject.properties
            }

            foreach($prop in ($properties | Sort-Object -Property Name)) {
                $PropName = $prop.Name

                if(
                   $prop.membertype -ne 'AliasProperty' -and
                    (
                        $(if(!$ExcludeValues){$prop.value -as [string] -and $prop.value.tostring() -ne $prop.value.gettype().fullname -and $prop.value -match $Pattern}) -or
                        $(if($SearchInPropertyNames) {$prop.name -as [string] -and $prop.name -match $Pattern})
                    ) -and
                    !($ExcludeProperty | &{process {if($PropName -like $_){$_}}}) -and
                    ($Property | &{process {if($PropName -like $_){$_}}}) -and
                    (!$IgnoreCollections -or $prop.value -isnot [collections.ilist])
                ){
                    $propFullName = ($_ParentNames + $PropName) -join "."
                    if($null -ne $prop.value) {
                        $type = $prop.value.gettype().fullname
                    }
                    else{
                        $type = $null
                    }

                    $out = [pscustomobject]@{
                                Object = $objectName
                                PropertyPath = $propFullName
                                Type = $type
                                Value = $prop.value
                            }

                    $out.pstypenames.insert(0, 'ScriptTools.Property.Expand')
                    $out
                }

                if($prop.value -and $prop.value.gettype().fullname -notin 'system.string', 'system.int32' -and $_Depth -lt $Depth) {
                    if($prop.value -is [collections.ilist]){
                        Search-Property -Object (,$prop.value) -Pattern $pattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property $Property -Exclude Property $Exclude Property -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -ParentNames ($_ParentNames + $PropName) -ObjectName $objectName
                    }
                    elseif($prop.Value -is [System.Management.Automation.PSReference]) {
                        $obj = [pscustomobject] @{Value = $prop.value.value}
                        Search-Property -Object $obj -Pattern $pattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property $Property -ExcludeProperty $ExcludeProperty -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -ParentNames ($_ParentNames + $PropName) -ObjectName $objectName
                    }
                    else{
                        Search-Property -Object $prop.value -Pattern $pattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property $Property -ExcludeProperty $ExcludeProperty -CaseSensitive:$CaseSensitive -IgnoreCollections: $IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -ParentNames ($_ParentNames + $PropName) -_ObjectName $objectName
                    }
                }
            }
        }
    }
}
}


function Compare-Property {
<#
.Synopsis
    Compares properties of objects or keys of hashtables.
.DESCRIPTION
    This function compares properties of two objects or keys of two hashtables recursively and returns a set of custom objects describing the differences.
.EXAMPLE
    $f1 = Get-Item C:\Windows\notepad.exe; $f2 = Get-Item C:\Windows\System32\notepad.exe; Compare-Property -ReferenceObject $f1 -DifferenceObject $f2
    This expression compares the properties of 2 notepad.exe files and returns all properties that are different.
.EXAMPLE
    $f1 = Get-Item C:\Windows\notepad.exe; $f2 = Get-Item C:\Windows\System32\notepad.exe; Compare-Property -ReferenceObject $f1 -DifferenceObject $f2 -IncludeEqual -Exclude Different -Exclude PS*
    In this example we compare the properties of the two notepad.exe file objects, exclude the properties that are different but include properties that are equal. We also exclude all properties whose name start with PS.
.EXAMPLE
    Compare-Property -ReferenceObject @{Name = 'First'; Number = 1; Array = 1,2; RefEmpty = $null} -DifferenceObject @{ Name = 'Second'; Number = 2; Array = 2,3; DiffEmpty = @()} -Hide Empty -NameProperty Name -Exclude Name
    In this example we compare the keys of two hashtables. We exclude those properties that contain 'empty' values ($null, empty array, empty hashtables, System.DBNull) in either input objects.
    We also include in the column names the content of the Name property of the respective hashtables, but exclude the Name property from the differences.
.INPUTS
    Hashtable or PSObject
.OUTPUTS
    Collection of custom objects having a Property, Relation and 'r:<reference object ID>', 'd:<difference object ID>' properties.
#>
[cmdletbinding(PositionalBinding=$false)]
param(
    # The reference object or hashtable
    [Parameter(Mandatory = $true, Position = 0)] [AllowNull()] [psobject] $ReferenceObject,
    # The difference object or hashtable
    [Parameter(Mandatory = $true, Position = 1)] [AllowNull()] [psobject] $DifferenceObject,
    # Include equal properties/keys in the result
    [switch] $IncludeEqual,
    # Exclude differences from the result
    [switch] $ExcludeDifferent,
    # Include properties/keys to compare
    [string[]] $Property = "*",
    # Exclude properties/keys to compare
    [string[]] $Exclude,
    # Use this property or the result of executing the scriptblock as the name for the objects
    [ValidateScript({$_ -is [string] -or $_ -is [scriptblock]})] [psobject] $NameProperty,
    # Hide certain type of empty properties
    [string] [ValidateSet('None', 'Empty', 'NonEmpty', 'BothEmpty')] $Hide = 'None',
    [Parameter(Dontshow = $true)] [int] $_Depth = 1,
    # Maximum depth of recursion, default is 5
    [int] $MaxDepth = 5
)
    $equal = $null
    $rObjName = ''
    $dObjName = ''

    if($null -eq $ReferenceObject -and $null -eq $DifferenceObject){
        $rObjName = '$null'
        $dObjName = '$null'
        $equal = "=="
    }
    elseif($null -eq $ReferenceObject -or $null -eq $DifferenceObject){
        if($null -eq $ReferenceObject){
            $rObjName = '$null'
            $equal = "=>"
        }
        else{
            $dObjName = '$null'
            $equal = "<="
        }
    }
    elseif($ReferenceObject.GetType().FullName -ne $DifferenceObject.GetType().FullName -and $PSBoundParameters.ContainsKey('_Depth')){
       $equal = "<>"
    }
    elseif($ReferenceObject -is [scriptblock] -and $PSBoundParameters.ContainsKey('_Depth')) {
        if($ReferenceObject.ToString() -eq $DifferenceObject.tostring()) {
            $equal = "=="
        }
        else{
            $equal = "<>"
        }
    }
    elseif($ReferenceObject -is [datetime] -and $PSBoundParameters.ContainsKey('_Depth')){
        if($ReferenceObject -eq $DifferenceObject){
            $equal = "=="
        }
        else{
            $equal = "<>"
        }
    }
    elseif($ReferenceObject.gettype().fullname -in 'System.RuntimeType', 'System.Reflection.RuntimeAssembly') {
        return
    }
    elseif($ReferenceObject -is [System.IO.FileSystemInfo] -and $PSBoundParameters.ContainsKey('_Depth')) {
        if($ReferenceObject.fullname -eq $DifferenceObject.fullname) {
            $equal = "=="
        }
        else{
            $equal = "<>"
        }
    }
    elseif($ReferenceObject -is [string]){
        if($ReferenceObject -eq $DifferenceObject){
            $equal = "=="
        }
        else{
            $equal = "<>"
        }
    }
    elseif($ReferenceObject -as [double] -and $DifferenceObject -as [double]){
        if($ReferenceObject -eq $DifferenceObject){
            $equal = "=="
        }
        else{
            $equal = "<>"
        }
    }
    elseif($ReferenceObject -is [system.collections.ilist]){
        if($ReferenceObject.psbase.count -ne $DifferenceObject.psbase.count){
            $equal = "<>"
        }
        else{
            $equal = "=="
            for($i = 0; $i -lt $ReferenceObject.psbase.count; $i++){
                $diff = Compare-Property -ReferenceObject $ReferenceObject[$i] -DifferenceObject $DifferenceObject[$i] -Depth ($_Depth + 1)
                if($diff){
                    $equal = "<>"
                    break
                }
            }
        }
    }

    if($NameProperty){
        if($NameProperty -is [string]) {
            if(!$rObjName) {
                $rObjName = $ReferenceObject.$NameProperty
            }
            if(!$dobjName) {
                $dObjName = $DifferenceObject.$NameProperty
            }
        }
        else{
            if(!$rObjName) {
                $rObjName = $ReferenceObject | &{process{ & $NameProperty}}
            }
            if(!$dobjName) {
                $dObjName = $DifferenceObject | &{process{ & $NameProperty}}
            }
        }
    }
    else{
        if(!$rObjName) {
            $rObjName = $ReferenceObject.tostring()
        }
        if(!$dobjName) {
            $dObjName = $DifferenceObject.tostring()
        }
    }
    $rs = "r:" + $rObjName
    $ds = "d:" + $dObjName

    if(!$equal -and $MaxDepth -lt $_Depth) {
        if($ReferenceObject.tostring() -eq $DifferenceObject.ToString()) {
            $equal = "=="
        }
        else{
            $equal = "<>"
        }
    }

    if($equal){
        if($equal -ne '==') {
            [pscustomobject] @{
                Property = "<value>"
                Relation = $equal
                $rs = $ReferenceObject
                $ds = $DifferenceObject
            }
        }
    }
    else{
        if($ReferenceObject -is [System.Collections.IDictionary]){
            $ReferenceObject = [pscustomobject] $ReferenceObject
            $DifferenceObject = [pscustomobject] $DifferenceObject
        }

        if($NameProperty){
            if($NameProperty -is [string]) {
                $rObjName = $ReferenceObject.$NameProperty
                $dObjName = $DifferenceObject.$NameProperty
            }
            else{
                $rObjName = $ReferenceObject | &{process{ & $NameProperty}}
                $dObjName = $DifferenceObject | &{process{ & $NameProperty}}
            }
        }
        else{
           $rObjName = $ReferenceObject.tostring()
           $dObjName = $DifferenceObject.tostring()
        }
        $rs = "r:" + $rObjName
        $ds = "d:" + $dObjName

        $rp =  $referenceobject.psobject.Properties |
                &{process{ if($_.membertype -ne 'AliasProperty'){$_}}} |
                    Select-Object -ExpandProperty Name

        $allprops = @($rp)

        $dp = $differenceobject.psobject.Properties |
                &{process {if($_.membertype -ne 'AliasProperty'){$_}}} |
                    Select-Object -ExpandProperty Name

        foreach($p in $dp) {
            if($allprops -notcontains $p) {
               $allprops += $p
            }
        }

        $allprops = $allprops | &{process {
               $pp = $_
               if(($Property | &{process {if($pp -like $_){$_}}}) -and !($Exclude | &{process{if($pp -like $_){$_}}})) {$_}
            }} | Sort-Object

        foreach($p in $allprops) {
            if($rp -contains $p -and $dp -contains $p) {
                $ra = $ReferenceObject.$p
                $da = $DifferenceObject.$p

                $diff = Compare-Property -ReferenceObject $ra -DifferenceObject $da -Property $Property -Exclude $Exclude -Depth ($ Depth + 1)
                if($diff){
                    $equal = "<>"
                }
                else{
                    $equal = "=="
                }
            }
            elseif($rp -contains $p){
                $equal = "<="
                $ra = $ReferenceObject.$p
                $da = $null
            }
            else{
               $equal = "=>"
                $da = $DifferenceObject.$p
                $ra = $null
            }

            $raempty = $null -eq $ra -or
                        '' -eq $ra -or
                        (($ra -is [collections.ilist] -or $ra -is [Collections.IDictionary]) -and $ra.count -eq 0) -or
                        $ra -is [System.DBNull]

           $daempty = $null -eq $da -or
                        '' -eq $da -or
                        (($da -is [collections.ilist] -or $da -is [Collections.IDictionary]) -and $da.count -eq 0) -or
                        $ra -is [System.DBNull]

            if((!$Excludedifferent -and $equal -ne '==') -or ($includeequal -and $equal -eq '==')){
                if(($Hide -eq 'Both Empty' -and $raempty -and $daempty) -or
                    ($Hide -eq 'Empty' -and ($raempty -or $daempty)) -or
                    ($Hide -eq 'NonEmpty' -and (!$raempty -or !$daempty))) {
                    continue
                }

                [pscustomobject] @{
                    Property = $p
                    Relation = $equal
                    $rs = $ra
                    $ds = $da
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
   Get-ChildItem C:\Windows\system32\*.exe | Get-Property -PropertyPath "Version Info. CompanyName", "PSDrive. Provider.Name" -ObjectNameProperty Name
    Gets the Version Info. CompanyName and PSDrive. Provider. Name properties of all EXE files under c:\windows\system32 folder. The result will have the Name of each files under the Object column.
.EXAMPLE
   $h = @{Name = "MyHashTable"; Array = @{n = 'First'; data = 'Text1'}, @{n = 'Second'; data = 'Text2'}}; Get-Property -Object $h -PropertyPath 'Array[1].data' -ValueOnly
    In this example we get the 'Text2' from hashtable $h. In this case the -PropertyPath contains an index as well and because we used the -ValueOnly switch only the value of 'data' is returned.
.INPUTS
    hashtables or psobjects
.OUTPUTS
    Collection of custom objects having an Object, PropertyPath, PropertyExists and Value properties, or only the value of the addressed property if the -ValueOnly switch is used.
#>
[cmdletbinding (PositionalBinding=$false)]
param(
    # Input object to get its property
    [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)] [psobject] $Object,
    # Path(s) of the value to query. This path is the full path to the value, including property names and key names and indexes.
    [Parameter(Mandatory = $true, Position = 1)] [string[]] $PropertyPath,
    # Property or key that can be used to reference the object. If not specified then the result of the ToString() method will be used.
    [string] $ObjectNameProperty,
    # Return only the addressed property/key value, not the complete custom object.
    [switch] $ValueOnly,
    # Do not enumerate elements of collections, treat collection as a single object
    [switch] $CollectionAsObject
)
begin{
    $pipeline = $false
    $ObjectName = $null
    if(!$ObjectNameProperty){
        $parts = $null
        try{
            $mi = $MyInvocation
            $parts = [scriptblock]::Create($mi.Line).ast.findall({$true}, $true)

            for($i = 0; $i -lt $parts.count; $i++){
                if($parts[$i].psobject.Properties.Name -contains 'ParameterName' -and $parts[$i].ParameterName -eq 'Object') {
                    $ObjectName = $parts[$i + 1].Extent.Text
                    
                    if($ObjectName -notmatch '^\(.*\)$' -and ($ObjectName -notmatch '^\$' -or ($parts[$i + 1].staticType -match "\[\]$" -and $ObjectName -notmatch "^\("))){
                        $ObjectName = "($ObjectName)"
                    }
                    break
                }
            }
        }
        catch{
            $global:Error.RemoveAt(0)
        }
        
        if(!$ObjectName -and $parts -and $parts[2].gettype().fullname -match 'PipelineAst') {
            $pipeline = $true
        }

        if(!$ObjectName) {
            if($pipeline) {
                $ObjectName = '$Input'
            }
            else{
                $ObjectName = '$Object'
            }
        }

        $objectCount = 0
    }
    else{
        $pipeline = $false
    }
}
process{
    if($pipeline){
        $ObjectName = $ObjectName -replace "\[\d+\]$" -replace '$', "[$objectCount]"
        $objectCount++
    }

    if(!$pipeline -or ($object -is [System.Collections.Ilist] -and $CollectionAsObject)){
        $Object, $Object
    }

    foreach ($obj in $object){
        if($null -eq $obj) {
            continue
        }

        if($ObjectNameProperty){
            $ObjectName = $Object.$ObjectNameProperty
        }

        foreach($pp in $PropertyPath) {
            $props = $pp -split "\.|(?<=.)(?=\[)"

            $currentObj = $obj

            $exists = $true

            foreach ($p in $props) {
                if(@($currentObj.psobject.Properties).Count) {
                    $propertyNames = @($currentObj.psobject.properties.name) + 'PSObject' + 'PSBase'
                }
                else{
                    $propertyNames = @()
                }

                if($p -match "\[(\d+)\]"){
                   $index = [int] $Matches[1]
                }
                elseif($p -match '\[["'']([^"'']+)["'']\]'){
                    $p = $p -replace '\[["'']([^"'']+)["'']\]', '$1'
                    $index = $null
                }
                else{
                    $index = $null
                    if($p -match '^([''"]).*\1$'){
                        $p = $p -replace "^.(.*).$", '$1'
                    }
                }
                if($null -ne $index){
                    if($currentObj.count -gt $index) {
                        $currentObj = $currentObj[$index]
                    }
                    else{
                        $currentObj = $null
                        $exists = $false
                        break
                    }
                }
                elseif($null -ne $currentObj -and (($currentObj -is [System.Collections.IDictionary] -and $currentObj.containskey($p)) -or $propertyNames -contains $p)){
                    $currentObj = $currentObj.$p
                    if($null -eq $currentObj) {
                        $exists = $false
                        break
                    }
                }
                else{
                    $exists = $false
                    $currentObj = $null
                    break
               }
            }

            if($ValueOnly){
                $currentObj
            }
            else{
                $out = [pscustomobject]@{
                    Object = $ObjectName
                    PropertyPath = $pp
                    PropertyExists = $exists
                    Type = $(if($exists) {$currentObj.gettype().fullname})
                    Value = $(if($exists){$currentObj})
                }

                $out.pstypenames.insert(0, 'ScriptTools.Property.Get')
                $out
            }
        }

        if($object -is [System.Collections.IList]){
            $ObjectName = $ObjectName -replace "\[\d+\]$" -replace '$', "[$objectCount]"
            $objectCount++
        }
    }
}
}

function Merge-Property {
<#
.Synopsis
Merges properties / keys of the Secondary object hashtable to the Primary object hashtable.
.DESCRIPTION
This function takes all properties or keys of the Secondary object hashtable into the Primary object or hashtable. By default only those properties / keys are merge that doesn't exist in the Primary object hashtable.
If the -Force switch is used then the properties / keys of the Secondary object hashtable always merged to the Primary.
.EXAMPLE
$p = @{one = 1; three = 3}; $s = [pscustomobject]@{two = 2; three = 33; four = 4}; Merge-Property -Primary $p -Secondary $s -PassThru
Merges $s into $p. The updated hashtable will have its key 'three' remained to be 3.
.EXAMPLE
$p = @{one = 1; three = 3}; $s = [pscustomobject]@{two = 2; three = 33; four = 4}; Merge-Property -Primary $p -Secondary $s -PassThru -Force
Merges $s into $p. The updated hashtable will have its key 'three' updated to be 33.
.INPUTS
Hashtables or PSObjects
.OUTPUTS
None or the updated object of the Primary object if the -Pass Thru switch is used.
#>
[cmdletbinding (PositionalBinding=$false)]
param(
    # Primary object or hashtable to merge the properties of Secondary into.
    [Parameter(Mandatory = $true, Position = 0)] [PSobject] $Primary,
    # Secondary object or hashtable whose properties or keys to be merged into Primary.
    [Parameter(Mandatory = $true, Position = 1)] [PSobject] $Secondary,
    # If used then the updated primary objects is returned.
    [switch] $PassThru,
    # By default conflicting properties / keys are skipped. In case the -Force switch is used then conflicting properties / keys of Primary will be overwritten by properties / keys of Secondary.
    [switch] $Force
)

    if($Primary -is [System.Collections.IDictionary]){
        if($Secondary -is [System.Collections.IDictionary]){
            foreach($key in $Secondary.keys){
                if($Force -or !$Primary.containskey($key)){
                    $Primary.$key = $Secondary.$key
                }
            }
        }
        else{
            foreach($prop in $Secondary.psobject.properties.name){
                if($Force -or !$Primary.containskey($prop)){
                    $Primary.$prop = $Secondary. $prop
                }
            }
        }
    }
    else{
        if($Secondary -is [System.Collections.IDictionary]) {
            foreach($key in $Secondary.keys){
                if($Force -or $Primary.psobject.properties.name -notcontains $key){
                    Add-Member -InputObject $Primary -MemberType NoteProperty -Name $key -Value $Secondary. $key -Force
                }
            }
        }
        else{
            foreach($prop in $Secondary.psobject.properties.name){
                if($Force -or $Primary.psobject.properties.name -notcontains $prop) {
                    Add-Member -InputObject $Primary -MemberType NoteProperty -Name $prop -Value $Secondary.$prop -Force
                }
            }
        }
    }

    if($PassThru){
        $Primary
    }
}

function Expand-Property {
<#
.Synopsis
Expands all the properties or keys of the input object.
.DESCRIPTION
Recursively dumps all properties or keys of the input object. By default it goes 1 level deep, but with the -MaxDepth parameter you can allow deep search.
If the -Condensed switch is used, only the leaf properties are returned (properties that don't have any further properties or which are at the -MaxDepth).
.EXAMPLE
Expand-Property -Object $PSVersionTable -MaxDepth 2 -SkipTypes Additional system. version
Expands the properties of the $PSVersionTable object down to 2 level deep, but any [system. version] type of property won't be expanded further.
.EXAMPLE
Expand-Property -Object $PSVersionTable -MaxDepth 2 -SkipTypes Additional system. version -Condensed
Expands only the last properties in the hierarchy of properties in the $PSVersionTable object down to 2 level deep, but any [system.version] type of property won't be expanded further.
.INPUTS
Hashtables or PSObjects
.OUTPUTS
Collection of custom objects having a PropertyPath, Type, and Value properties.
#>
[cmdletbinding (PositionalBinding=$false)]
param(
    # Input object or hashtable
    [Parameter(ValueFromPipeline = $true, Position = 0)] $Object,
    # Maximum depth of recursion, default is 1
    [int] $MaxDepth = 1,
    [Parameter(Dontshow = $true)]$ObjectName,
    [Parameter(Dontshow = $true)]$PropertyPath,
    [Parameter(Dontshow = $true)]$_currentDepth = 0,
    # Only leaf properties / keys are returned
    [switch] $LeafOnly,
    # .NET types that are not expanded in properties / keys
    [string[]] $SkipTypesDefault = ('System.Int*', 'System.UInt*', 'System.Double', 'System.Decimal', 'System.String', 'System.DateTime', 'System.TimeSpan', 'System.RuntimeType',
        'System.Management.Automation.ScriptBlock', 'System.Management.Automation.PSModuleInfo', 'System.Version*', 'System.Object[]', 'System.Enum', 'System.Collections.Ilist', 'System.Byte*'),
    [string[]] $SkipTypesAdditional,
    [string[]] $ExcludeProperty
)
begin{
    $pipeline = $false
    if(!$ObjectName) {
        $parts = [scriptblock]::Create($MyInvocation.Line).ast.findall({$true}, $true)

        for($i = 0; $i -lt $parts.count; $i++){
            if($parts[$i].psobject.Properties.Name -contains 'ParameterName' -and $parts[$i].ParameterName -eq 'Object'){
                $ObjectName = $parts[$i+1].Extent.Text

                if($ObjectName -notmatch '^\(.*\)$' -and ($ObjectName -notmatch '^\$' -or ($parts[$i + 1].staticType -match "\[\]$" -and $ObjectName -notmatch "^\("))){
                    $ObjectName = "($ObjectName)"
                }
                break
            }
        }

        if(!$ObjectName -and $parts[2].gettype().fullname -match 'PipelineAst'){
            $pipeline = $true
        }

        $excludeType = $SkipTypesDefault + $SkipTypesAdditional | &{process{$_ -replace "\[", '[['-replace "\]", ']]'}}

        if(!$ObjectName) {
            if($pipeline){
                $ObjectName = '$Input'
            }
            else{
                $ObjectName = '$Object'
            }
        }

        $objectCount = 0
    }
    else{
        $pipeline = $false
    }

    $excludeType = $SkipTypesDefault + $SkipTypesAdditional | &{process{$_ -replace "\[", "[[" -replace "\]", "]]"}}
}
process{
    if($pipeline){
        $displayPath = $ObjectName + "[$objectCount]"
        $objectCount++
    }
    else{
        $displayPath = $ObjectName
    }

    if($null -eq $object) {
        $r = [pscustomobject] @{
                Object = $displayPath
                PropertyPath = $PropertyPath
                Depth = $_currentDepth
                Type = $null
                Value =  '$null'
            }
        $r.pstypenames.insert(0, 'ScriptTools.Property.Expand')
        $r
        return
    }

    if($object -is [System.DBNull]){
        $r = [pscustomobject] @{
                Object = $displayPath
                PropertyPath = $PropertyPath
                Depth = $_currentDepth
                Туре = 'System.DBNull'
                Value = 'NULL'
            }
        $r.pstypenames.insert(0, 'ScriptTools.Property.Expand')
        $r
        return
    }

    $keys = $null

    if(!($excludeType | &{process{if($Object.gettype().fullname -like $_ -or $Object.pstypenames -contains $_){$_}}})){
        if($object -is [System.Collections.IDictionary]){
            $keys = $Object.Keys
        }
        else{
            $keys = $Object.psobject.properties.name

            if($ExcludeProperty) {
                $keys = @($keys).Where({$currKey = $_; !($ExcludeProperty.Where({$currKey -like $_}))})
            }

            if($Object.GetType().FullName -notmatch 'ordered'){
                $keys = $keys | Sort-Object
            }
        }

        if(!$LeafOnly -or (!$keys -and ($Object -isnot [System.Collections.Ilist] -or $Object.count -eq 0)) -or $_currentDepth -ge $MaxDepth){
            $r = [pscustomobject] @{
                    Object = $displayPath
                    PropertyPath = $PropertyPath
                    Depth = $_currentDepth
                    Type = $(if($null -ne $object){$object.GetType().fullname})
                    Value = $0bject
                }
            $r.pstypenames.insert(0, 'ScriptTools.Property.Expand')
            $r

            if($_currentDepth -ge $MaxDepth){
                return
            }
        }

        foreach($key in $keys){
            $displayKey = $key
            if($key -match '\W'){
                $displayKey = "*$key'"
            }

            Expand-Property -Object $Object.$key -ObjectName $displayPath -MaxDepth $MaxDepth -LeafOnly:$LeafOnly -_currentDepth ($_currentDepth + 1) -SkipTypesDefault $SkipTypesDefault -SkipTypesAdditional $SkipTypesAdditional -PropertyPath $(if($PropertyPath){$PropertyPath + '.' + $displayKey}else{$displayKey})
        }

        if($keys -and $Object -is [System.Collections.Ilist] -and $_currentDepth -lt $MaxDepth){
            for($i = 0; $i -lt $Object.count; $i++){
                Expand-Property -Object $Object[$i] -ObjectName $displayPath -MaxDepth $MaxDepth -LeafOnly:$LeafOnly -_currentDepth ($_currentDepth + 1) -SkipTypesDefault $SkipTypesDefault -SkipTypesAdditional $SkipTypesAdditional -PropertyPath ("$PropertyPath[$i]")
            }
        }
    }
}
}


function Remove-Property {
<#
.Synopsis
   Removes properties of objects or values of hashtables.
.DESCRIPTION
   This function removes a property or key from an object or hashtable. It supports navigating nested property paths using dot notation and index notation (e.g. 'Parent. Child' or 'Array[0]').
   If the property or key does not exist, an error is written unless -ErrorAction Ignore is specified.
   The -Pass Thru switch can be used to return the root input object after the removal.
.EXAMPLE
   $obj = [pscustomobject] @{Prop1 = "Text"; Prop2 = "ToRemove"}; Remove-Property -Object $obj -PropertyPath Prop2; $obj
   In this example the property 'Prop2' is removed from the custom object $obj. Afterwards only Prop1 remains on the object.
.EXAMPLE
   $h = @{Name = "MyHashTable"; Temp = "RemoveMe"}; Remove-Property -Object $h -PropertyPath Temp -Pass Thru
   In this example the key 'Temp' is removed from hashtable $h. Because -PassThru is used, the updated hashtable is returned.
.EXAMPLE
   $h = @{Level1 = @{Level2 = "Value"; Extra = "Delete"}}; Remove-Property -Object $h -PropertyPath 'Level1.Extra'
   In this example a nested key 'Extra' under 'Level1' is removed from the hashtable $h using dot notation in -PropertyPath.
.EXAMPLE
   $list = [System.Collections.Generic. List[object]] @("First", "Second", "Third"); Remove-Property -Object $list -PropertyPath '[1]' -PassThru
   In this example the element at index 1 ('Second') is removed from the list using index notation in -PropertyPath. The updated list is returned via -PassThru.
.INPUTS
   hashtable or psobject
.OUTPUTS
   The updated input object if the -Pass Thru switch is used.
#>
[cmdletbinding (PositionalBinding=$false)]
param(
    # Input object, either a hashtable or a PSObject
    [Parameter(Position = 0, Mandatory = $true)] [psobject] $Object,
    # Name of the property or key to remove
    [Parameter(Position = 1, Mandatory = $true)][string] $PropertyPath,
    # Do not expands dots (.) in -PropertyPath
    [Parameter()] [switch] $LiteralPropertyName,
    # Returns the updated object after the property is removed
    [Parameter()] [switch] $PassThru,
    # Hidden parameter for recursion to return the root object when -PassThru is used
    [Parameter(Dontshow = $true)] $objectToReturn = $Object
)

    if(!$LiteralPropertyName -and $PropertyPath -match '\.|\[\w+\](?=(\.|$))'){
        $nextProp, $PropertyPath = $PropertyPath -split '\.|(?=\[\w+\]$)', 2
        if($nextProp){
            $testProp = Get-Property -Object $0bject -PropertyPath $nextProp

            if(!$testProp.PropertyExists -and $ErrorActionPreference -ne 'Ignore'){
                Write-Error -Message "Property '$nextProp' doesn't exist on object '$Object'"
                return
            }

            $nextObj = $Object.$nextProp

            if($PropertyPath -match '^\[(\d+)\]$' -and $nextObj -is [System.Collections.IList] -and $nextObj.IsFixedSize){
                $indx = [int] $Matches[1]

                if($nextObj.Count -le $indx) {
                    if($ErrorActionPreference -ne 'Ignore') {
                        Write-Error "Index property is out of range"
                    }
                    return
                }

                $updatedCollection = for($i = 0; $i -lt $nextObj.Count; $i++){
                                        if($i -ne $indx) {
                                            $nextObj[$i]
                                        }
                                    }

                $Object.$nextProp = $updatedCollection

                if($PassThru){
                    $objectToReturn
                }
            }
            else{
                Remove-Property -Object $nextObj -PropertyPath $PropertyPath -PassThru:$PassThru -objectToReturn $objectToReturn
            }
            return
        }
    }

    $indx = $null

    if($PropertyPath -match '^\[(\w+)\]$'){
        if($null -ne ($Matches[1] -as [int])){
            $indx = [int] $Matches[1]

            if($object -is [collections.ilist]){
                $PropertyPath = $null
                if($object.count -le $indx) {
                    if($ErrorActionPreference -ne 'Ignore') {
                        Write-Error "Index property is out of range"
                    }
                    return
                }
            }
            else{
                $PropertyPath = $indx
                $indx = $null
            }
        }
        else{
           $PropertyPath = $Matches[1]
        }
    }

    $PropertyPath = $PropertyPath -replace '^[''"]|[''"]$'

    if($null -eq $object) {
        if($ErrorActionPreference -ne 'Ignore') {
           Write-Error "No object"
        }
        return
    }

    if($object -is [System.Collections.IDictionary]){
        $Object.Remove($PropertyPath)
    }
    else{
        if($null -eq $indx) {
            try{
                $Object.PSObject.Properties.Remove($PropertyPath)
            }
            catch{
                throw "Couldn't remove property '$PropertyPath'"
            }
        }
        else{
            try{
                $Object.RemoveAt($indx)
            }
            catch{
                $Global:error.RemoveAt(0)
                throw "Couldn't remove index [$indx]"
            }
        }
    }

    if($PassThru){
        $objectToReturn
    }
}
#endregion

#region MicroFunctions framework

[Flags()] enum exitCode {
   OK = 0
   Error = 1                      # The functions had an issue and it is considered to exit prematurely, similar to Failed + Skipped
   Warning = 2                    # The function had a minor issue, but it is considered to have completed its execution, similar to Failed
   Skipped = 4                    # The function is considered to be skipped
   Failed = 8                     # The function had an issue, but it is considered to have completed its execution
   Break = 256                    # Terminate from a loop
   Continue = 512                 # Terminate the current flow and jump and start the flow with the next element in a loop.
   Exit = 896                     # 'Stop' flag (128 is not exposed on its own) + Break + Continue, used for functions that need to stop the whole execution flow but not as a result of an error
   Terminate = 897                # 'Stop' flag (128 is not exposed on its own) + Break + Continue + Error, used for functions that need to terminate the whole execution flow due to an error
   SkippedPermanently = 1024      # Doesn't count against Dependson and Conflicts with checks, used for functions that should be skipped in all circumstances
   TimeOut = 2048                 # The function is considered to be timed out based on the Retry configuration. We can use it together with Error or Failed if we want to consider timeout as a failure, or with Skipped if we want to consider timeout as a skip.
   Dump = 4096                    # The framework should save the current data bus and status information to a file for debugging purposes when this exit code is used, can be combined with Error, Failed, Skipped, etc.
   Retry = 8192                   # The function needs to be retried based on the Retry configuration.
}

[Flags()] enum RetryUntil {
   Error = 1
   Warning = 2
   Failed = 8
   Exit = 896
   Terminate = 897
   Break = 256
   Continue = 512
   TimeOut = 2048
}

class Retry {
    [RetryUntil] $RetryUntil = [RetryUntil] 'Error, Break, Continue'
    [TimeSpan] $TimeOut = 0
    [int32] $Counter = 0
    [TimeSpan] $RetryDelay = 0
    [datetime] $StartTime
    [uint32] $Retried = 0
    [datetime] $LastRetry
    [int32] $OriginalCounter

    [void] Reset (){
        $this.Counter = $this.OriginalCounter
        $this.LastRetry = 0
        $this.Retried = 0
        $this.StartTime = get-date
    }

    Retry () {
        $this.OriginalCounter = $this.Counter
    }

    Retry ([uint32] $RetryCounter) {
        $this.Counter = $RetryCounter - 1
        $this.OriginalCounter = $this.Counter
        $this.RetryUntil = [RetryUntil] 'Error, Break, Continue'
    }

    Retry ([int] $RetryCounter) {
        $this.Counter = $RetryCounter - 1
        $this.OriginalCounter = $this.Counter
        $this.RetryUntil = [RetryUntil] 'Error, Break, Continue'
    }

    Retry ([uint32] $RetryCounter, [TimeSpan] $Delay) {
        $this.RetryUntil = 'Error, Break, Continue'
        $this.RetryDelay = $Delay
        $this.Counter = $RetryCounter - 1
        $this.OriginalCounter = $this.Counter
    }

    Retry ([int] $RetryCounter, [string] $Delay) {
        $this.RetryUntil = 'Error, Break, Continue'
        $this.RetryDelay = [timespan] $Delay
        $this.Counter = $RetryCounter - 1
        $this.OriginalCounter = $this.Counter
    }

    Retry ([timespan] $TimeOutSpan) {
        $this.TimeOut = $TimeOutSpan
        $this.RetryUntil = [RetryUntil] 'TimeOut, Error, Break, Continue'
    }

    Retry ([string] $TimeOutSpan) {
        $this.TimeOut = [timespan] $TimeOutSpan
        $this.RetryUntil = [RetryUntil] 'TimeOut, Error, Break, Continue'
    }

    Retry ([timespan] $TimeOutSpan, [TimeSpan] $Delay) {
        $this.TimeOut = $TimeOutSpan
        $this.RetryDelay = $Delay
        $this.RetryUntil = [RetryUntil] 'TimeOut, Error, Break, Continue'
    }

    Retry ([string] $TimeOutSpan, [string] $Delay) {
        $this.TimeOut = [timespan] $TimeOutSpan
        $this.RetryDelay = [timespan] $Delay
        $this.RetryUntil = [RetryUntil] 'TimeOut, Error, Break, Continue'
    }

    Retry ([RetryUntil] $RetryUntilType, [uint32] $RetryCounter) {
        $this.RetryUntil = $RetryUntilType
        $this.Counter = $RetryCounter - 1
        $this.OriginalCounter = $this.Counter
    }

    Retry ([RetryUntil] $RetryUntilType, [TimeSpan] $TimeOutSpan, [uint32] $RetryCounter) {
        $this.RetryUntil = $RetryUntilType
        $this.TimeOut = $TimeOutSpan
        $this.Counter = $RetryCounter - 1
        $this.OriginalCounter = $this.Counter
    }

    Retry ([RetryUntil] $RetryUntilType, [TimeSpan] $TimeOutSpan, [TimeSpan] $Delay, [uint32] $RetryCounter) {
        $this.RetryUntil = $RetryUntilType
        $this.TimeOut = $TimeOutSpan
        $this.Counter = $RetryCounter - 1
        $this.OriginalCounter = $this.Counter
        $this.RetryDelay = $Delay
    }

    [string] NeedToRetry () {

        if($this.OriginalCounter -ge 0){
            $result = 'Yes'

            if($this.RetryUntil -band [RetryUntil]::TimeOut -and (((get-date) - $this.StartTime) -gt $this.TimeOut)){
                $result = 'TimeOut'
            }

            if($this.Counter -lt 0) {
                $result = 'TimeOut'
            }
        }
        else{
            $result = 'No'
        }

        return $result
    }

    [string] NeedToRetry ([exitCode] $ExitCode){
        $result = 'Yes'

        if(!(IsExitCode0K -exitcode $ExitCode) -and !($ExitCode -band $this.RetryUntil)){
            $result = $this.NeedToRetry()
        }
        else{
            $result = 'No'
        }

        return $result
    }

    [void] MarkRetry () {
        if($this.StartTime -eq 0) {
            $this.StartTime = get-date
        }

        if($this.OriginalCounter -gt 0) {
            $this.Counter--
        }

        $this.LastRetry = get-date
        $this.Retried++
    }

    [void] WaitForNextRetry () {
        if($this.Retried -gt 0){
            $waitTill = $this.LastRetry + $this.RetryDelay
            $waitFor = $waitTill = (get-date)

            if($waitFor -gt 0){
                Start-Sleep -Seconds $waitFor.totalseconds
            }
        }
    }
}

function New-MicroFunctionRetry {
<#
.SYNOPSIS
    Creates a Retry object with simple, readable parameters.
.DESCRIPTION
    Helper factory for micro-function Retry defaults. Supports counter-based,
    timeout-based, combined, and fully custom RetryUntil configurations.
.EXAMPLE
    $Retry (New-MicroFunctionRetry -Counter 3 -Delay '0:0:5')
.EXAMPLE
    $Retry = (New-MicroFunctionRetry -TimeOut '0:2:0' -Delay '0:0:10')
.EXAMPLE
   $Retry (New-MicroFunctionRetry -RetryUntil 'TimeOut, Error, Break, Continue' -Counter 5 -TimeOut '0:10:0' -Delay '0:0:5')
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    Retry
#>
[CmdletBinding(DefaultParameterSetName = 'Counter')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Counter')]
    [Parameter(Mandatory = $true, ParameterSetName = 'CounterAndTimeOut')]
    [Parameter(ParameterSetName = 'Custom')]
    [ValidateRange(1, [uint32]:: MaxValue)]
    [uint32] $Counter,

    [Parameter(Mandatory = $true, ParameterSetName = 'TimeOut')]
    [Parameter(Mandatory = $true, ParameterSetName = 'CounterAndTimeOut')]
    [Parameter(ParameterSetName = 'Custom')]
    [object] $TimeOut,

    [Parameter(ParameterSetName = 'Counter')]
    [Parameter(ParameterSetName = 'TimeOut')]
    [Parameter(ParameterSetName = 'CounterAndTimeOut')]
    [Parameter(ParameterSetName = 'Custom')]
    [object] $Delay =[timespan]::Zero,

    [Parameter(Mandatory = $true, ParameterSetName = 'Custom')]
    [RetryUntil] $RetryUntil
)

   $toTimeSpan = {
        param(
            [Parameter(Mandatory = $true)] [object] $Value,
            [Parameter(Mandatory = $true)] [string] $ParameterName
        )

        if($Value -is [timespan]){
            return $Value
        }

        if($Value -is [string]){
            try{
                return [timespan] $Value
            }
            catch{
                throw "Parameter '$ParameterName' has invalid timespan value '$Value'."
            }
        }

        throw "Parameter '$ParameterName' must be a [TimeSpan] or timespan-formatted string."
    }

    $delaySpan = & $toTimeSpan -Value $Delay -ParameterName 'Delay'

    switch($PSCmdlet.ParameterSetName) {
        'Counter' {
            return [Retry]::new($Counter, $delaySpan)
        }

        'TimeOut' {
            $timeOutSpan = & $toTimeSpan -Value $TimeOut -ParameterName 'TimeOut'
            return [Retry]::new($timeOutSpan, $delaySpan)
        }

        'CounterAndTimeOut' {
            $timeOutSpan = & $toTimeSpan -Value $TimeOut -ParameterName 'TimeOut'
            $combinedRetryUntil = [RetryUntil] 'TimeOut, Error, Break, Continue'
            return [Retry]::new($combinedRetryUntil, $timeOutSpan, $delaySpan, $Counter)
        }

        'Custom' {
            $retry = [Retry]::new()
            $retry.RetryUntil = $RetryUntil

            if($RetryUntil -band [RetryUntil]::Counter) {
                if(!$PSBoundParameters.ContainsKey('Counter')){
                    throw "Parameter 'Counter' is required when RetryUntil includes 'Counter'."
                }

                $retry.Counter = $Counter - 1
                $retry.OriginalCounter = $retry.Counter
            }

            if($RetryUntil -band [RetryUntil]::TimeOut) {
                if(!$PSBoundParameters.ContainsKey('TimeOut')){\
                    throw "Parameter 'TimeOut' is required when RetryUntil includes 'TimeOut'."
                }

                $retry.TimeOut = & $toTimeSpan -Value $TimeOut -ParameterName 'TimeOut'
           }

            $retry.RetryDelay = $delaySpan
            return $retry
       }
   }
}

function IsExitCodeOK {
<#
.SYNOPSIS
    Tests whether an exit code is considered successful.
.DESCRIPTION
   Applies the framework success-mask logic to an exitCode value and returns
    True when the code does not match the provided failure mask.
.EXAMPLE
    Is ExitCodeOK -ExitCode ([exitCode]: :OK)

    Returns True.
.INPUTS
    ScriptTools.exitCode
.OUTPUTS
    System.Boolean
#>
param([exitcode] $exitCode, $Against = [system.int32]::MaxValue)
    $mask = [int]::MaxValue -bxor [exitCode]:: Dump
    $maskedExitCode = $exitCode -band $mask

    ! ($Against -band $maskedExitCode)
}

class standardOutput {
    [int] $id
    [exitCode] $ExitCode
    [string[]] $StatusMessages
    [string[]] $FlowMessages
    [string] $Source
    [string] $NextFunction
    [standardOutput[]] $AllOutputs

    standardOutput (){
        $this.exitCode = 0
        $this.StatusMessages = [string[]] @()
        $this.FlowMessages = [string[]] @()
        $this.Source = ""
        $this.NextFunction = $null
        $this.AllOutputs = [standardOutput[]] @()
        $this.id = 1
    }
}

[Flags()] enum execCriteriaScopes {
    Previous = 0
    Dependent = 32
    Any = 64
}

[Flags()] enum execCriteriaTypes {
    Skip = 16
    Execute = 128
    AllSkipsExceptError = 1028
    AllSkips = 1029                 # SkippedPermanently + Skipped + Error, used for checking if a function is skipped by any reason
}

[Flags()] enum execCriteriaOptions {
    Execute = 128
    SkipPermanently = 1024
    SkipOnMissingParam = 2048

    # Skip = 16, Error = 1 ...
    SkipOnError = 17
    SkipOnWarning = 18
    SkipOnSkip = 20
    SkipOnFailed = 24
    SkipOnIssue = 31

    # Skip = 16, OnDependent = 32, Error = 1 ...
    SkipOnDependentError = 49
    SkipOnDependentWarning = 50
    SkipOnDependentSkip = 52
    SkipOnDependentFailed = 56
    SkipOnDependentIssue = 63

    # Skip = 16, OnAny = 64, Error = 1 ...
    SkipOnAnyError = 81
    SkipOnAnyWarning = 82
    SkipOnAnySkip = 84
    SkipOnAnyFailed = 88
    SkipOnAnyIssue = 95

    # Execute = 128, Error = 1 ...
    ExecuteOnError = 129
    ExecuteOnWarning = 130
    ExecuteOnSkip = 132
    ExecuteOnFailed = 136
    ExecuteOnIssue = 143

    # ExecuteOnDependent = 128 + 32, Error = 1 ...
    ExecuteOnDependentError = 161
    ExecuteOnDependentWarning = 162
    ExecuteOnDependentSkip = 164
    ExecuteOnDependentFailed = 168
    ExecuteOnDependentIssue = 175

    # ExecuteOnAny = 128 + 64, Error = 1 ...
    ExecuteOnAnyError = 193
    ExecuteOnAnyWarning = 194
    ExecuteOnAnySkip = 196
    ExecuteOnAnyFailed = 200
    ExecuteOnAnyIssue = 207
}

function NormalizeStringWithNumber {
<#
.SYNOPSIS
    Normalizes numeric segments between underscores for sorting.
.DESCRIPTION
    Pads numbers found between underscore separators to a fixed width so
    strings sort in natural numeric order.
.EXAMPLE
    NormalizeStringWithNumber -String 'Flow_2_Step'
    Returns Flow_0000000002_Step.
.INPUTS
    System.String
.OUTPUTS
    System.String
#>
param(
    [string] $String
)
    [regex]::Replace($String, '(?<=_)\d+(?=_)', { param($Match) $Match.Value.PadLeft(10, '0')})
}

function CheckDependson {
<#
.SYNOPSIS
    Evaluates dependency name patterns against executed functions.
.DESCRIPTION
   Checks whether dependency or conflict patterns are satisfied by previously
    executed function names, including OR syntax within each pattern entry.
.EXAMPLE
   CheckDependson -functionNames Executed $ran -Matching @('Init', 'Prepare | Setup')
    Returns satisfied function names for matching patterns.
.INPUTS
    System.String[]
.OUTPUTS
    System.String[]
#>
param(
    [string[]] $functionNamesExecuted,
    [string[]] $Matching,
    [switch] $CheckConflicts
)
    
    $satisfied = @()
    foreach($m in $Matching) {
        $currentMatch = !!$CheckConflicts
        $mAll = $m -split "\|"
        $escapedM = @($mAll | ForEach-Object {"^" + [regex]::Escape($_) + '$'}) -join "|"

        foreach($fne in $functionNamesExecuted){
            if($fne -match $escapedM){
                $currentMatch = !$CheckConflicts
                $satisfied += $fne
                break
           }
        }

        if(!$currentMatch -and !$CheckConflicts){
            $satisfied = @()
            break
        }
    }

    return $satisfied
}

function SelectFunctionsByDescriptiveNames {
<#
.SYNOPSIS
    Resolves descriptive function-name selections to concrete function names.
.DESCRIPTION
   Accepts full or suffix-style function identifiers and maps them to matching
    micro-function names from the available function list.
.EXAMPLE
    SelectFunctionsByDescriptive Names -AllFunctions $all -CurrentFunction $f -Selections @('Initialize')
    Returns resolved full function names.
.INPUTS
    System.Object
.OUTPUTS
   System.String[]
#>
param(
    $AllFunctions,
    $CurrentFunction,
    [string[]] $Selections
)
   $newSelections = @()
   foreach($s in $Selections) {
        if($s -match '^[^_]+_\d+_.+$' ){
           $selection = @($AllFunctions.Name).Where({$_ -eq $s})
        }
        else{
           $selection = @($AllFunctions.Name).Where({$_ -match "_\d+_$s"})
        }

        $selection = $selection -join "|"

        if($selection) {
            $newSelections += $selection
        }
        else{
            throw "*$s' is not a valid function name pattern in the parameters of function '$($CurrentFunction.name)"
        }
    }

    $newSelections
}

function CheckMicroFunctionOrderNumberUniqueness {
<#
.SYNOPSIS
   Validates uniqueness and naming format of micro-function order numbers.
.DESCRIPTION
   Scans function names for expected prefix-number-description format and
   returns duplicated order numbers or invalid names when found.
.EXAMPLE
   CheckMicroFunction OrderNumber Uniqueness -AllFunctions $functions
   Returns OK when numbering is valid and unique.
.INPUTS
   System.Object
.OUTPUTS
   System.Object
#>
param(
   $AllFunctions
)
   $orderNumbers = @()
   $response = 'OK'

   foreach($f in $AllFunctions){
        if($f.name -match "^(?<prefix>[^_]+)_(?<ordernumber>\d+)_(?<description>.+)$"){
           $orderNumbers += $Matches.ordernumber
        }
        else{
            if($response -eq 'OK'){
               $response = @()
            }
            $response += "Invalid function name: $($f.name)"
       }
    }

    $grouping = $orderNumbers | Group-Object

    $duplicates = $grouping | Where-Object {$_.count -gt 1}

    if($duplicates) {
        if($response -eq 'OK'){
           $response = @()
        }

        $response += "Duplicated order numbers: $($duplicates.name -join ', ')"
    }

    $response
}

function GetFunctionParameterDeclarations {
<#
.SYNOPSIS
    Extracts execution-related parameter declarations from a function's AST.
.DESCRIPTION
    Reads ExecCriteria, Dependson, ConflictsWith, and Retry declarations from a function's
    parameter block and evaluates them. Also detects loop-processing parameters.
.OUTPUTS
    [pscustomobject] with ExecCriteria, Depends On, ConflictsWith, Retry, LoopVariable
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [System.Management.Automation.FunctionInfo] $CurrentFunction,
    [Parameter(Mandatory = $true)] [System.Management.Automation.FunctionInfo[]] $AllFunctions
)

    $paramBlock = $CurrentFunction.ScriptBlock.Ast.Body.ParamBlock

    $remoteFunction = $false
    if($CurrentFunction.name -match '_remote$' ){
        $remoteFunction = $true
    }

    # Extract ExecCriteria
    $ExecCriteriaParamString = $paramBlock.Parameters | where-object {$_.Name.VariablePath.UserPath -eq 'ExecCriteria'} | Select-Object -ExpandProperty DefaultValue | Select-Object -ExpandProperty Extent | Select-Object -ExpandProperty Text
    [execCriteriaOptions] $ExecCriteria = 'Execute'

    if($ExecCriteriaParamString) {
        [execCriteriaOptions] $ExecCriteria = Invoke-Expression -Command $ExecCriteriaParamString
    }

    # Extract DependsOn
    $dependentFunctionsString = $paramBlock.Parameters | where-object {$_.Name.VariablePath.UserPath -eq 'Dependson'} | Select-Object -ExpandProperty DefaultValue | Select-Object -ExpandProperty Extent | Select-Object -ExpandProperty Text
    [string[]] $Dependson = @()

    if($dependentFunctionsString) {
        [string[]] $DependsOn = Invoke-Expression -Command $dependent Functions String
    }

    $newDependsOn = @()
    if($DependsOn) {
       $newDependson = SelectFunctionsByDescriptive Names -AllFunctions $AllFunctions -CurrentFunction $CurrentFunction -Selections $DependsOn
    }

    # Extract ConflictsWith
    $conflictingFunctionsString = $paramBlock.Parameters | where-object {$_.Name.VariablePath.UserPath -eq 'ConflictsWith'} | Select-Object -ExpandProperty DefaultValue | Select-Object -ExpandProperty Extent | Select-Object -ExpandProperty Text
    [string[]] $ConflictsWith = @()

    if($conflictingFunctionsString) {
        [string[]] $ConflictsWith = Invoke-Expression -Command $conflictingFunctionsString
    }

    $newConflictsWith = @()
    if($ConflictsWith){
        $newConflictsWith = SelectFunctionsByDescriptive Names -AllFunctions $AllFunctions -CurrentFunction $CurrentFunction -Selections $ConflictsWith
    }

    # Extract Retry
    $Retry = $null
    $retryParamString = $paramBlock.Parameters | where-object {$_.Name.VariablePath.UserPath -eq 'Retry'} | Select-Object -ExpandProperty DefaultValue | Select-Object -ExpandProperty Extent | Select-Object -ExpandProperty Text
    if($retryParamString){
        $Retry = Invoke-Expression -Command $retryParamString
        if($Retry -and $Retry.GetType().Fullname -ne 'Retry') {
            $Retry = [retry] $Retry
        }
    }

    # Detect loop-processing parameter (*_element)
    $loopProcessing = $paramBlock.Parameters | where-object {$_.Name.VariablePath.UserPath -like '*_element'}
    $LoopVariable = $null

    if($loopProcessing -and $remoteFunction){
        throw "Function '$($CurrentFunction.Name)' has a loop-processing parameter but is marked as a remote function (name ends with '_remote'). Loops are not supported with remote functions."
    }

    if($loopProcessing){
        if($loopProcessing -is [System.Collections.IList]){
            throw "Function '$($CurrentFunction.Name)' has multiple loop element parameters"
        }
        $LoopVariable = $loopProcessing.Name.VariablePath.UserPath -replace '_element$'
    }

    # Detect computer-specific parameter (*_computer)
    $computerParams = $paramBlock.Parameters | where-object {$_.Name.VariablePath.UserPath -like '*_computer'} | ForEach-Object {$_.Name.VariablePath.UserPath -replace '_computer$'}

    if($computerParams -and !$remoteFunction) {
        throw "Function '$($CurrentFunction.Name)' has computer-specific parameters but is not marked as a remote function (name should end with '_remote')"
    }

    return [pscustomobject] @{
        ExecCriteria = $ExecCriteria
        DependsOn = $newDependsOn
        ConflictsWith = $newConflictsWith
        Retry = $Retry
        LoopVariable = $LoopVariable
        RemoteFunction = $remoteFunction
        ParametersByComputer = $computerParams
    }
}

function TestSkipCriteria {
<#
.SYNOPSIS
Evaluates all skip conditions for a micro-function execution.
.DESCRIPTION
Checks SkipPermanently flag, ExecCriteria rules, ConflictsWith, and DependsOn
conditions against previous outputs. Returns exit code and skip reason message.
.OUTPUTS
[pscustomobject] @{ ShouldSkip = [bool], ExitCode = [exitCode], Message = [string] }
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [execCriteriaOptions] $ExecCriteria,
    [string[]] $ConflictsWith,
    [string[]] $Dependson,
    [standardOutput] $Output,
    [standardOutput] $PreviousStatus
)
    # Check SkipPermanently
    if($ExecCriteria -band [execCriteriaOptions]::SkipPermanently){
        return [pscustomobject] @{
            ShouldSkip = $true
            ExitCode = [exitCode] 'Skipped Permanently'
            Message = 'Skipped because function set to permanently skip'
        }
    }

    # Check ExecCriteria Skip rules against this output's history
    if($ExecCriteria -band [execCriteriaTypes]::Skip){
        if($output.AllOutputs){
            # Check if criteria is met by previous steps
            if($PreviousStatus -and $PreviousStatus.ExitCode -band $ExecCriteria){
                return [pscustomobject] @{
                    ShouldSkip = $true
                    ExitCode = [exitCode] 'Skipped'
                    Message = "Skipped because the criteria '$ExecCriteria' is met based on the exit code of the previous steps"
                }
            }

            # Check if criteria is met by any previous step
            if($ExecCriteria -band [execCriteriaScopes]::Any -and $Output.AllOutputs.ExitCode.Where({$_ -band $ExecCriteria})){
                return [pscustomobject] @{
                    ShouldSkip = $true
                    ExitCode = [exitCode] 'Skipped'
                    Message = "Skipped because the criteria '$ExecCriteria' is met based on the exit code of any previous steps"
                }
            }
        }

        # Check Skip based on ConflictsWith
        if($ConflictsWith){
            $allExecutions = $Output.AllOutputs | where-object {!($_.ExitCode -band [execCriteriaTypes]::AllSkips) } | Select-Object -ExpandProperty Source
            $conflictedExecutions = CheckDependsOn -functionNamesExecuted $allExecutions -Matching $ConflictsWith -CheckConflicts

            if($conflictedExecutions){
                return [pscustomobject] @{
                    ShouldSkip = $true
                    ExitCode = [exitCode] 'Skipped'
                    Message = "Skipped because conflicting function(s) was executed: $($conflictedExecutions -join ', ')"
                }
            }
        }

        # Check Skip based on DependsOn
        if($DependsOn -and $ExecCriteria -band [execCriteriaScopes]::Dependent){
            $allExecutions = $Output.AllOutputs | where-object {!($_.ExitCode -band [execCriteriaTypes]::AllSkips) } | Select-Object -ExpandProperty Source
            $dependentExecutions = CheckDependsOn -functionNamesExecuted $allExecutions -Matching $DependsOn

            if(!$dependentExecutions) {
                return [pscustomobject] @{
                    ShouldSkip = $true
                    ExitCode = [exitCode] 'Skipped'
                    Message = 'Skipped because at least one dependent step is missing'
                }
            }

            if($output.AllOutputs | where-object {$_.Source -in $dependentExecutions -and $_.ExitCode -band $ExecCriteria}){
                return [pscustomobject] @{
                    ShouldSkip = $true
                    ExitCode = [exitCode] 'Skipped'
                    Message = "Skipped because the criteria '$ExecCriteria' is met based on the exit code of any dependent steps"
                }
            }
        }
    }

    $shouldSkip = $true
    $Message = ''
    $exitCode = $Output.ExitCode

    # Check ExecCriteria Execute rules against this output's history
    if($ExecCriteria -band [execCriteriaTypes]::Execute -and $execCriteria -ne [execCriteriaOptions]::Execute){
        if($output.AllOutputs) {
            # Check if criteria is met by previous steps
            if($PreviousStatus -and $PreviousStatus.ExitCode -band $ExecCriteria){
                $ShouldSkip = $false
                $Message = "Executed because the criteria '$ExecCriteria' is met based on the exit code of the previous steps"
            }

            # Check if criteria is met by any previous step
            if($ExecCriteria -band [execCriteriaScopes]::Any -and $Output.AllOutputs.ExitCode.Where({$_ -band $ExecCriteria})){
                $ShouldSkip = $false
                $Message = "Executed because the criteria '$ExecCriteria' is met based on the exit code of any previous steps"
            }
        }

        # Check Execute based on ConflictsWith
        if($ConflictsWith){
            $allExecutions = $Output.AllOutputs | where-object {!($_.ExitCode -band [execCriteriaTypes]::AllSkips) } | Select-Object -ExpandProperty Source
            $conflictedExecutions = CheckDependsOn -functionNamesExecuted $allExecutions -Matching $ConflictsWith -CheckConflicts

            if($conflictedExecutions){
                $shouldSkip = $true
                $exitCode = [exitcode] 'Skipped'
                $Message = "Skipped because conflicting function(s) was executed: $($conflictedExecutions -join ', ')"
            }
        }

        # Check Execute based on DependsOn
        if($DependsOn -and $ExecCriteria -band [execCriteriaScopes]::Dependent){
            $allExecutions = $Output.AllOutputs | where-object {!($_.ExitCode -band [execCriteriaTypes]::SkipPermanently) } | Select-Object -ExpandProperty Source
            $dependentExecutions = CheckDependsOn -functionNamesExecuted $allExecutions -Matching $DependsOn

            if(!$dependentExecutions -and !($ExecCriteria -band [execCriteriaTypes]::AllSkips)){
                $ShouldSkip = $true
                $exitCode = [exitcode] 'Skipped'
                $Message = 'Skipped because at least one dependent step is missing'
            }
            elseif(!($Output.AllOutputs | where-object{$_.Source -in $dependentExecutions -and $_.ExitCode -band $ExecCriteria} ) ) {
                $ShouldSkip = $true
                $exitCode = [exitcode] 'Skipped'
                $Message = "Skipped because the criteria '$ExecCriteria' is NOT met based on the exit code of any dependent steps"
            }
            else{
                $Message = "Executed because the criteria '$ExecCriteria' is met based on the exit code of any dependent steps"
            }
        }
    }

    return [pscustomobject] @{
        ShouldSkip = $shouldSkip
        ExitCode = $exitCode
        Message = $Message
    }
}

function BuildFunctionSplatting {
<#
.SYNOPSIS
    Builds splatted parameters for a micro-function from DataBus properties.
.DESCRIPTION
    Matches function parameters to DataBus properties and builds a splatting hashtable.
    Handles SkipOnMissingParam criteria and DataBus special parameter.
.OUTPUTS
    [hashtable] @{ param1 = value, param2 = value, ... }
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [System.Management.Automation.FunctionInfo] $CurrentFunction,
    [Parameter(Mandatory = $true)] [pscustomobject] $DataBus,
    [Parameter(Mandatory = $true)] [execCriteriaOptions] $ExecCriteria,
    [string[]] $ExcludedParameters
)

    $paramBlock = $CurrentFunction.ScriptBlock.Ast.Body.ParamBlock
    $splatting = @{ExecCriteria = $ExecCriteria}

    foreach($param in $paramBlock.Parameters) {
        $paramName = $param.Name.VariablePath.UserPath

        if($paramName -in $ExcludedParameters) {
            continue
        }

        if($paramName -match '_element$') {
            continue
        }

        if($paramName -match '_computer$') {
            continue
        }

        if($paramName -eq 'DataBus') {
            $splatting.$paramName = $DataBus
        }
        elseif($DataBus.psobject.Properties.name -contains $paramName){
            $splatting.$paramName = $DataBus.psobject.Properties | Where-Object {$_.Name -eq $paramName} | Select-Object -ExpandProperty value
        }
        elseif($ExecCriteria -band [execCriteriaOptions]::SkipOnMissingParam){
            return [pscustomobject] @{
                Success = $false
                Reason = "Skipped because one of the input parameters is not present on the data bus"
            }
        }
        else{
            Write-Error "$($CurrentFunction.Name): Parameter '$paramName' is not available on the data bus" -ErrorAction Stop
        }
    }

    return [pscustomobject] @{
       Success = $true
       Splatting = $splatting
    }
}

function MergeSplattingWithRemoteParameters {
<#
.SYNOPSIS
    Merges splatted parameters with computer-specific parameters for remote execution.
.DESCRIPTION
   Combines parameters from the common DataBus with computer-specific parameters from the DataByComputer for remote execution.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    System.Management. Automation. PSCustomObject
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [hashtable] $Splatting,
    [Parameter(Mandatory = $true)] [pscustomobject] $DataBus,
    [execCriteriaOptions] $ExecCriteria,
    [string[]] $ParametersByComputer,
    [string] $PSComputerName
)

    $success = $true
    $status = @()

    foreach($paramName in $ParametersByComputer){
        if($DataBus.DataByComputer.ContainsKey($PSComputerName) -and $DataBus.DataByComputer.$PSComputerName.psobject.Properties.name -contains $paramName){
            $splatting.$paramName = $DataBus.DataByComputer.$PSComputerName.$paramName
        }
        elseif($ExecCriteria -band [execCriteriaOptions]::SkipOnMissingParam) {
            $status += "Parameter '$paramName' is not available on the DataByComputer for computer '$PSComputerName'"
            $success = $false
        }
        else{
            Write-Error "$($CurrentFunction.Name): Computer: $($ParametersByComputer): '$paramName' is not available on the computer-specific data bus" -ErrorAction Stop
        }
    }

    return [pscustomobject] @{
        Success = $success
        Splatting = $splatting
        Status = $status
   }
}

function MergeFunctionOutput {
<#
.SYNOPSIS
   Merges function execution results into standard output and DataBus.
.DESCRIPTION
   Separates function results into standardOutput properties and DataBus payload.
    Handles forced updates for stamped properties via _forceUpdateProperty flag.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    None. This function does not emit output.
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [pscustomobject] $Result,
    [Parameter(Mandatory = $true)] [standardOutput] $Output,
    [Parameter(Mandatory = $true)] [pscustomobject] $DataBus,
    [string] $MergeResultTo
)
    foreach($property in $Result.PSObject.Properties){
        if ($property.Name -in [standardOutput].GetProperties().Name) {
            Update-Property -Object $Output -PropertyPath $property.Name -Value $property.value
            continue
        }

        $forcedUpdate = $false

        if($null -ne $property.value){
            $forcedUpdate = Get-Property -Object $property.value -PropertyPath _forceUpdateProperty -ValueOnly -CollectionAsObject
        }

        Update-Property -Object $DataBus -PropertyPath "$($MergeResultTo).$($property.Name)" -Value $property.Value -Force:$forcedUpdate
    }
}

function MergeFunctionOutputLoop {
<#
.SYNOPSIS
    Merges function execution results during loop iteration.
.DESCRIPTION
    Similar to Merge FunctionOutput but skips ExitCode to preserve aggregated exit code
    from loop iterations. Used when processing collections element-by-element.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    None. This function does not emit output.
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [pscustomobject] $Result,
    [Parameter(Mandatory = $true)] [standardOutput] $Output,
    [Parameter(Mandatory = $true)] [pscustomobject] $DataBus,
    [string] $MergeResultTo
)

    foreach($property in $Result.PSObject.Properties){
        if($property.Name -in [standardOutput].GetProperties().Name) {
            # In loop mode, keep aggregated exit code and do not overwrite it with per-element exit code
            if($property.Name -eq 'ExitCode') {
                continue
            }

            Update-Property -Object $Output -PropertyPath $property.Name Value $property.value
            continue
        }

        $forcedUpdate = $false

        if($null -ne $property.value){
            $forcedUpdate = Get-Property -Object $property.value -PropertyPath _forceUpdateProperty -ValueOnly -CollectionAsObject
        }

        Update-Property -Object $DataBus -PropertyPath "$($MergeResultTo).$($property.Name)" -Value $property.Value -Force:$forcedUpdate
    }
}

function InvokeMicroFunctionLoopProcessing {
<#
.SYNOPSIS
    Executes a micro-function over a collection of DataBus elements.
.DESCRIPTION
    Handles element-by-element iteration, retry logic per element, and aggregates results.
    Respects Break and Continue exit codes for loop control.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    System.Management. Automation.PSCustomObject
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [System.Management.Automation.FunctionInfo] $CurrentFunction,
    [Parameter(Mandatory = $true)] [pscustomobject] $DataBus,
    [Parameter(Mandatory = $true)] [string] $LoopVariable,
    [Parameter(Mandatory = $true)] [hashtable] $Splatting,
    [Parameter(Mandatory = $true)] [standardOutput] $Output,
    [Retry] $Retry,
    [scriptblock] $DebugHook,
    [scriptblock] $ErrorHook,
    [string] $MergeResultTo
)

    if($DataBus.$LoopVariable){
        $elementCounter = 0
        [exitCode] $aggregatedExitCode = 'OK'
        $Output.FlowMessages += "Loop processing starts"

        foreach($element in $DataBus.$LoopVariable){
            try{
                # Converting loop parameter to standard parameter
                if($null -ne $element) {
                    Update-Property -Object $element -PropertyPath _ForceUpdateProperty -Value $true
                }

                $Splatting."$($LoopVariable)_element" = $element
                Update-Property -Object $DataBus -PropertyPath "$($LoopVariable)Element" -Value $Splatting."$($LoopVariable)_element" -Force
                if($DebugHook){
                    [void] (& $DebugHook $CurrentFunction.Name $DataBus $element )
                }

                # Executing the current function with retry support
                do{
                    $result = & $CurrentFunction @Splatting
                    if($Retry) {
                        $Retry.MarkRetry()
                        $needToRetry = $Retry.NeedToRetry($result.ExitCode)

                        if($needToRetry -eq 'Yes'){
                            $Retry.WaitForNextRetry()
                            $Output.FlowMessages += "Retrying $($Retry.Retried) after exit code '$($result.ExitCode)*"
                        }
                        elseif($needToRetry -eq 'TimeOut'){
                            $result.ExitCode = $result.ExitCode -bor [exitCode]::TimeOut
                        }
                    }
                } while($Retry -and $needToRetry -eq 'Yes')

                if($Retry) {
                    $Retry.Reset()
                }

                $aggregatedExitCode = [exitCode] ($aggregatedExitCode -bor $result.ExitCode)
                $Output.FlowMessages += "$($result.ExitCode): element index $elementCounter"
            }
            catch{
                $global:Error.RemoveAt(0)
                $result = [pscustomobject] @{}
                $Output.FlowMessages += "Execution failed: $($_.exception.message) at element index $elementCounter"
                $Output.ExitCode = 'Error'
                $aggregatedExitCode = 'Error'
                $traceInfo = ($_.ScriptStackTrace -split "\r\n" | Where-Object {$_ -notmatch 'at (InvokeMicroFunctionWrapper,|InvokeMicroFunctionLoopProcessing,|Start-MicroFunctions,)'} ) -join "`r`n"
                Write-Error -Message $traceInfo

                if($ErrorHook){
                    [void] (& $ErrorHook $CurrentFunction.Name $DataBus $element )
                }

                break
            }
                
            $elementCounter++
            $Output.exitCode = $aggregatedExitCode

            MergeFunctionOutputLoop -Result $result -Output $Output -DataBus $DataBus -MergeResultTo $MergeResultTo

            if($result.ExitCode -band [exitCode]::Break){
                $Output.FlowMessages += "Break: Breaking from loop"
                break
            }

            if($result.ExitCode -band [exitCode]::Continue) {
                $Output.FlowMessages += "Continue: jumping to next element"
                continue
            }
        }
    }
    else{
        $result = [pscustomobject]@{
                                    ExitCode = [exitCode]::Skipped
                                    FlowMessages = "Skipped: collection '$LoopVariable' in DataBus is empty"
                                    NextFunction = $null
                                }
        MergeFunctionOutput -Result $result -Output $Output -DataBus $DataBus -MergeResultTo $MergeResultTo
    }

    return $result
}

function ExecuteMicroFunctionRemotely {
<#
.SYNOPSIS
    Executes a micro-function remotely on a target computer.
.DESCRIPTION
    Stages the script on the remote node when needed, invokes a generated
    remote execution wrapper, and returns result plus per-node output.
.EXAMPLE
    ExecuteMicroFunction Remotely -ExecuteOnComputer srv01 -ScriptPath $script -splatting $splat -CurrentFunctionName 'Flow_010_Run' -id 1
    Executes the specified micro-function remotely.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    System.Management. Automation. PSCustomObject
#>
param(
    [string] $ExecuteOnComputer,
    [string] $ScriptPath,
    [hashtable] $splatting,
    [string] $CurrentFunctionName,
    [int] $id
)
    $cleanupRemoteFiles = $null

    $ms = Split-Path -Path $ScriptPath -Leaf
    $hash = Get-FileHash -Path $ScriptPath

    $destination = "\\$ExecuteOnComputer\c$\SysAdmin\Temp"
    
    if(!(Test-Path -Path $destination)) {
        [void] (New-Item -Path $destination -ItemType Directory)
    }

    $destinationScript = Join-Path -Path $destination -ChildPath $ms

    $remoteScriptExists = Test-Path -Path $destinationScript

    $remoteFileHash = [pscustomobject] @{Hash = $null}

    if($remoteScriptExists){
        $remoteFileHash = Get-FileHash -Path $destinationScript
    }

    if($remoteFileHash.hash -ne $hash.hash){
        $cleanupRemoteFiles = Copy-Item -Path $ScriptPath -Destination $destination -PassThru
    }

$remoteScriptString = @"
param(
    [hashtable] `$splatting = `$using:splatting,
    [string] `$CurrentFunctionName = `$using:CurrentFunctionName,
    [PSObject] `$Output = `$using:Output
)

[Flags()] enum exitCode {
    OK = 0
    Error = 1
    Warning = 2
    Skipped = 4
    Failed = 8
    Retry = 8192
}

[Flags()] enum execCriteriaOptions {
    Execute = 128
    SkipPermanently = 1024
    SkipOnMissingParam = 2048
    SkipOnError = 17
    SkipOnWarning = 18
    SkipOnSkip = 20
    SkipOnFailed = 24
    SkipOnIssue = 31
    SkipOnDependentError = 33
    SkipOnDependentWarning = 34
    SkipOnDependentSkip = 36
    SkipOnDependentFailed = 40
    SkipOnDependentIssue = 47
    SkipOnAnyError = 65
    SkipOnAnyWarning = 66
    SkipOnAnySkip = 68
    SkipOnAnyFailed = 72
    SkipOnAny Issue = 79
}

class standardOutput {
    [int] `$id
    [exitCode] `$ExitCode
    [string[]] `$StatusMessages
    [string[]] `$FlowMessages
    [string]   `$Source
    [string] `$NextFunction
    [standardOutput[]] `$AllOutputs

    standard Output () {
        `$this.exitCode = 0
        `$this.StatusMessages = [string[]] @()
        `$this.FlowMessages = [string[]] @()
        `$this.Source =
        `$this.NextFunction = $null
        `$this.AllOutputs = [standardOutput[]] @()
        `$this.id = 1
   }
}

[Flags()] enum RetryUntil {
    Error 1
    Warning = 2
    Failed = 8
    Exit = 896
    Terminate = 897
    Break = 256
    Continue 512
    TimeOut = 2048
}

class Retry {
    [RetryUntil] `$RetryUntil = [RetryUntil] 'Error, Break, Continue'
    [TimeSpan] `$TimeOut = 0
    [int32] `$Counter = 0
    [TimeSpan] `$RetryDelay = Ө
    [datetime] `$StartTime
    [uint32] `$Retried = 0
    [datetime] `$LastRetry
    [int32] `$OriginalCounter

    [void] Reset () {
        `$this.Counter = `$this.OriginalCounter
        `$this.LastRetry = 0
        `$this.Retried = 0
        `$this.StartTime = get-date
    }

    Retry () {
        `$this.OriginalCounter = `$this.Counter
    }

    Retry ([uint32] $RetryCounter) {
        `$this.Counter = `$RetryCounter - 1
        `$this.OriginalCounter = `$this.Counter
        `$this.RetryUntil = [RetryUntil] 'Error, Break, Continue'
    }

    Retry ([int] `$RetryCounter) {
        `$this.Counter = `$RetryCounter - 1
        `$this.OriginalCounter = `$this.Counter
        `$this.RetryUntil = [RetryUntil] 'Error, Break, Continue'
    }

    Retry ([uint32] `$RetryCounter, [TimeSpan] `$Delay) {
        `$this.RetryUntil = 'Error, Break, Continue'
        `$this.RetryDelay = `$Delay
        `$this.Counter = `$RetryCounter - 1
        `$this.OriginalCounter = `$this.Counter
    }

    Retry ([int] `$RetryCounter, [string] `$Delay) {
        `$this.RetryUntil = 'Error, Break, Continue'
        `$this.RetryDelay = [timespan]  `$Delay
        `$this.Counter = `$RetryCounter - 1
        `$this.OriginalCounter = `$this.Counter
    }

    Retry ([timespan] `$TimeOutSpan) {
        `$this.TimeOut = `$TimeOutSpan
        `$this.RetryUntil = [RetryUntil] 'TimeOut, Error, Break, Continue'
    }

    Retry ([string] `$TimeOutSpan) {
        `$this.TimeOut = [timespan] `$TimeOutSpan
        `$this.RetryUntil = [RetryUntil] 'TimeOut, Error, Break, Continue'
    }

    Retry ([timespan] `$TimeOutSpan, [TimeSpan] `$Delay) {
        `$this.TimeOut = `$TimeOutSpan
        `$this.RetryDelay = `$Delay
        `$this.RetryUntil = [RetryUntil] 'TimeOut, Error, Break, Continue'
    }

    Retry ([string] `$TimeOutSpan, [string] `$Delay) {
        `$this.TimeOut = [timespan] `$TimeOutSpan
        `$this.RetryDelay = [timespan] `$Delay
        `$this.RetryUntil = [RetryUntil] 'TimeOut, Error, Break, Continue'
    }

    Retry ([RetryUntil] `$RetryUntilType, [uint32] `$RetryCounter) {
        `$this.RetryUntil = `$RetryUntilType
        `$this.Counter = `$RetryCounter - 1
        `$this.OriginalCounter = `$this.Counter
    }

    Retry ([RetryUntil] `$RetryUntilType, [TimeSpan] `$TimeOutSpan, [uint32] `$RetryCounter) {
        `$this.RetryUntil = `$RetryUntilType
        `$this.TimeOut = `$TimeOutSpan
        `$this.Counter = `$RetryCounter - 1
        `$this.OriginalCounter = `$this.Counter
    }

    Retry ([RetryUntil] `$RetryUntilType, [TimeSpan] `$TimeOutSpan, [TimeSpan] `$Delay, [uint32] `$RetryCounter) {
        `$this.RetryUntil = `$RetryUntilType
        `$this.TimeOut = `$TimeOutSpan
        `$this.Counter = `$RetryCounter - 1
        `$this.OriginalCounter = `$this.Counter
        `$this.RetryDelay = `$Delay
    }

    [string] NeedToRetry (){
        if(`$this.OriginalCounter -ge 0){
            `$result = 'Yes'

            if(`$this.RetryUntil -band [RetryUntil]::TimeOut -and (((get-date) - `$this.StartTime) -gt `$this.TimeOut)){
                 `$result = 'TimeOut'
            }

            if(`$this.Counter -lt 0) {
                `$result = 'TimeOut'
            }
       }
       else{
            `$result = 'No'
       }

       return `$result
    }

    [string] NeedToRetry ([exitCode] `$ExitCode) {
        `$result = 'Yes'

        if(!(IsExitCode0K -exitcode `$ExitCode) -and !(`$ExitCode -band `$this.RetryUntil)){
            `$result = `$this.NeedToRetry()
        }
        else{
            `$result = 'No'
        }

        return `$result
    }

    [void] MarkRetry () {
        if(`$this.StartTime -eq 0){
            `$this.StartTime = get-date
        }

        if(`$this.OriginalCounter -gt 0) {
            `$this.Counter--
        }

        `$this.LastRetry = get-date
        `$this.Retried++
    }

    [void] WaitForNextRetry () {
        if(`$this.Retried -gt 0){
            `$waitTill = `$this.LastRetry + `$this.RetryDelay
            `$waitFor = `$waitTill - (get-date)
            if(`$waitFor -gt 0) {
                Start-Sleep -Seconds `$waitFor.totalseconds
            }
        }
    }
}

    function IsExitCodeOK {
    param([exitcode] `$exitCode, `$Against = [system.int32]::MaxValue)
        `$mask = [int]::MaxValue -bxor [exitCode]::Dump
        `$maskedExitCode = `$exitCode -band `$mask
        !(`$Against -band `$maskedExitCode)
    }

    `$Output = [standardOutput] `$Output

    - '$destinationScript' -DefineFunctionsOnly

    `$Retry = [retry] `$Splatting.Retry

    do{
        `$result = &$($CurrentFunctionName) @splatting


        if(`$Retry){
            `$Retry.MarkRetry()
            `$needToRetry = `$Retry.NeedToRetry(`$result.ExitCode)
            if(`$needToRetry -eq 'Yes'){
                `$Retry.WaitForNextRetry()
                `$output.FlowMessages += "Retrying `$(`$Retry.Retried) after exit code "`$(`$result.ExitCode)'"
            }
            elseif(`$needToRetry -eq 'TimeOut'){
                 `$result.ExitCode = `$result.ExitCode -bor [exitCode]::TimeOut
            }
        }
    }while(`$Retry -and `$needToRetry -eq 'Yes')

    `$output.FlowMessages += "`$(`$result.ExitCode): function exited"

    [pscustomObject] @{
        Result = `$result
        Output = `$output
    }
"@

    $Output = [standardOutput]::new()
    $Output.id = $id
    $Output.Source = $CurrentFunctionName

    $remoteScript = [scriptblock]::Create($remoteScriptString)

    $remoteResult = Invoke-Command -ComputerName $ExecuteOnComputer -ScriptBlock $remoteScript

    Add-Member -InputObject $remoteResult.Result -MemberType NoteProperty -Name PSComputerName -Value $remoteResult.PSComputerName
    Add-Member -InputObject $remoteResult.Output -MemberType NoteProperty -Name PSComputerName -Value $remoteResult.PSComputerName

    if($cleanupRemoteFiles) {
        add-member -InputObject $remoteResult -MemberType NoteProperty -Name CleanupRemoteFiles -Value $cleanupRemoteFiles
    }

    return $remoteResult
}

function InvokeMicroFunctionWrapper {
<#
.SYNOPSIS
    Invokes one micro-function with orchestration controls.
.DESCRIPTION
    Builds runtime splatting from DataBus, evaluates skip criteria, executes
    local/remote/loop modes, merges outputs, and determines NextFunction.
.EXAMPLE
    InvokeMicroFunctionWrapper -DataBus $db -Current Function $fn -AllFunctions $all
    Executes one orchestration step and returns standard output.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    standardOutput
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [pscustomobject] $DataBus,
    [standardOutput] $PreviousStatus,
    [System.Management.Automation.FunctionInfo] $CurrentFunction,
    [System.Management.Automation.FunctionInfo[]] $AllFunctions,
    [scriptblock] $DebugHook,
    [scriptblock] $SkipHook,
    [scriptblock] $ErrorHook,
    [string] $MergeResultTo,
    $InitialOutput
)

    $excludedParameters = 'ExecCriteria', 'Depends On', 'ConflictsWith', 'Retry', 'StatusMessages', 'ExecuteRemotely'

    # Extract execution-related declarations from function parameters
    $declarations = GetFunctionParameterDeclarations -CurrentFunction $CurrentFunction -AllFunctions $AllFunctions

    [execCriteriaOptions] $ExecCriteria = $declarations.ExecCriteria
    [string[]] $newDependsOn = $declarations.DependsOn
    [string[]] $newConflictsWith = $declarations.ConflictsWith
    [Retry] $Retry = $declarations.Retry
    [string] $loopVariable = $declarations.LoopVariable

    # Each micro-function can declare execution criteria and dependencies in its param defaults.
    # This wrapper reads those declarations and decides whether to run or skip this step.
    $result = [pscustomobject]@{}

    if($InitialOutput){
        try{
            $PreviousStatus = [pscustomobject] $InitialOutput
        }
        catch{
            $global:Error.RemoveAt(0)
            $string = ConvertTo-PSData -Object $InitialOutput
            $PreviousStatus = ConvertFrom-PSData -PSDataString $string
        }
    }

    $output = New-Object -TypeName standardOutput
    $output.Source = $CurrentFunction.Name
    if($PreviousStatus) {
        if($PreviousStatus.All0utputs){
            $output.AllOutputs += $PreviousStatus.AllOutputs
        }
        $output.AllOutputs += $PreviousStatus
    }
    else{
        $output.AllOutputs = @()
    }

    $output.id = $output.AllOutputs.Count

    $splatting = @{ExecCriteria = $ExecCriteria}

    if($Retry){
        $splatting.Retry = $Retry
    }

    # Evaluate all skip conditions
    $skipResult = TestSkipCriteria -ExecCriteria $ExecCriteria -ConflictsWith $newConflictsWith -DependsOn $newDependsOn -Output $output -PreviousStatus $PreviousStatus
    
    if($skipResult.ShouldSkip){
        $output.ExitCode = $skipResult.ExitCode
        Update-Property -Object $output -PropertyPath FlowMessages -Value $skipResult.Message
    }

    if(!($output.ExitCode -band [execCriteriaTypes]::AllSkips)){
        # Build splatted parameters from DataBus properties by matching parameter names
        $splattingResult = BuildFunctionSplatting -CurrentFunction $CurrentFunction -DataBus $DataBus -ExecCriteria $ExecCriteria -ExcludedParameters $excludedParameters

        if(!$splattingResult.Success) {
            $output.ExitCode = [exitCode] 'Skipped'
            Update-Property -Object $output -PropertyPath FlowMessages -Value $splattingResult.Reason
        }
        else{
            $splatting = $splattingResult.Splatting
            if($Retry) {
                $splatting.Retry = $Retry
            }
        }
    }

    if(!($output.ExitCode -band [execCriteriaTypes]::AllSkips)){
        $element = $null
        if(!$loopVariable){
            try{
                # Executing the current function

                if($DebugHook){
                    [void] (& $DebugHook $CurrentFunction.Name $DataBus $element )
                }

                if($declarations.RemoteFunction){
                    foreach($computer in $DataBus.PSComputerName) {
                        $splattingResult = MergeSplattingWithRemoteParameters -Splatting $splatting -ParametersByComputer $declarations.ParametersByComputer -DataBus $DataBus -PSComputerName $computer -ExecCriteria $ExecCriteria
                        
                        if($splattingResult.Success){
                            $splatting = $splattingResult.Splatting

                            $id = 0

                            $previousOutputs = Get-Property -Object $DataBus -PropertyPath "OutputByComputer.$computer"

                            if($previousOutputs.PropertyExists){
                                $id = @($previousOutputs.Value).Count
                            }

                            $remoteResult = ExecuteMicroFunction Remotely -ExecuteOnComputer $computer -ScriptPath $DataBus.mainscriptpath -splatting $splatting -CurrentFunctionName $currentfunction.name -id $id

                            $remoteResult.Output.AllOutputs += $previousOutputs.value

                            $previousRemoteResult = Get-Property -Object $DataBus -PropertyPath "DataByComputer.$computer"

                            if(!$previousRemoteResult.PropertyExists) {
                                Update-Property -Object $DataBus.DataByComputer -propertyPath $computer -Value $remoteResult.Result
                            }
                            else{
                                $previousStatusMessages = $DataBus.DataByComputer.$computer.StatusMessages
                                Merge-Property -Primary $DataBus.DataByComputer.$computer -Secondary $remoteResult.Result -Force
                                $DataBus.DataByComputer.$computer.ExitCode = $DataBus.DataByComputer.$computer.ExitCode -bor $remoteResult.Result.exitCode
                                $DataBus.DataByComputer.$computer.StatusMessages = $previousStatusMessages + $remoteResult.Result.StatusMessages
                            }

                            Update-Property -Object $DataBus.OutputByComputer -propertyPath $computer -Value $remoteResult.Output
                        }
                        else{
                            $output.ExitCode = [exitCode] 'Skipped'
                            Update-Property -Object $output -PropertyPath FlowMessages -Value $splattingResult.Reason
                        }
                    }
                }
                else{
                    do{
                        $result = &$CurrentFunction @splatting

                        if($Retry){
                            $Retry.MarkRetry()
                            $needToRetry = $Retry.NeedToRetry($result.ExitCode)
                            if($needToRetry -eq 'Yes') {
                                $Retry.WaitForNextRetry()
                                $output.FlowMessages += "Retrying $($Retry.Retried) after exit code '$($result.ExitCode)'"
                            }
                            elseif($needToRetry -eq 'TimeOut') {
                                $result.ExitCode = $result.ExitCode -bor [exitCode]::TimeOut
                            }
                        }
                    }while($Retry -and $needToRetry -eq 'Yes')

                    $output.FlowMessages += "$($result.ExitCode): function exited"
                }
            }
            catch{
                $result = [pscustomobject] @{}
                $output.FlowMessages += "Execution failed: $($_.exception.message)"
                Write-Error -ErrorRecord $_
                $traceInfo = ($_.ScriptStackTrace -split "\r\n" | Where-Object {$ -notmatch 'at (InvokeMicroFunctionWrapper,|Start-MicroFunctions,)'} ) -join "`r`n"
                Write-Error -Message $traceInfo
                $output.ExitCode = 'Error'

                if($ErrorHook){
                    [void] (& $ErrorHook $CurrentFunction.Name $DataBus $element )
                }
            }

            # Merge function output back to either standard status fields or DataBus payload fields
            MergeFunctionOutput -Result $result -Output $output -DataBus $DataBus -Merge ResultTo $MergeResultTo
        }
        elseif($DataBus.PSObject.Properties.Name -eq $loopVariable){
            $PSBoundParameters.LoopProcessing = $true

            $splattingInvokeMFLP = @{
                CurrentFunction = $CurrentFunction
                DataBus = $DataBus
                LoopVariable = $loopVariable
                Splatting = $splatting
                Output = $output
                Retry = $Retry
                DebugHook = $DebugHook
                ErrorHook = $ErrorHook
                MergeResultTo = $MergeResultTo
            }

            $result = InvokeMicroFunction LoopProcessing @splattingInvokeMFLP
        }
        else{
            throw "Loop variable '$loopVariable' is not valid in function '$($CurrentFunction.Name)*"
        }
    }
    elseif($SkipHook) {
        [void] (& $SkipHook)
    }

    $nextFunction = Get-Property -Object $result -PropertyPath "NextFunction"

    if(!$nextFunction.PropertyExists -or !$nextFunction.value){
        $output.NextFunction = $AllFunctions.Name | Where-Object {(NormalizeStringWithNumber $_) -gt (NormalizeStringWithNumber $CurrentFunction.Name)} | Select-Object -First 1

        if($output.NextFunction){
            $output.FlowMessages += "Next function is set to '$($output.NextFunction)' by function naming"
        }
        else{
            $output.FlowMessages += "There's no next function, ending flow"
        }
    }
    else{
        if($nextFunction.value -match '^[^_]+_\d+_.+$'){
            $nextFunctionName = $AllFunctions.Name | Where-Object {$_ -eq $result.NextFunction}
        }
        else{
            $nextFunctionName = $AllFunctions.Name | Where-Object {$_ -match "_\d+_$($result.NextFunction)"}
        }
        $output.NextFunction = $nextFunctionName

        if($nextFunctionName) {
            $output.FlowMessages += "Next function is explicitly set to '$nextFunctionName'"
        }
        else{
            $output.FlowMessages += "Next function is not valid or empty, ending flow"
        }
    }

    $nextFunctionAllowed = Get-Property -Object $result -PropertyPath "NextFunctionAllowed"

    if($nextFunctionAllowed.PropertyExists -and $nextFunctionAllowed.value){
        $allowedNextFunction = SelectFunctionsByDescriptive Names -AllFunctions $AllFunctions -CurrentFunction $CurrentFunction -Selections $nextFunctionAllowed.value
        if($allowedNextFunction -notcontains $nextFunctionName) {
            throw "Next function '$nextFunctionName' is not allowed by function '$($CurrentFunction.Name)'"
        }
    }

    $dumpNow = $false
    if($DataBus.psobject.properties.name -contains 'DumpAt' -and $DataBus.DumpAt){
        $dumpAt = SelectFunctionsByDescriptiveNames -AllFunctions $AllFunctions -CurrentFunction $CurrentFunction -Selections $DataBus.DumpAt
        if($dumpAt -contains $CurrentFunction.Name) {
            $dumpNow = $true
        }
    }

    if(($result.exitCode -band [exitCode]::Dump -or $dumpNow) -and $Databus.psobject.Properties.Name -contains 'DumpFolder' -and $Databus.DumpFolder){
        DumpStatus -DataBus $DataBus -Output $output
    }

    return $output
}

function DumpStatus {
<#
.SYNOPSIS
   Dumps current DataBus and output state to a .data.ps1 file.
.DESCRIPTION
   Creates a dump artifact under the configured dump folder containing
   orchestration state for troubleshooting or resume scenarios.
.EXAMPLE
   DumpStatus -DataBus $DataBus -Output $Output
   Writes a dump file for the current orchestration state.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    None. This function does not emit output.
#>
param(
    [psobject] $DataBus,
    [standardOutput] $Output
)

    $dumpFileName = "MicroFunctionDump-" + (Split-Path $DataBus.MainScriptPath -Leaf) + "-" + $Output.Source + ".data.ps1"

    $dumpObject = @{DataBus = $DataBus; Output = $Output}

    Export-PSData -Path (Join-Path -Path $DataBus.DumpFolder -ChildPath $dumpFileName) -Object $dumpObject
}

function InitializeDataBus {
<#
.SYNOPSIS
    Initializes the DataBus from parent script/function parameters.
.DESCRIPTION
    Extracts parameters from parent caller's AST and builds initial DataBus hash,
    merging caller's bound parameters with parameter defaults.
.INPUTS
   None. This function does not accept pipeline input.
.OUTPUTS
    System.Collections. Hashtable
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [System.Management.Automation.CallStackFrame] $ParentFunction
)
    $pbp = $ParentFunction.InvocationInfo.BoundParameters
    $paramBlock = @()
    $hasParamBlock = $false
    $ast = $ParentFunction.InvocationInfo.MyCommand.ScriptBlock.Ast

    if($ast.psobject.Properties.Name -contains 'ParamBlock'){
        $hasParamBlock = $true
        $paramBlock = $ast.ParamBlock.Parameters
    }
    elseif($ast.psobject.Properties.Name -contains 'Body' -and $ast.Body.psobject.Properties.Name -contains 'ParamBlock'){
        $hasParamBlock = $true
        $paramBlock = $ast.Body.ParamBlock.Parameters
    }

    $dbHash = @{
                    DataByComputer = @{}
                    OutputByComputer = @{}
                }

    foreach($pb in $paramBlock){
        $variableName = $pb.Name.VariablePath.UserPath

        if($variableName -eq 'Define Functions Only'){
            continue
        }

        if($pbp.ContainsKey($variableName)){
            $dbHash.$variableName = $pbp.$variableName
        }
        else{
            if($null -ne $pb.DefaultValue) {
                try{
                    $defaultValue = Invoke-Expression $pb.DefaultValue.Extent.Text
                }
                catch{
                    Write-Error -Exception $_
                    $global:error.RemoveAt(0)
                    $defaultValue = $null
                }
            }
            elseif($pb.StaticType.FullName -in 'System.Management.Automation.SwitchParameter', 'System.Boolean') {
                $defaultValue = $false
            }
            else{
                $defaultValue = $null
            }

            $dbHash.$variableName = $defaultValue
        }
    }

    return @{
        HasParamBlock = $hasParamBlock
        ParameterBlock = $paramBlock
        BoundParameters = $pbp
        DataBusHash = $dbHash
    }
}

function LoadMicroFunctionsLibrary {
<#
.SYNOPSIS
Loads external micro-function library scripts.
.DESCRIPTION
Parses and dots sources external .ps1 files containing micro-function definitions.
Validates that files contain only function definitions and no other code.
.INPUTS
None. This function does not accept pipeline input.
.OUTPUTS
System.String[]
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [string[]] $LibraryPaths,
    [Parameter(Mandatory = $true)] [string] $FunctionNameFilter
)

    Get-ChildItem -Path "function:\$FunctionNameFilter" | Remove-Item

    $newExternalScripts = @()
    foreach($es in $LibraryPaths){
        if(Test-Path -Path $es -PathType Leaf){
            $tokens = [System.Management.Automation.Language.Token[]]::new(1)
            $errors = [System.Management.Automation.Language.ParseError[]]::new(1)

            $AST = [System.Management.Automation.Language.Parser]:: ParseFile(
                $es,
                [ref] $tokens,
                [ref] $errors
            )

            if($ast){
                $functionDefinitions += $Ast.FindAll({$args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $args[0].name -like $FunctionNameFilter}, $false)
                $nonFunctionDefs = $Ast.FindAll({$args[0].GetType().fullname -notin ('System.Management.Automation.Language.FunctionDefinitionAst',
                                                     'System.Management.Automation.Language.ScriptBlockAst',
                                                         'System.Management.Automation.Language.NamedBlockAst')}, $false)
            }

            if($errors) {
                $errors.Message | Write-Error
                throw "File '$es' is an invalid PowerShell file"
            }

            if($nonFunctionDefs.Count -gt 0){
                throw "File '$es' doesn't contain only function definitions"
            }

            . $es

            $newExternalScripts += $es
        }
    }

    return $newExternalScripts
}

function InvokeMicroFunctionOrchestrationLoop {
<#
.SYNOPSIS
    Executes the main orchestration loop for micro-function sequencing.
.DESCRIPTION
    Iterates through functions in order, invoking each via InvokeMicroFunctionWrapper
    and following the Next Function chain.
.INPUTS
    None. This function does not accept pipeline input.
.OUTPUTS
    standardOutput
#>
[cmdletbinding()]
param(
    [Parameter(Mandatory = $true)] [System.Management.Automation.FunctionInfo[]] $FunctionsToExecute,
    [Parameter(Mandatory = $true)] [System.Management.Automation.FunctionInfo] $StartingFunction,
    [Parameter(Mandatory = $true)] [pscustomobject] $DataBus,
    [scriptblock] $PreInvoke,
    [scriptblock] $PostInvoke,
    [scriptblock] $DebugHook,
    [scriptblock] $ErrorHook,
    [scriptblock] $SkipHook,
    [string] $MergeResultTo,
    $InitialOutput,
    $LoopedSubFlow
)

    $result = $null
    $currentFunction = $StartingFunction
    $currentInitialOutput = $InitialOutput

    while($currentFunction){
        if($PreInvoke) {
            [void] (& $PreInvoke $currentFunction)
        }

        $result2 = [standardOutput] $result
        $result = InvokeMicroFunctionWrapper -DataBus $DataBus -PreviousStatus $result2 -CurrentFunction $currentFunction -AllFunctions $FunctionsToExecute -DebugHook $DebugHook -SkipHook $SkipHook -MergeResultTo $MergeResultTo -ErrorHook $ErrorHook -InitialOutput $currentInitialOutput

        if($LoopedSubFlow -and ($result.ExitCode -band [exitcode]::Continue -or $result.ExitCode -band [exitcode]::Break)){
            $currentFunction = $null
        }
        elseif($result.ExitCode -band 128) {
            $currentFunction = $null
        }
        else{
            $currentFunction = $FunctionsToExecute | Where-Object {$_.name -eq $result.NextFunction}
        }

        if($PostInvoke){
            & $PostInvoke
        }

        $currentInitialOutput = $null
    }

    return $result
}

function Start-MicroFunctions {
<#
.SYNOPSIS
Starts execution of a micro-function flow.
.DESCRIPTION
Initializes and/or rehydrates DataBus state, loads function libraries,
validates function order, and runs orchestration from the first or resumed step.
.EXAMPLE
Start-MicroFunctions -FunctionName Filter Flow_*
Runs all matching micro-functions in orchestration order.
.INPUTS
None. This function does not accept pipeline input.
.OUTPUTS
standardOutput
#>
param(
    [Parameter (Mandatory = $true)] [string] $FunctionNameFilter,
    [pscustomobject] $DataBus,
    [string[]] $MicroFunctionsLibrary,
    [scriptblock] $CatchScriptBlock,
    [scriptblock] $FinallyScriptBlock,
    [scriptblock] $PreInvoke,
    [scriptblock] $PostInvoke,
    [scriptblock] $DebugHook,
    [scriptblock] $ErrorHook,
    [scriptblock] $SkipHook,
    [scriptblock] $beforeFunctionLoad,
    [scriptblock] $afterFunctionLoad,
    [string]      $MergeResultTo
)

    $result = $null

    $mainScriptParams = 'DumpFolder', 'DumpAt', 'StartFlowUsing'

    $cs = @(Get-PSCallStack)
    $script = $cs | Where-Object {$_.ScriptName -and $_.ScriptName -ne $cs[0].ScriptName}
    $parentFunction = $cs[1]
    $loopedSubFlow = $cs | Select-Object -Skip 1 |
                        Where-Object {$_.Command -eq 'InvokeMicroFunctionWrapper' -and $_.InvocationInfo.BoundParameters.containskey('LoopProcessing') -and $_.InvocationInfo.BoundParameters.LoopProcessing} |
                            Select-Object -First 1

    # Initialize DataBus from parent parameters
    $initResult = InitializeDataBus -ParentFunction $parentFunction
    $hasParamBlock = $initResult.HasParamBlock
    $pbp = $initResult.BoundParameters
    $dbHash = $initResult.DataBusHash

    # If DataBus parameter not provided, create from PSBoundParameters
    if(!$pbp.ContainsKey("DataBus")) {
        if(!$hasParamBlock){
            Write-Error -Message 'No ParamBlock found'
        }

        $dbhash.MainScriptPath = $script.InvocationInfo.MyCommand.Path
        
        $DataBus = [pscustomobject] $dbHash
        $pbp.Add("DataBus", $DataBus)
    }

    $loopVariable = @($dataBus.PSObject.Properties.Name) -match '_element$'

    foreach($lv in $loopVariable){
        $localVarName = $lv -replace '_element$', 'Element'
        Update-Property -Object $dataBus -PropertyPath $localVarName -Value $dataBus.$lv
        Remove-Property -Object $dataBus -PropertyPath $lv
    }

    # Execution order is encoded by numeric prefixes in function names (for example: *_010_*).
    if($beforeFunctionLoad){
        [void] (& $beforeFunctionLoad)
    }

    if($MicroFunctionsLibrary){
        $newExternalScripts = LoadMicroFunctionsLibrary -LibraryPaths $MicroFunctionsLibrary -FunctionNameFilter $FunctionNameFilter

        if($newExternalScripts){
            Update-Property -Object $DataBus -PropertyPath MicroFunctionsLibrary -Value $newExternalScripts -Force
        }
    }
    elseif($script.InvocationInfo.MyCommand.ScriptBlock.Ast.ParamBlock.Parameters.Name.VariablePath.UserPath -contains 'DefineFunctionsOnly'){
        . $script.InvocationInfo.MyCommand.Path -DefineFunctionsOnly
    }

    if($afterFunctionLoad){
        [void] (& $afterFunctionLoad)
    }

    $functionsToExecute = Get-Command -Name $FunctionName Filter -CommandType Function | Sort-Object -Property {NormalizeStringWithNumber -String $_.Name}

    if(!$functionsToExecute){
        throw "There are no functions available with pattern '$FunctionNameFilter*'"
    }

    $duplicates = CheckMicroFunctionOrderNumberUniqueness -AllFunctions $functionsToExecute

    if($duplicates -ne 'OK'){
        throw "Exception with micro function names: $duplicates"
    }

    $currentFunction = $functionsToExecute[0]
    $initialOutput = $null

    foreach($msp in $MainScriptParams) {
        if($dbhash.ContainsKey($msp)) {
            Update-Property -Object $DataBus -PropertyPath $msp -Value $dbhash.$msp -Force
        }
    }

    if(!$dbhash.ContainsKey('StartFlowUsing')){
        Update-Property -Object $DataBus -PropertyPath StartFlowUsing -Value $null -Force
    }

    if($dataBus.PSObject.Properties.Name -contains 'StartFlowUsing' -and $DataBus.StartFlowUsing){
        if(!(Test-Path -Path $DataBus.StartFlowUsing)) {
            throw "Dump file at '$($DataBus.StartFlowUsing)' does not exist"
        }

        $dump = Import-PSData -PathsOrNames $DataBus.StartFlowUsing -PassThru

        $DataBus = $Dump.DataBus
        $currentFunction = $functionsToExecute | Where-Object {$_.name -eq $Dump.Output.NextFunction}
        $initialOutput = $dump.Output
    }

    try{
        $result = InvokeMicroFunctionOrchestrationLoop -FunctionsToExecute $functionsToExecute -StartingFunction $currentFunction -DataBus $dataBus -PreInvoke $PreInvoke -PostInvoke $PostInvoke -DebugHook $DebugHook -ErrorHook $ErrorHook -SkipHook $SkipHook -MergeResultTo $MergeResultTo -InitialOutput $initialOutput -LoopedSubFlow $loopedSubFlow
        Update-Property -Object $result -PropertyPath DataBus -Value $dataBus
    }
    catch{
        $global:Error.RemoveAt(0)
        $_.exception.message, $_.InvocationInfo.PositionMessage, $_.ScriptStackTrace | ForEach-Object {Write-Error -Message $_}
        if($catchScriptBlock){
            &$catchScriptBlock
        }
    }
    finally{
        if($FinallyScriptBlock){
            &$FinallyScriptBlock
        }
        if($result) {
            $result.AllOutputs += $result
        }
        $result
    }
}

function Set-MicroFunctionDatabusValue {
<#
.SYNOPSIS
    Marks a value for forced overwrite when merged into DataBus.
.DESCRIPTION
    Stamps an object with internal metadata used by merge logic so downstream
    DataBus updates replace existing values instead of merging.
.EXAMPLE
    Set-MicroFunction DatabusValue -Object $newValue
    Marks the object for forced DataBus replacement semantics.
.INPUTS
    System.Object
.OUTPUTS
    None. This function does not emit output.
#>
[cmdletbinding()]
param(
    [Parameter (Mandatory = $true)] [object] $Object
)
    Update-Property -Object $Object -PropertyPath _forceUpdateProperty -Value $true -Force
}
#endregion

New-Alias -Name Compare-ObjectProperty -Value Compare-Property -Force
New-Alias -Name Expand-PSData -Value Expand-Property -Force

Export-ModuleMember -Variable scriptinvocation, astTypes, paramDef_ElementType -Function '*' -Alias Compare-ObjectProperty, Expand-PSData