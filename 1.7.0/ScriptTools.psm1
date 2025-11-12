<#
    Author: Tibor Soós (soos.tibor@hotmail.com)
    Version: 1.7.0 [2025.10.03]
#>

#region Logging
function Initialize-Logging {
[CmdletBinding()]
param(
    [string] $Title,
    [string] $Name,
    [string] $Path,
    # [hashtable[]] $additionalColumns,
    [string[]] $IgnoreCommand = "HandleError",
    [int]    $KeepDays = 60,
    [int]    $ProgressBarSec = 1,
    [int]    $ProgressLogFirst = 60,
    [int]    $ProgressLogMin   = 5,
    [string[]] $IgnoreLocation = ("ScriptTools", "ScriptBlock"),
    [string] $MergeTo,
    [string[]] $EmailNotification,
    [string] $SMTPServer,
    [switch] $BySeconds,
    [string] $DatePart,
    [switch] $SimulateRunbook
)
    if($MergeTo){
        return $MergeTo
    }

    (Get-Variable -Name Error -Scope global -ValueOnly).Clear()

    $cs = @(Get-PSCallStack)
    $scriptinvocation = $cs[1].InvocationInfo

    $version = "0.0.0"
    $releasedate = ""

    $additionalColumns = @(@{Name = "Function"; Rule = {$environmentInvocation.MyCommand.Name}; width = 26})

    if(($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters.Debug) -or ($MergeTo -and $global:logging.$MergeTo._DebugMode)){
        $additionalColumns += @{Name = "Module"; Rule = {$environmentInvocation.mycommand.Modulename}; width = 20}, 
                                @{Name = "Environment"; Rule = {$environmentInvocation.BoundParameters.cmdenvironment}}, 
                                @{Name = "Resource"; Rule = {$environmentInvocation.BoundParameters.resource}; width = 20},
                                @{Name = "ResourceID"; Rule = {$environmentInvocation.BoundParameters.resourceID}; width = 13}
    }

    if(Get-Member -InputObject $scriptinvocation.MyCommand -Name scriptcontents -ErrorAction Ignore){
        $scripttext = $scriptinvocation.MyCommand.scriptcontents
        $versionfound = $scripttext -match "Version\s*:\s*(?<version>\d+\.\d+(\.\d+)*)(\s*\((?<releasedate>\d{4}\.\d{2}\.\d{2})\))?"
        if($versionfound){
            $releasedate = $Matches.releasedate
            $version = $Matches.version
        }
    }
    
    $environment = $host.Name
    $UseOutput = $false

    if($SimulateRunbook){
        $Path = $env:TEMP
        $environment = 'Simulated Runbook'
        $BySeconds = $true
        $UseOutput = $true
    }
    elseif($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation'){
        $Path = $env:TEMP
        $environment = $env:AZUREPS_HOST_ENVIRONMENT
        $BySeconds = $true
        $UseOutput = $true
    }
    elseif($host.name -eq 'Default Host'){
        $Path = $env:TEMP
        $environment = "Hybrid Worker"
        $BySeconds = $true
        $UseOutput = $true
    }
    elseif(!$Path){
        if($scriptinvocation.MyCommand.path){
            $Path = Split-Path $scriptinvocation.MyCommand.path
        }
        else{
            $Path = $env:TEMP
        }

        $Path = Join-Path $Path Logs
    }

    if($scriptinvocation.MyCommand.Name){
        $scriptname = $scriptinvocation.MyCommand.Name
    }
    else{
        $scriptname = "Interactive"
    }

    if($scriptinvocation.MyCommand.path){
        $scriptpath = Split-Path -Path $scriptinvocation.MyCommand.path
    }
    else{
        $scriptpath = "Interactive"
    }

    $columns = @('"DateTime"           ','"Line"  ','"Type"     ')
    if($additionalColumns){
        $columns += $additionalColumns | ForEach-Object {"{0,$(-([math]::max($_.width,$_.name.length)+2))}" -f """$($_.name)"""}
    }
    $columns += '"Message"'

    if(!$Name){
        $LogName = "$($scriptname).log"
    }
    else{
        $LogName = $Name
    }
    
    if(!$global:logging -or $global:logging -isnot [hashtable]){
        $global:logging = @{}
    }

    $logFile = New-LogFile -name $LogName -path $Path -keepdays $KeepDays -logname $LogName -byseconds:$BySeconds -datepart $DatePart

    $cs[1].InvocationInfo.BoundParameters.logname = $logFile.name

    $parentprocess = $null
    $myprocess = Get-CimInstance -ClassName Win32_process -Filter "ProcessID = '$PID'" -Verbose:$false
    if($myprocess.ParentProcessId){
        $parentprocess = Get-CimInstance -ClassName Win32_process -Filter "ProcessID = '$($myprocess.ParentProcessId)'" -Verbose:$false
    }

    $global:logging.$($logFile.Key) = [pscustomobject] @{
            Title = $Title
            ScriptName = $scriptname
            ScriptPath = $scriptpath
            ScriptVersion = "$version $(if($releasedate){"($releasedate)"})"
            RunBy = "$env:USERDOMAIN\$env:USERNAME"
            IsAdministrator = Get-LogIsAdministrator
            Computer = $env:COMPUTERNAME
            LogPath = $logFile.fullname
            LogFolder = $logFile.DirectoryName
            LogStart  = Get-Date
            Environment = $environment
            _IndentOffset   = $cs.count
            _LastLine       = ""
            _WarningsLogged = 0
            _ErrorsLogged   = 0
            _UnhandledErrors = 0
            _VerboseMode    = if($PSBoundParameters.ContainsKey('verbose')){$PSBoundParameters.verbose}else{$false}
            _DebugMode      = $PSBoundParameters.Debug
            _Progress = [PSCustomObject] @{
                    ArrayID = 0
                    Counter = 0
                    Start   = $null
                    BarSec  = $ProgressBarSec
                    BarNext  = $null
                    LogFirst = $ProgressLogFirst
                    LogNext  = $null
                    LogMin   = $ProgressLogMin
                }
            _AdditionalColumns = $additionalColumns
            _IgnoreCommand  = $IgnoreCommand
            _ignoreLocation = $IgnoreLocation
            _email          = $EmailNotification
            _smtpserver     = $SMTPServer
            _baseindent     = 0
            _LogCache       = [System.Collections.Queue] @()
            _MaxCacheSize   = 1000
            _UseOutput      = $UseOutput
            _parentProcess  = $parentprocess
        }

    if($logFile.new){
        Set-Content -Path $logFile.Fullname -Value ($columns -join ",")
    }

    $global:logging.$($logFile.Key) | Format-LogStringList -excludeProperty _* | FormatBorder | New-LogEntry -type Header -logname $logFile.key

    if($scriptinvocation.BoundParameters.count){
        [PSCustomObject][hashtable]$scriptinvocation.BoundParameters | Format-LogStringList -excludeproperty LogName | 
            FormatBorder -title "Bound Parameters:" -indentlevel 1 |
                New-LogEntry -indentlevel 1 -logname $logFile.key
    }

    if($ScriptImplicitParams = Get-Variable -Name ScriptImplicitParams -Scope Global -ErrorAction Ignore -ValueOnly){
        [PSCustomObject] $ScriptImplicitParams | Format-LogStringList | 
            FormatBorder -title "Parameters with defaults:" -indentlevel 1 |
                New-LogEntry -indentlevel 1 -logname $logFile.key
    }

    $logFile.DelayedLogEntries | New-LogEntry -indentlevel 1

    return $logFile.key
}

function GetLogName {
    if($global:logging -and $global:logging -is [hashtable] -and $global:logging.Keys.Count -eq 1){
        $LogName = $global:logging.Keys | Select-Object -First 1 
    }

    $cs = @(Get-PSCallStack | Where-Object {$_.Location -ne '<No file>'})
    $realstack = @($cs | Where-Object {$_.ScriptName -ne $cs[0].ScriptName})
    Set-Variable -Name logcallstack -Value $cs -Scope 1
    Set-Variable -Name logrealdepth -Value $realstack.Count -Scope 1

    if(!$LogName){
        for($i = 1; $i -lt $cs.Length; $i++){
            if(!$LogName -and $cs[$i].InvocationInfo.BoundParameters.ContainsKey('logname')){
                $LogName = $cs[$i].InvocationInfo.BoundParameters.logname            
                break       
            }
        }
    }

    if(!$LogName -and $global:logname){
        $LogName = $global:logname
    }

    $LogName
}

function Write-LogProgress {
[cmdletbinding()]
    param(
        $InputArray,
        [string][Alias('Action')] $Activity,
        [int] $Percent,
        [string] $LogName,
        [int] $ProgressLogFirst
    )

    if(!$inputarray -or !$inputarray.count){
        return
    }

    if($PSBoundParameters.ContainsKey('logname') -and !$LogName){
        return
    }

    $LogName = GetLogName

    if(!$LogName -or !$global:logging.ContainsKey($LogName)){
        $LogName = $null
        if($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation'){
            Write-Error "Logname '$LogName' is not valid"
            $global:Error.RemoveAt(0)
        }
        else{
            Write-Host "Logname '$LogName' is not valid" -ForegroundColor Red
        }
        return
    }

    if($ProgressLogFirst -eq 0){
        $ProgressLogFirst = $global:logging.$LogName._Progress.LogFirst
    }

    if($inputarray.gethashcode() -ne $global:logging.$LogName._Progress.ArrayID){
        $global:logging.$LogName._Progress.ArrayID = $inputarray.gethashcode()
        $global:logging.$LogName._Progress.Start   = get-date
        $global:logging.$LogName._Progress.BarNext = get-date
        $global:logging.$LogName._Progress.Counter = 0
        $global:logging.$LogName._Progress.LogNext = (get-date).AddSeconds($ProgressLogFirst)
    }

    if((Get-Date) -ge $global:logging.$LogName._Progress.BarNext -and ($global:logging.$LogName._VerboseMode -or $PSBoundParameters.verbose)){
        if(!$PSBoundParameters.ContainsKey('percent')){
            $percent = $global:logging.$LogName._Progress.Counter / $inputarray.count * 100
        }

        if($percent -gt 100){
            $percent = 100
        }

        if($global:logging.$LogName._Progress.Counter -eq 0){
            $timeleft = [int]::MaxValue
        }
        else{
            $timeleft = ((Get-Date) - $global:logging.$LogName._Progress.Start).totalseconds * ($inputarray.Count - $global:logging.$LogName._Progress.Counter) / $global:logging.$LogName._Progress.Counter
        }

        $done = "{0,$("$($inputarray.Count)".Length)}" -f $global:logging.$LogName._Progress.Counter
        $left = "{0,$("$($inputarray.Count)".Length)}" -f ($inputarray.Count - $global:logging.$LogName._Progress.Counter)
        Write-Progress -Activity $Activity -Status "All: $($inputarray.Count) Done: $done Left: $left" -PercentComplete $percent -SecondsRemaining $timeleft
        $global:logging.$LogName._Progress.BarNext = (get-date).AddSeconds($global:logging.$LogName._Progress.BarSec)
    }

    if((Get-Date) -ge $global:logging.$LogName._Progress.LogNext){
        if($global:logging.$LogName._Progress.Counter -eq 0){
            $timeleft = [int]::MaxValue
        }
        else{
            $timeleft = [int] (((Get-Date) - $global:logging.$LogName._Progress.Start).totalseconds * ($inputarray.Count - $global:logging.$LogName._Progress.Counter) / $global:logging.$LogName._Progress.Counter)
        }

        $timeleft = [timespan]::FromSeconds($timeleft).tostring()

        $done = "{0,$("$($inputarray.Count)".Length)}" -f $global:logging.$LogName._Progress.Counter
        $left = "{0,$("$($inputarray.Count)".Length)}" -f ($inputarray.Count - $global:logging.$LogName._Progress.Counter)
        
        New-LogEntry -message "All: $($inputarray.Count) Done: $done Left: $left Estimated time left: $timeleft" -type Progress

        $global:logging.$LogName._Progress.LogNext = (get-date).AddMinutes($global:logging.$LogName._Progress.LogMin)
    }

    $global:logging.$LogName._Progress.Counter++
}

function New-LogFile {
param(
    [string] $Name,
    [string] $Path,
    [int]    $KeepDays = 60,
    [switch] $BySeconds,
    [switch] $Overwrite,
    [string] $DatePart
)
    if(!$Path){
        $LogName = GetLogName

        $Path = $global:logging.$LogName.LogFolder
    }
    
    if(!(Test-Path -Path $Path -PathType Container)){
        [void] (New-Item -Path $Path -ItemType Directory -ErrorAction Stop)
    }
    
    if($BySeconds){
        $DatePart = Get-Date -Format 'yyyyMMddHHmmss'
    }
    elseif(!$DatePart){
        $DatePart = Get-Date -Format 'yyyyMMdd'
    }

    $filename = $Name -replace "(?=\.(?!.*?\.))", "-$DatePart"
    $searchname = $Name -replace "(?=\.(?!.*?\.))", "-*"

    if($PSBoundParameters.ContainsKey('datepart')){
        $key = $filename
    }
    else{
        $key = $Name
    }

    $delayedLogEntries = @()
    if($KeepDays){
        Get-ChildItem -Path $Path -Filter $searchname | Where-Object {((get-date) - $_.LastWriteTime).totaldays -gt $KeepDays} |
            ForEach-Object {
                if(!$LogName -or !$global.logging.$LogName){
                    $delayedLogEntries += "Removing obsolete file: '$($_.FullName)'"
                }
                else{
                    New-LogEntry -message "Removing obsolete file: '$($_.FullName)'" -indentlevel 1
                }
                Remove-Item -Path $_.FullName
            }
    }

    if($Overwrite -or (!(Test-Path -Path (Join-Path -Path $Path -ChildPath $filename)))){
        $file = New-Item -Path $Path -Name $filename -ItemType file -Force:$Overwrite | Add-Member -MemberType NoteProperty -Name New -Value $true -PassThru 
    }
    else{
        $file = Get-Item -Path (Join-Path -Path $Path -ChildPath $filename) | Add-Member -MemberType NoteProperty -Name New -Value $false -PassThru
    }

    Add-Member -InputObject $file -MemberType NoteProperty -Name Key -Value $key -PassThru | Add-Member -MemberType NoteProperty -Name DelayedLogEntries -Value $delayedLogEntries -PassThru
}

function FormatBorder {
param(
    [Parameter(ValueFromPipeline=$true)][string[]]$Strings,
    [string] $Title,
    [int] $IndentLevel
)
begin{
    $lines = @()
    if($Title){
        $lines += $Title
    }
}
process{
    foreach($string in $Strings){
        $lines += " " * $IndentLevel * 4 + $string
    }
}
end{
    $longest = $lines | Sort-Object -Property Length -Descending | Select-Object -First 1 -ExpandProperty Length
    "#" * ($longest + 4)
    foreach($line in $lines){
        "# $($line.padright($longest)) #"
    }
    "#" * ($longest + 4)
}
}

function Format-LogStringList {
param(
    [Parameter(ValueFromPipeline = $true)]$Object,
    [string[]] $Property = "*",
    [string[]] $ExcludeProperty = $null,
    [switch] $Divide,
    [switch] $HideNulls,
    [int] $IndentLevel,
    [switch] $Sort,
    $Sortby,
    [switch] $Bordered,
    [string[]] $HideProperty
)
begin {
    $lines = @()
}
process{
    
    $selecttedprops = @()
    $longest = 0

    foreach($p in $Object.psobject.Properties){
        if($ExcludeProperty | Where-Object {$p.name -like $_} | Select-Object -First 1){
            continue
        }
        if(($Property | Where-Object {$p.name -like $_} | Select-Object -First 1) -and (!$HideNulls -or $p.value)){
            $selecttedprops += $p

            if($p.name.length -gt $longest){
                $longest = $p.name.length + 1
            }
        }
    }

    if($Object -is [string]){
        $lines += " " * $IndentLevel * 4 + $Object
    }
    elseif($selecttedprops){
        if($Sort){
            if(!$Sortby){
                $Sortproperty = "name"
            }
            else{
                $Sortproperty = $Sortby
            }
        }
        else{
            $Sortproperty = "dummy"
        }

        foreach($sp in ($selecttedprops | Sort-Object -Property $Sortproperty -Debug:$false)){
            if($sp.value -as [string] -and ($HideProperty | Where-Object {$sp.name -like $_})){
                $Value = '*' * ([string]$sp.value).length
            }
            else{
                $Value = $sp.value
            }
            $lines += " " * $IndentLevel * 4 + $sp.name.padright($longest) + ": " + $Value
        }
    }
    if($Divide){
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

function Format-LogStringTable {
param(
    [Parameter(ValueFromPipeline = $true)]$Object,
    [object[]] $Property = "*",
    [string[]] $ExcludeProperty = $null,
    [switch] $Bordered
)
    $ftsplatting = @{}

    if($Property){
        $ftsplatting.Property = $Property
    }

    if($ExcludeProperty){
        $ftsplatting.ExcludeProperty = $ExcludeProperty
    }

    $lines = ($input | Select-Object @ftsplatting | Format-Table -AutoSize | Out-String) -split "\r\n" | 
        Where-Object {$_ -and $_.trim()}

    if($Bordered){
        $lines | FormatBorder
    }
    else{
        $lines
    }
}

function Write-LogUnhandeldErrors {
    $scripterror = Get-Variable -Name Error -Scope Global -ValueOnly

    if($scripterror){
        $err2 = $scripterror.clone()
        $err2.reverse()
        $scripterror.clear()
        foreach($e in $err2){
            New-LogEntry -message "$($e.ScriptStackTrace): $($e.Exception.Message)" -type Unhandled
            $global:logging.$LogName._UnhandledErrors++
        }
    }
}

function Add-LogTextWithRetry {
[cmdletbinding()]
param(
    [string] $Path,
    [Parameter(ValueFromPipeline = $true)][string[]] $Text,
    [ValidateScript( { $_ -is [System.Text.Encoding] })] $Encoding = [System.Text.Encoding]::UTF8,
    [int] $Timeout = 1,
    [switch] $Force
)   
begin{
    $retry = $true
    $start = Get-Date
    $h = $null
    do {
        try {
            $locked = $false
            $h = [io.file]::AppendText($Path)
        } 
        catch {
            $global:Error.Clear()
            if ($_.Exception.InnerException -and $_.Exception.InnerException.HResult -eq -2147024864) {
                Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 500)
                $locked = $true
            } 
            else {
                $retry = $false
                $Force = $true
            }
        }
        if (((Get-Date) - $start).totalseconds -gt $Timeout) {
            $retry = $false
        }
    }while ((!$h -or !$h.BaseStream) -and $retry)

    if ($h -and $h.BaseStream -and $global:logging.$LogName._LogCache.count) {
        while ($global:logging.$LogName._LogCache.Count) {
            $cline = $global:logging.$LogName._LogCache.dequeue()
            $h.Writeline($cline)
        }
    }
}
process{
    foreach($line in $Text){
        if (!$h -or !$h.BaseStream) {            
            if ($Force -or !$locked) {
                throw "LogAppendText error"
            } 
            else {
                $global:logging.$LogName._LogCache.EnQueue($line)
                if($global:logging.$LogName._LogCache.Count -gt $global:logging.$LogName._MaxCacheSize){
                    $tempfile = Join-Path -Path (Split-Path $Path) -ChildPath "_Templog-$(get-date -Format 'yyyy-MM-dd-HH-mm-ss-fffffff').log" 
                    $global:logging.$LogName._LogCache | Set-Content -Path $tempfile -Encoding ($Encoding.EncodingName -replace 'US-')
                    $global:logging.$LogName._LogCache.Clear()
                }
            }
        }
        else{
            $h.Writeline($line)
        }
    }
}
end{
    if($h){
        $h.Close()
    }
}
}

function New-LogEntry {
[cmdletbinding()]
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
begin{
    $LogName = GetLogName

    $relativelevel = 0

    $localverbose = $null

    for($i = 1; $i -lt $logcallstack.Length; $i++){
        if(!$relativelevel -and $logcallstack[$i].ScriptName -ne $logcallstack[0].ScriptName -and (!$LogName -or $logcallstack[$i].Command -notin $global:logging.$LogName._IgnoreCommand)){
            $relativelevel = $i
        }

        if($null -eq $localverbose -and ($VerbosePreference -notin 'SilentlyContinue', 'Ignore' -or $logcallstack[$i].InvocationInfo.BoundParameters.ContainsKey('Verbose'))){
            $localverbose = $logcallstack[$i].InvocationInfo.BoundParameters.Verbose
        }
    }

    if(!$LogName){
        $LogName = $null
        if($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation' -or $host.name -eq 'Default Host'){
            Write-Error "Logname '$LogName' is not valid"
            $global:Error.RemoveAt(0)
        }
        else{
            Write-Host "Logname '$LogName' is not valid" -ForegroundColor Red
        }
    }

    if($null -eq $localverbose){
        $localverbose = $global:logging.$LogName._VerboseMode
    }

    $environmentInvocation = $logcallstack | Where-Object {$_.Location -notmatch ($global:logging.$LogName._IgnoreLocation -join "|") -and $_.command -notmatch ($global:logging.$LogName._IgnoreCommand -join "|")} | Select-Object -First 1 -ExpandProperty InvocationInfo

    $baseindent = [math]::Max($logrealdepth - 1, 0)

    if($IndentLevel){
        $global:logging.$LogName._BaseIndent = $IndentLevel
    }
    else{
        $global:logging.$LogName._BaseIndent = $baseindent
    }

    if(!$UseAbsoluteIndent){
        $IndentLevel = $IndentLevel + $baseindent
    }

    $linenumber = $logcallstack[$relativelevel].ScriptLineNumber
    
    switch($Type){
        'Info'           {$param = @{ForegroundColor = "Gray"}}
        'Highlight'      {$param = @{ForegroundColor = "Green"}}
        'Header'         {$param = @{ForegroundColor = "Green"}}
        'Debug'          {$param = @{ForegroundColor = "Cyan"; BackgroundColor = 'DarkGray'}}
        'Warning'        {$param = @{ForegroundColor = "Yellow"; BackgroundColor = 'DarkGray'}; $global:logging.$LogName._WarningsLogged++}
        'Error'          {$param = @{ForegroundColor = "Red"}; $global:logging.$LogName._ErrorsLogged++}
        'Negative'       {$param = @{ForegroundColor = "Red"}}
        'Exit'           {$param = @{ForegroundColor = "Green"}}
        'Terminate'      {$param = @{ForegroundColor = "Red"; BackgroundColor = 'Black'}; $global:logging.$LogName._ErrorsLogged++}
        'Unhandled'      {$param = @{ForegroundColor = "Red"; BackgroundColor = 'DarkGray'}; $global:logging.$LogName._ErrorsLogged++}
        'Progress'       {$param = @{ForegroundColor = "Magenta"}}
    }

    if($Type -ne 'Unhandled'){
        Write-LogUnhandeldErrors
    }
}
process{
    if($LogName){
        if($global:logging.$LogName._LastLine){
            $line = " $Message"
        }
        else{
            $line = "[$(Get-Date -Format 'yyyy.MM.dd HH:mm:ss')],[$(([string]$linenumber).PadLeft(6))],[$($Type.toupper().padright(9))]"
            if($global:logging.$LogName._additionalColumns){
                foreach($c in $global:logging.$LogName._additionalColumns){
                    $line += ",[{0,$(-([math]::max($c.width,$c.name.length)))}]" -f ($c.Rule.GetNewClosure().invoke()[0])
                }
            }
            $line += ", »$(" " *$IndentLevel * 4)$Message"
        }

        if($NoNewLine -or $global:logging.$LogName._LastLine){
            $global:logging.$LogName._LastLine += $line
        }

        if($LogName -and !$NoNewLine -and !$DisplayOnly){
            if($global:logging.$LogName._LastLine){
                #Add-Content -path $global:logging.$LogName.LogPath -Value $global:logging.$LogName._LastLine
                Add-LogTextWithRetry -path $global:logging.$LogName.LogPath -text $global:logging.$LogName._LastLine
                $global:logging.$LogName._LastLine = ""
            }
            else{
                #Add-Content -path $global:logging.$LogName.LogPath -Value $line
                Add-LogTextWithRetry -path $global:logging.$LogName.LogPath -text $line
            }
        }
    }

    if($DisplayOnly -or $localverbose -or $Type -in 'Debug', 'Error', 'Terminate', 'Unhandled', 'Negative', 'Warning'){
        if($global:logging.$LogName._UseOutput){
            if($Type -in 'Error', 'Terminate', 'Unhandled'){
                Write-Error $line
                $global:Error.RemoveAt(0)
            }
            elseif($Type -eq 'Warning'){
                Write-Warning $line
            }
            elseif($Type -match '^(Progress|Highlight)$' -and @($logcallstack | Where-Object {$_.ScriptName -ne $logcallstack[0].ScriptName}).Count -le 1){
                Write-Output $line
            }
        }
        else{
            Write-Host -Object $line @param -NoNewline:$NoNewLine
        }
    }
}
end{
    if($Type -in 'Exit', 'Terminate'){
        if($LogName){
            
            New-LogFooter -logname $LogName

            if($null -eq $ExitCode -or $ExitCode -isnot [int]){
                if($global:logging.$LogName._ErrorsLogged){
                    $ExitCode = 1
                }
                elseif($global:logging.$LogName._WarningsLogged){
                    $ExitCode = 2
                }
                else{
                    $ExitCode = 0
                }
            }

            if(!$IgnoreLog){
                if($global:logging.$LogName._email -and $global:logging.$LogName._smtpserver){
                    $contents = ""
                    foreach($log in $global:logging.Keys){
                        if($global:logging.$log._ErrorsLogged){
                            $contents += (Get-Content $global:logging.$log.LogPath -Encoding utf8) -join "`r`n"
                            $contents += "`r`n" + "`r`n" + ("-" * 200) + "`r`n"
                            $global:logging.$log._ErrorsLogged = 0
                        }
                    }

                    if($contents){
                        Send-MailMessage  -SmtpServer $global:logging.$LogName._smtpserver -To $global:logging.$LogName._email -Subject "PAMaaS Error Logs - $(get-date -Format 'yyyy.MM.dd HH.mm.ss')" -From "$($global:logging.$LogName.ScriptName)@clearstream.com" -Body $contents -Encoding utf8
                    }
                }
            }
            else{
                Remove-Item -Path $global:logging.$LogName.LogPath
            }

            if($global:logging.$LogName._UseOutput){
                get-content -Path $global:logging.$LogName.LogPath -encoding utf8

                if($logrealdepth -lt 1 -and ($global:logging.$LogName._parentprocess.Name -in 'exporer.exe', 'WindowsTerminal.exe' -or $Host.Name -match 'ISE|Visual Studio')){
                    throw "$($Type)ing session with exit code $ExitCode"
                }
                else{
                    exit $ExitCode
                }
            }
            elseif($global:logging.$LogName.ScriptName -ne 'Interactive'){
                if($global:logging.$LogName._parentprocess.Name -in 'exporer.exe', 'WindowsTerminal.exe' -or $Host.Name -match 'ISE|Visual Studio'){
                    if($logrealdepth -lt 1){
                        throw "$($Type)ing session with exit code $ExitCode"
                    }
                    else{
                        exit $ExitCode
                    }
                }
                else{
                    [environment]::Exit($ExitCode)
                }
            }
        }

        if($logcallstack.count -le 3){
            return
        }
        else{
            throw "Interactive exit: $ExitCode"
        }
    }
}
}

function New-LogFooter {
param([string]$LogName)

    if($PSBoundParameters.ContainsKey('logname') -and !$LogName){
        return
    }

    $LogName = GetLogName

    if(!$LogName -or !$global:logging.ContainsKey($LogName)){
        $LogName = $null
        if($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation' -or $host.name -eq 'Default Host'){
            Write-Error "Logname '$LogName' is not valid"
            $global:Error.RemoveAt(0)
        }
        else{
            Write-Host "Logname '$LogName' is not valid" -ForegroundColor Red
        }
    }

    $seconds = [int] ((Get-Date) - $global:logging.$LogName.LogStart).totalseconds

    $footer =   "LogName       : $LogName",
                "Runtime       : $([timespan]::FromSeconds($seconds).tostring())",
                "ErrorsLogged  : $($global:logging.$LogName._ErrorsLogged)",
                "WarningsLogged: $($global:logging.$LogName._WarningsLogged)",
                "ParentProcess : $($global:logging.$LogName._parentprocess.name)"
    $footer | FormatBorder | New-LogEntry -type Header
}

function Search-LogEntries {
param(
    [string[]] $LogNames = $global:logging.Keys,
    [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)] [string[]] $LogPath,
    [scriptblock] $FilterScript,
    [switch] $AllDates,
    [AllowNull()] [string[]] $SortBy,
    [switch] $Descending
)
begin{
    if($LogPath){
        if($PSBoundParameters.ContainsKey('lognames')){
            $LogPath = Get-ChildItem -Path $LogPath -Include $LogNames -Recurse | Select-Object -ExpandProperty fullname
        }
        else{
            $LogPath = Get-ChildItem -Path $LogPath | Select-Object -ExpandProperty fullname
        }
    }
    elseif($LogNames){
        foreach($ln in $LogNames){
            $LogPath += $global:logging.$ln.LogPath
        }
    }
}
process{
    foreach($lp in $LogPath){
        if($AllDates){
            $lp = $lp -replace "-\d{8,}(?=\.[^\.]+$)", '*'
        }

        if($lp -notmatch "\.log"){
            $lp += "\*"
        }

        if(!$FilterScript){
             $FilterScript = {$_.Line -match '^\[\s*\d+\]$'}
        }
        else{
            $filterstring = [string] $FilterScript
            $filterstring += ' -and $_.Line -match ''^\[\s*\d+\]$'''
            $FilterScript = [scriptblock]::Create($filterstring)
        }

        if($SortBy){
            Get-Item -Path $lp -PipelineVariable p -ErrorAction Ignore | ForEach-Object {$_.fullname} | Import-Csv -Encoding Default | Where-Object -FilterScript $FilterScript | Sort-Object -Property $SortBy -Descending:$Descending | select-object -Property @{n="LogName"; e={$p.name}}, * | Format-LogStringTable
        }
        else{
            Get-Item -Path $lp -PipelineVariable p -ErrorAction Ignore | ForEach-Object {$_.fullname} | Import-Csv -Encoding Default | Where-Object -FilterScript $FilterScript | select-object -Property @{n="LogName"; e={$p.name}}, * | Format-LogStringTable
        }
    }
}
}

function Get-LogIsAdministrator {
    $u = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.principal.windowsprincipal -ArgumentList $u
    $IsAdministrator = !!(($principal.Identity.Groups | Select-Object -ExpandProperty value) -match "S-1-5-32-544")
    $IsAdministrator
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
            ResolveDynamicData -PSDatahive $PSDatahive.$key -dontexpand:$dontexpand
        }
        elseif($PSDatahive.$key -is [System.Object[]]){
            for($i = 0; $i -lt $PSDatahive.$key.count; $i++){
                if($PSDatahive.$key[$i] -is [System.Collections.IDictionary]){
                    ResolveDynamicData -PSDatahive $PSDatahive.$key[$i] -dontexpand:$dontexpand
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
        elseif($PSDatahive.$key -is [scriptblock] -and ($PSDatahive.Keys -notcontains 'Condition' -or $PSDatahive.Condition)){
            [ref] $errors = $null
            $tokens = [System.Management.Automation.PSParser]::Tokenize($PSDatahive.$key, $errors)
            $skip = $dontexpand

            if(!$skip){
                foreach($token in $tokens){
                    if($token.type -eq 'GroupStart'){                        
                        continue
                    }

                    if($token.Type -eq 'Comment' -and $token.Content -match "DontExpand"){
                        if($token.Content -match "DontExpandAll"){
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

                if($errorhappened -or $errorcount -gt $error.Count){
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

    foreach($h in $hive.Getenumerator()){
        if($h.key -match '^Condition|^ConfigAction'){
            continue
        }
        elseif($h.value -isnot [System.Collections.IDictionary]){
            $target.($h.key) = $h.value
        }
        elseif($target.Keys -notcontains $h.key){
            $configActions = @($h.value.keys) -match '^ConfigAction'
            foreach($ca in $configActions){
                $h.value.remove($ca)
            }
                
            $target.($h.key) = $h.value
        }
        else{
            try{
                MergeHives -hive $h.value -target $target.($h.key)
            }
            catch{
            }
        }
    }
}

function Import-PSData {
[cmdletbinding()]
param(
    [string[]]$PathsOrNames,
    [Parameter(Mandatory = $false)][System.Collections.IDictionary] $PSData,
    [switch] $PassThru
)    

    $initiatePSConfig = $false
    if($null -eq $PSData){
        $PSData = @{}

        if(!(Get-Variable -Name PSConfig -Scope Global -ErrorAction Ignore)){
            $initiatePSConfig = $true
        }
    }

    $scriptinvocation = (Get-PSCallStack)[-2].InvocationInfo

    if($scriptinvocation.mycommand.path){
        $basepath = $scriptinvocation.mycommand.path
    }
    elseif($scriptinvocation.MyCommand.Module -and $scriptinvocation.MyCommand.Module.Path){
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

    foreach($Path in $PathsOrNames){
        if($Path -notlike "*.data.ps1"){
            throw "Name of the PS data file must end with '.data.ps1'"
        }

        if($Path -notmatch "^\w+:|^\."){
            $Path = Join-Path (split-path $scriptinvocation.mycommand.path) "\Config\$Path"
        }

        if(!(Test-Path -Path $Path)){
            Write-Error "No PS data file was found at '$Path'"
            continue
        }

        $tokens = [System.Management.Automation.Language.Token[]]::new(1)
        $errors = [System.Management.Automation.Language.ParseError[]]::new(1)

        $realPath = Resolve-Path -Path $Path | Select-Object -ExpandProperty ProviderPath
        $AST = [System.Management.Automation.Language.Parser]::ParseFile(
                    $realPath,
                    [ref] $tokens,
                    [ref] $errors
                )
        
        if($errors){
            throw "There are errors in PS data file '$Path'"
        }

        $topLevelLayer = $AST.Find({$true}, $false)

        $topLevelExtentText = Get-Property -Object $topLevelLayer -PropertyPath "[0].EndBlock.Extent.Text" -ValueOnly

        if(!$topLevelExtentText -or $topLevelExtentText.trim() -notmatch "^(\[ordered\]\s*)?@\{"){
            throw "PS data file '$Path' must contain a single hash literal"
        }

        $allCommands = @($AST.FindAll({$args[0] -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -or 
                                        $args[0] -is [System.Management.Automation.Language.CommandAst] -or 
                                        $args[0] -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -or 
                                        $args[0] -is [System.Management.Automation.Language.CommandExpressionAst]},$true))

        foreach($command in $allCommands){
            Update-Property -Object $command.Parent -PropertyPath Children -Value $command
        }

        $errors = $false

        for($i = 1; $i -lt $allCommands.count; $i++){
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

    if($initiatePSConfig){
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

    if($Name){
        if($Name -match "\W" -and $Name -notmatch "^('|"").*\1$"){
            $Name = "'$Name'"
        }

        if($Compress){
            $open = "$Name="
        }
        else{
            $open = "$Name = "
        }
    }
    else{
        $open = ""
    }

    if($null -eq $Object){
        $fullType = "NULL"
    }
    else{
        $fullType = $Object.gettype().fullname
    }

    if($fullType -match "\[\]$" -or $Object -is [System.Collections.ArrayList]){
        if($fullType -match "^System\.Object"){
            $open += "@("
            $close = ")"
        }
        else{
            $open += "[$($fullType)] @("
            $close = ")"
        }

        if($Compress){
            $joinchar = ","
        }
        else{
            $joinchar = ", "
        }

        $multiline = $false
        $strelements = @()
        foreach($elem in $Object){
            $strelem = ConvertTo-PSData -Object $elem -Compress:$Compress

            if($elem -is [System.Object[]]){
                $strelem = "," + $strelem
            }

            $strelements += $strelem
            if(!$multiline -and $strelem -match '\n'){
                $multiline = $true
            }
        }

        if(!$Compress -and $multiline){
            $joinchar += "`r`n"
            $strelements = @($open) +
                            (($strelements | &{process{
                                $parts = $_ -split "\r\n"
                                ($parts | &{process{" " * 4 + $_}}) -join "`r`n"
                            }}) -join $joinchar) +
                            $close
            $strelements | &{process{
                            $parts = $_ -split "`r`n"
                            ($parts | &{process{" " * $IndentLevel * 4 + $_}}) -join "`r`n"
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
        switch ($fullType){
            "NULL" {
                        if($Compress){
                            $open + '$null'
                        }
                        else{            
                            " " * $IndentLevel * 4 + $open + '$null'
                        }
                        break
                    }

            "System.Collections.Hashtable" {
                                     $open += "@{"

                                     if($Compress){
                                        $out = @($open)
                                     }
                                     else{
                                        $out = @(" " * $IndentLevel * 4 + $open)
                                     }

                                     foreach($key in $Object.keys){
                                        $out += ConvertTo-PSData -Object $Object.$key -IndentLevel ($IndentLevel + 1) -Name $key -Compress:$Compress
                                     }

                                     if($Compress){
                                        "$($out[0])" + ($out[1..($out.count -1)] -join ";") + "}"
                                     }
                                     else{
                                         $out += " " * $IndentLevel * 4 + "}"
                                         $out -join "`r`n"
                                     }
                                     break
                                }

            "System.Collections.Specialized.OrderedDictionary" {
                                     if($Compress){
                                        $open += "[ordered]@{"
                                        $out = @($open)
                                     }
                                     else{
                                        $open += "[ordered] @{"
                                        $out = @(" " * $IndentLevel * 4 + $open)
                                     }

                                     foreach($key in $Object.keys){
                                        $out += ConvertTo-PSData -Object $Object.$key -IndentLevel ($IndentLevel + 1) -Name $key -Compress:$Compress
                                     }

                                     if($Compress){
                                        "$($out[0])" + ($out[1..($out.count -1)] -join ";") + "}"
                                     }
                                     else{
                                         $out += " " * $IndentLevel * 4 + "}"
                                         $out -join "`r`n"
                                     }
                                     break
                                }

            "System.String" {
                                    if($Compress){
                                        $open + "'$Object'"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "'$Object'"
                                    }
                                    break
                                }

            "System.Char" {
                                    if($Compress){
                                        $open + "[char]'$Object'"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[char] '$Object'"
                                    }
                                    break
                                }

            "System.Version" {
                                    if($Compress){
                                        $open + "[version]'$Object'"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[version] '$Object'"
                                    }
                                    break
                                }

            "System.Management.Automation.ScriptBlock" {
                                    if($Compress){
                                        $open + "{$Object}"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "{$Object}"
                                    }
                                    break
                                }

            "System.DateTime" {
                                    if($Compress){
                                        $open + "[DateTime]'$(get-date -Date $Object -Format 'yyyy.MM.dd HH:mm:ss')'"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[DateTime] '$(get-date -Date $Object -Format 'yyyy.MM.dd HH:mm:ss')'"
                                    }
                                    break
                                }

            "System.TimeSpan" {
                                    if($Compress){
                                        $open + "[TimeSpan]'$Object'"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[TimeSpan] '$Object'"
                                    }
                                    break
                                }

            "System.Byte" {
                                    if($Compress){
                                        $open + "[byte]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[byte] $Object"
                                    }
                                    break
                                }

            "System.Int16" {
                                    if($Compress){
                                        $open + "[System.Int16]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.Int16] $Object"
                                    }
                                    break
                                }

            "System.Int32" {
                                    if($Compress){
                                        $open + "$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "$Object"
                                    }
                                    break
                                }

            "System.Int64" {
                                    if($Compress){
                                        $open + "[System.Int64]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.Int64] $Object"
                                    }
                                    break
                                }

            "System.UInt16" {
                                    if($Compress){
                                        $open + "[System.UInt16]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.UInt16] $Object"
                                    }
                                    break
                                }

            "System.UInt32" {
                                    if($Compress){
                                        $open + "[System.UInt32]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.UInt32] $Object"
                                    }
                                    break
                                }

            "System.UInt64" {
                                    if($Compress){
                                        $open + "[System.UInt64]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.UInt64] $Object"
                                    }
                                    break
                                }

            "System.Decimal" {
                                    if($Compress){
                                        $open + "[System.Decimal]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.Decimal] $Object"
                                    }
                                    break
                                }

            "System.Double" {
                                    if($Compress){
                                        $open + "[System.Double]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.Double] $Object"
                                    }
                                    break
                                }

            "System.Single" {
                                    if($Compress){
                                        $open + "[System.Single]$Object"
                                    }
                                    else{
                                        " " * $IndentLevel * 4 + $open + "[System.Single] $Object"
                                    }
                                    break
                                }

            "System.Management.Automation.PSCustomObject" {

                                     if($Compress){
                                        $open += "[PSCustomObject]@{"
                                        $out = @($open)
                                     }
                                     else{
                                        $open += "[PSCustomObject] @{"
                                        $out = @(" " * $IndentLevel * 4 + $open)
                                     }

                                     foreach($prop in $Object.psobject.properties.name){
                                        $out += ConvertTo-PSData -Object $Object.$prop -IndentLevel ($IndentLevel + 1) -Name $prop -Compress:$Compress
                                     }

                                     if($Compress){
                                        "$($out[0])" + ($out[1..($out.count -1)] -join ";") + "}"
                                     }
                                     else{
                                         $out += " " * $IndentLevel * 4 + "}"
                                         $out -join "`r`n"
                                     }
                                     break
                                }

            "System.Boolean" {
                                    if($Object -eq $true){
                                        if($Compress){
                                            $open + '$true'
                                        }
                                        else{
                                            " " * $IndentLevel * 4 + $open + '$true'
                                        }
                                    }
                                    else{
                                        if($Compress){
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

                if(!$Name){
                    $nameInMessage = Get-Variable -Name Name -ValueOnly -Scope 1 -ErrorAction Ignore
                }

                throw "Couldn't convert datatype at '$nameInMessage' : '$($Object.gettype().fullname)' - $Object"
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
    Set-Content -Value $PSDataString -Path $Path -Encoding Default
}

function ConvertFrom-PSData {
param(
    [Parameter(ValueFromPipeLine = $true)] [string] $PSDataString
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
    [Parameter(ValueFromPipelineByPropertyName = $true)] [type]   $Type,
    [Parameter(ValueFromPipelineByPropertyName = $true)] [string[]] $ParameterSetName ="Default",
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
    $paramDictionary = new-object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
    $position = $StartPosition
}
process{
    if($null -eq $Condition -or (&$Condition)){
        $attributeCollection = new-object -TypeName System.Collections.ObjectModel.Collection[Attribute]

        foreach($psn in $ParameterSetName){
            $attribute = new-object -TypeName System.Management.Automation.ParameterAttribute
            $attribute.ParameterSetName = $psn
            if($PSBoundParameters.ContainsKey('startposition')){
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

        if($ValidationSet){
            $vsa = New-Object -TypeName System.Management.Automation.ValidateSetAttribute -ArgumentList (&$ValidationSet)
            $attribute.HelpMessage = "Possible values: $((&$ValidationSet) -join ', ')"
            $attributeCollection.Add($vsa)           
        }

        if($Aliases){
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
        $selectstringsplatting = @{}
        if($CaseSensitive){
            $selectstringsplatting.CaseSensitive = $true
        }

        $Sortparam = "Path", "LineNumber"
    }
    elseif($elementType -ne 'Comment'){
        $notpart = ""

        if($CaseSensitive){
            $Pattern = "(?-i)$Pattern"
        }

        if($IncludeAll -and $Global:astTypes.$elementType.NotPart){
            $notpart = "-and (!`$args[0].parent -or `$args[0].parent.gettype().fullname -ne ""System.Management.Automation.Language.$($Global:astTypes.$elementType.NotPart)Ast"")"
        }

        if($Global:astTypes.$elementType.ContainsKey('TypeOverride')){
            $querystr = "`$args[0].gettype().fullname -eq ""System.Management.Automation.Language.$($Global:astTypes.$elementType.TypeOverride)Ast"" $notpart -and 
                            (Get-Property -Object `$args[0] -PropertyPath $($Global:astTypes.$elementType.PropName -join ', ')).Value -match '$Pattern'"
        }
        else{
            $querystr = "`$args[0].gettype().fullname -eq ""System.Management.Automation.Language.$($elementType)Ast"" $notpart -and 
                            (Get-Property -Object `$args[0] -PropertyPath $($Global:astTypes.$elementType.PropName -join ', ')).Value -match '$Pattern'"
        }

        if($Global:astTypes.$elementType.containskey('AdditionalCriteria')){
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

    foreach($psf in $selectedFiles){
        if($elementType -ne 'String'){
            $tokens = [System.Management.Automation.Language.Token[]]::new(1)
            $errors = [System.Management.Automation.Language.ParseError[]]::new(1)

            $AST = [System.Management.Automation.Language.Parser]::ParseFile(
                $psf.fullname,
                [ref] $tokens,
                [ref] $errors
            )

            if($elementType -eq 'Comment'){
                $selectstringsplatting = @{}

                if($CaseSensitive){
                    $selectstringsplatting.CaseSensitive = $true
                }

                $Sortparam = "Path", "LineNumber"

                $tokens | &{process{
                    if($_.kind -eq 'Comment' -and (
                            $res = $_.Extent.Text -split "\r?\n" | Select-String -Pattern $Pattern @selectstringsplatting -Encoding default
                        )){
                            foreach($r in $res){
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
                foreach($ta in $toAdd){
                    $expression = if($ta.gettype().fullname -match 'VariableExpression'){
                                        if($ta.parent.GetType().fullname -notmatch 'AssignmentStatement'){
                                            ($ast.Extent.Text -split "\r?\n")[$ta.extent.StartLineNumber - 1].trim()
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

                    $expression = $expression -split '\r?\n'

                    $currentMaxLines = $MaxLines

                    for($i = 0; $i -lt $expression.count -and $currentMaxLines -gt 0; $i++){
                        $currentMaxLines--

                        $return = [pscustomobject]@{
                                        Path = $ta.extent.File
                                        LastWriteTime = $psf.LastWriteTime
                                        LineNumber = if($i -eq 0){$ta.extent.StartLineNumber.toString().padleft(10,'-')}else{" +" + $i.ToString().PadLeft(8)}
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

    'Comment'   = "Custom"

    'String'    = "Custom"

    'FileName'  = "Custom"
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
   Merges properties / keys of the Secondary object / hashtable to the Primary object / hashtable.
.DESCRIPTION
   This function takes all properties or keys of the Secondary object / hashtable into the Primary object or hashtable. By default only those properties / keys are merge that doesn't exist in the Primary object / hashtable.
   If the -Force switch is used then the properties / keys of the Secondary object / hashtable always merged to the Primary.
.EXAMPLE
    $o = @{ObjProp = [pscustomobject] @{Prop1 = 1; Prop2 = 2}; HashProp = @{Key1 = 1; Key2 = 2}}; $result = Convert-CustomObjectHash -Object $o

    Because parameter -To is not specified, the conversion will be from [pscustomobject] to [hashtable], including all properties that are also [pscustomobject].
.EXAMPLE
    $o = @{ObjProp = [pscustomobject] @{Prop1 = 1; Prop2 = 2}; HashProp = @{Key1 = 1; Key2 = 2}}; $result = Convert-CustomObjectHash -Object $o -to pscustomobject

    Because the -To parameter is [pscustomobject], only the HashProp of the input object will be converted to [PScustomobject].
.INPUTS
   hashtables or pscustomobjects
.OUTPUTS
   The converted input object
#>
[cmdletbinding()]
param(
    # Object to convert.
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)][AllowNull()] [object]$Object,
    # Force conversion to this datatype.
    [Parameter()] [ValidateSet('hashtable', 'pscustomobject')] [AllowNull()] [string] $To,
    # Recursion depth, by default 5.
    [Parameter()][int] $Depth = 5,
    [Parameter(DontShow = $true)][int] $_currentdepth = 0
)
process{
    if($null -eq $Object){
        return
    }
    
    if($Object -isnot [System.Collections.IDictionary]){
        return $Object
    } 

    if($_currentdepth -gt $Depth){
        return
    }

    if(!$PSBoundParameters.to){
        if($Object -is [System.Collections.IDictionary]){
            $To = 'pscustomobject'
        }
        elseif($Object -is [System.Management.Automation.PSCustomObject]){
            $To = 'hashtable'
        }
        else{
            return
        }
    }    

    if($To -eq 'hashtable'){
        $newObject = @{}

        foreach($prop in $Object.psobject.properties){
            $newObject.($prop.name) = Convert-CustomObjectHash -Object $prop.value -To $To -_currentdepth ($_currentdepth + 1) -Depth $Depth
        }
        $newObject
    }
    elseif($To -eq 'pscustomobject'){
        $Object = [pscustomobject] $Object
        foreach($prop in $Object.psobject.properties){
            $Object.($prop.name) = Convert-CustomObjectHash -Object $prop.value -To $To -_currentdepth ($_currentdepth + 1) -Depth $Depth
        }
        $Object
    }
}
}

Function Update-Config {
param(
    [Parameter(Mandatory = $true)][string] $Environment,
    [Parameter(Mandatory = $true)]$prefix
)

    if($PSBoundParameters.ContainsKey("Environment") -or !$global:psconfig.ContainsKey("$($prefix)Environment")){
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
    - in other cases the function converts the existing value to a collection if it's not already that and adds the new value as a new element to that collection. If the new value is already
      among the existing elements then it will skip adding the new element to it.
    - if the -Force switch is used then the existing value is going to be overwritten by the new value

    This function is meant to extend the scope and functionality of Add-Member. 
.EXAMPLE
   $splatting = @{}; Update-Property -Object $splatting -PropName DisplayName -Value 'Tibor Soos'; Update-Property -Object $splatting -PropName Replace -Value @{proxyAddresses = "SMTP:Soos.Tibor@hotmail.com"}

   In this example we prepare a hashtable $splatting for splatting the Set-ADUser cmdlet to set the displayname and the proxyAddresses attribute of an AD user object.
.EXAMPLE
   Update-Property -Object $splatting -PropName Replace -Value @{proxyAddresses = "smtp:SoosTibor@hotmail.com"} ; $splatting.Replace

   In this example we add a secondary SMTP address to the splatting hashtable under its Replace key.
.EXAMPLE
   Update-Property -Object $splatting.Replace -PropName proxyAddresses -Value "smtp:tibor.soos@hotmail.com" -PassThru

   In this example we add another secondary SMTP address to the splatting hashtable directly under its Replace.proxyAddresses key. Using the -PassThru switch we get back the updates hashtable under the Replace key.
.EXAMPLE
    $obj = [pscustomobject] @{Prop1 = "Text"; Prop3 = "Obsolete"}; Update-Property -Object $obj -PropName Prop2; Update-Property -Object $obj -PropName Prop3 -Value Fresh -Force; Update-Property -Object $obj -PropName Prop1 -Value NewText -PassThru

    In this example we update an object in $obj 3 times. First we create a new property Prop2, then we overwrite the property 'Prop3' to 'Fresh', then we extend the existing value of Prop1 by converting it to a collection and adding 'NewText' to it as a new element.
.INPUTS
   hashtable or psobject
.OUTPUTS
   The updated input object if the -PassThru switch is used.
#>
[cmdletbinding()]
param(
    # Input object, either a hashtable or a PSObject
    [psobject] $Object,
    # Name of the property or key to update
    [string]   $PropertyPath,
    # Do not expand dots (.) in -PropertyPath
    [switch] $LiteralPropertyName,
    # The new value to include in the update process. By default it's 1.
    [psobject] $Value = 1,
    # Switch to output the update input object
    [switch]   $PassThru,
    # Switch to do an overwrite
    [switch]   $Force,
    [Parameter(Dontshow = $true)] $objectToReturn = $Object
)
    if(!$LiteralPropertyName -and $PropertyPath -match '\.|\[\w+\](?=(\.|$))'){
        $nextProp, $PropertyPath = $PropertyPath -split '\.|(?=\[\w+\]$)', 2

        if($nextProp){            
            $nextObj = $Object.$nextProp
            Update-Property -Object $nextObj -PropertyPath $PropertyPath -Value $Value -PassThru:$PassThru -Force:$Force -objectToReturn $objectToReturn
            return
        }
    }

    $indx = $null

    if($PropertyPath -match '^\[(\w+)\]$'){
        if($Matches[1] -as [int]){
            $indx = [int] $Matches[1]

            if($Object -is [collections.ilist]){
                $PropertyPath = $null
                if($Object.count -le $indx){
                    if($ErrorActionPreference -ne 'Ignore'){
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
        if($ErrorActionPreference -ne 'Ignore'){
            Write-Error "No object"        
        }
        return
    }

    if($Object -is [hashtable] -and !$Object.containskey($PropertyPath)){
        $Object.$PropertyPath = $Value
    }
    elseif($Object -isnot [hashtable] -and $Object -isnot [system.collections.ilist] -and $Object.psobject.Properties.Name -notcontains $PropertyPath){
        Add-Member -InputObject $Object -MemberType NoteProperty -Name $PropertyPath -Value $Value
    }
    elseif($Force){
        if($null -eq $indx){
            $Object.$PropertyPath = $Value
        }
        else{
            $Object[$indx] = $Value
        }
    }
    else{
        if($null -eq $indx){
            if($Object.$PropertyPath -is [int] -and $Value -is [int]){
                $Object.$PropertyPath += $Value
            }
            elseif($Object.$PropertyPath -is [string]){
                if($Value -ne $Object.$PropertyPath){
                    $Object.$PropertyPath = @($Object.$PropertyPath) + $Value
                }
            }
            elseif($Object.$PropertyPath -is [collections.ilist]){
                if($Object.$PropertyPath.count -gt 0 -and $Object.$PropertyPath[0] -is [hashtable]){
                    if($Value -is [collections.ilist] -and $Value.count -gt 0 -and $Value[0] -is [hashtable]){
                        $existingKeys = $Object.$PropertyPath | &{process{$_.Keys}}

                        if($existingKeys -notcontains ($Value | &{process{$_.Keys}})){
                            $Object.$PropertyPath += $Value
                        }
                        else{              
                            foreach($v in $Value){      
                                $equalfound = $null

                                for($i = 0; $i -lt $Object.$PropertyPath.count; $i++){
                                    $difffound = $false
                                    foreach($k in $o.keys){
                                        if($v.$k -ne $v.$k){
                                            $difffound = $true
                                            break
                                        }
                                    }
                                    if(!$difffound){
                                        $equalfound = $i
                                        break
                                    }
                                }
                    
                                if($null -ne $equalfound){
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
                    foreach($elem in $Value){
                        if($Object.$PropertyPath -notcontains $elem){
                            $toadd += $elem
                        }
                    }

                    if($toadd){
                        if($Object.$PropertyPath -is [System.Collections.ArrayList]){
                            $Object.$PropertyPath.addrange($toadd)
                        }
                        else{
                            $Object.$PropertyPath += $toadd
                        }
                    }
                }
            }
            elseif($Object.$PropertyPath -is [System.Collections.Hashtable] -and $Value -is [System.Collections.Hashtable]){
                $keys = [object[]] $Value.keys
                foreach($key in $keys){
                    if($Object.$PropertyPath.containskey($key)){
                        if($Object.$PropertyPath.$key -notcontains $Value.$key){
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
            elseif($null -eq $Object.$PropertyPath){
                $Object.$PropertyPath = $Value
            }
            else{
                $Object.$PropertyPath = @($Object.$PropertyPath) + $Value
            }
        }
        else{
            if($Object[$indx] -is [int] -and $Value -is [int]){
                $Object[$indx] += $Value
            }
            elseif($Object[$indx] -is [string]){
                if($Value -ne $Object[$indx]){
                    $Object[$indx] = @($Object[$indx]) + $Value
                }
            }
            elseif($Object[$indx] -is [collections.ilist]){
                if($Object[$indx].count -gt 0 -and $Object[$indx][0] -is [hashtable]){
                    if($Value -is [collections.ilist] -and $Value.count -gt 0 -and $Value[0] -is [hashtable]){
                        $existingKeys = $Object[$indx] | &{process{$_.Keys}}

                        if($existingKeys -notcontains ($Value.keys | &{process{$_.Keys}})){
                            $Object[$indx] += $Value
                        }
                        else{                    
                            foreach($v in $Value){      
                                $equalfound = $null

                                for($i = 0; $i -lt $Object[$indx].count; $i++){
                                    $difffound = $false
                                    foreach($k in $o.keys){
                                        if($v.$k -ne $v.$k){
                                            $difffound = $true
                                            break
                                        }
                                    }
                                    if(!$difffound){
                                        $equalfound = $i
                                        break
                                    }
                                }
                    
                                if($null -ne $equalfound){
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
                    foreach($elem in $Value){
                        if($Object.$PropertyPath -notcontains $elem){
                            $toadd += $elem
                        }
                    }

                    if($toadd){
                        if($Object.$PropertyPath -is [System.Collections.ArrayList]){
                            $Object.$PropertyPath.addrange($toadd)
                        }
                        else{
                            $Object.$PropertyPath += $toadd
                        }
                    }
                }
            }
            elseif($Object[$indx] -is [System.Collections.Hashtable] -and $Value -is [System.Collections.Hashtable]){
                $keys = [object[]] $Value.keys
                foreach($key in $keys){
                    if($Object[$indx].containskey($key)){
                        if($Object[$indx].$key -notcontains $Value.$key){
                            if($null -ne $Object[$indx].$key){
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
            else{
                $Object[$indx] = @($Object[$indx]) + $Value
            }
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
   If the pattern is in the form of '<name>', the the function searches for all the properties / keys where the value matches the value of property / key with name 'name'.
   If we want to skip certain properties / keys, then we can specify those at the -ExcludeProperty parameter.
   By default the search is case insensitive, we can make it case sensitive by specifying the -CaseSensitive switch.
   By default the search is done among those properties / keys which contain a collection of values. To skip searching in those properties we can specify the -IgnoreCollections switch.
   By default the search goes into the immediate properties / keys of the input objects. We can specify the search depth by assigning a value to the -Depth parameter.
   The result contains custom objects having an 'Object' property which is meant to be an identifyer of the input objects. That is by default the result of the ToString() method invoking on the input object. 
   If we want to have that identifier of one of the properties of the input object then we can specify that property name / key in the -ObjectNameProp parameter.
.EXAMPLE
   Get-Item -Path C:\Windows\notepad.exe | Search-Property -Pattern '<basename>' -Depth 2 -ObjectNameProp name -CaseSensitive -IgnoreCollections

   In this example we search the base name of the notepad.exe file object (notepad) among its properties and the properties of properties (-Depth 2) in a case sensitive way, so the VersionInfo.OriginalFilename property is not returned, because there the value is NOTEPAD.EXE.MUI.
   The first column of the result set contain the name of the file (notepad.exe) and not the full path, because we specified that the object name should be taken from property 'name'.
.EXAMPLE
   @{One = "MyValue"; KeyTwo = 'One'; Coll = 'one', 'two'; KeyThree = @{SubKey1 = 'One'; SubKey2 = [pscustomobject]@{Prop1 = 'One'; Prop2One = 'Text'}}} | Search-Property -Pattern '^One$' -SearchInPropertyNames -Depth 3 -IgnoreCollections

   In this example we search for the exact string 'One' among all the keys of the hashtable specified in the command line max 3 levels deep. We skip the key 'Coll', because that contains a collection and we specified the -IgnoreCollections switch. The result also contains property 'Prop1' of the object under the key 'Subkey2'. 
.INPUTS
   hashtable or psobject
.OUTPUTS
   Collection of custom objects having an Object, Name and Value properties.
#>
[cmdletbinding()]
param(
    # Regex pattern to search for       
    [parameter(Position=0)][string] $Pattern = ".",

    # Input object or hashtable
    [parameter(ValueFromPipeline)][psobject] $Object,

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
begin{
    if($LiteralSearch -and $Pattern -ne "."){
        $Pattern = [regex]::Escape($Pattern)            
    }

    if($CaseSensitive){
        $Pattern = "(?-i)$Pattern"
    }

    $origpattern = $Pattern
    $pipeline = $false

    if(!$_ObjectName -and !$ObjectNameProp){
        $parts = [scriptblock]::Create($MyInvocation.Line).ast.findall({$true},$true)

        for($i = 0; $i -lt $parts.count; $i++){
            if($parts[$i].ParameterName -eq 'Object'){
                $_ObjectName = $parts[$i + 1].Extent.Text

                if($_ObjectName -notmatch '^\(.*\)$' -and ($_ObjectName -notmatch '^\$' -or ($parts[$i + 1].staticType -match "\[\]$" -and $_ObjectName -notmatch "^\("))){
                    $_ObjectName = "($_ObjectName)"
                }
                break
            }
        }

        if(!$_ObjectName -and $parts[2].gettype().fullname -match 'PipelineAst'){
            $pipeline = $true            
        }

        $excludeType = $SkipTypesDefault + $SkipTypesAdditional | &{process{$_ -replace "\[", '[[' -replace "\]", ']]'}}

        if(!$_ObjectName){
            if($pipeline){
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
    foreach($o in $Object){
        if($null -eq $o){
            continue
        }        

        if($_ObjectName){
            $objectName = $_ObjectName
            if($pipeline -or ($Object -is [System.Collections.IList]) -and $_Depth -eq 1){
                $objectName = $ObjectName -replace "(\[\d+\])?$" -replace '$', "[$objectCount]"
                $objectCount++
            }
        }
        elseif($ObjectNameProp){
            $objectName = $o.$ObjectNameProp
        }
        else{
            $objectName = $o.ToString()
        }

        if(!$IgnoreCollections -and $o -is [collections.ilist]){
            $index = 0

            foreach($elem in $o){
                $parentNames = "$($_ParentNames -join '.')[$index]"

                if($elem.tostring() -ne $elem.gettype().fullname -and $elem -match $Pattern){
                    $out = [pscustomobject]@{
                        Object = $objectName
                        PropertyPath = $parentNames
                        Type = $type
                        Value = $elem
                    }

                    $out.pstypenames.insert(0, 'ScriptTools.Property.Expand')
                    $out
                }

                Search-Property -Object $elem -Pattern $origpattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property:$Property -ExcludeProperty:$ExcludeProperty -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -_ParentNames $parentNames -_ObjectName $objectName
                $index++
            }
        }
        else{
            if(!$LiteralSearch -and $origpattern -match "<[^>]+>"){
                $Pattern = [regex]::Replace($origpattern, "<([^>]+)>", {[regex]::Escape($o.($args[0].value -replace "<|>"))})
            }

            if($o -is [System.Collections.IDictionary]){
                $properties = $o.getenumerator() | Select-Object -Property Name, Value
            }
            else{
                $properties = $o.psobject.properties
            }

            foreach($prop in ($properties | Sort-Object -Property Name)){
                $PropName = $prop.Name

                if($PropName -eq 'loop'){
                    $dummy = 0
                }

                if(
                    $prop.membertype -ne 'AliasProperty' -and 
                    (
                        $(if(!$ExcludeValues){$prop.value -as [string] -and $prop.value.tostring() -ne $prop.value.gettype().fullname -and $prop.value -match $Pattern}) -or
                        $(if($SearchInPropertyNames){$prop.name -as [string] -and $prop.name -match $Pattern})
                    ) -and
                    !($ExcludeProperty | &{process {if($PropName -like $_){$_}}}) -and
                    ($Property | &{process {if($PropName -like $_){$_}}}) -and
                    (!$IgnoreCollections -or $prop.value -isnot [collections.ilist])
                ){
                    $propFullName = ($_ParentNames + $PropName) -join "."
                    if($null -ne $prop.value){
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
                    
                if($prop.value -and $prop.value.gettype().fullname -notin 'system.string', 'system.int32' -and $_Depth -lt $Depth){
                    if($prop.value -is [collections.ilist]){
                        Search-Property -Object (,$prop.value) -Pattern $pattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property $Property -ExcludeProperty $ExcludeProperty -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -_ParentNames ($_ParentNames + $PropName) -_ObjectName $objectName
                    }
                    elseif($prop.Value -is [System.Management.Automation.PSReference]){
                        $obj = [pscustomobject] @{Value = $prop.value.value}
                        Search-Property -Object $obj -Pattern $pattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property $Property -ExcludeProperty $ExcludeProperty -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -_ParentNames ($_ParentNames + $PropName) -_ObjectName $objectName
                    }
                    else{
                        Search-Property -Object $prop.value -Pattern $pattern -SearchInPropertyNames:$SearchInPropertyNames -ExcludeValues:$ExcludeValues -LiteralSearch:$LiteralSearch -Property $Property -ExcludeProperty $ExcludeProperty -CaseSensitive:$CaseSensitive -IgnoreCollections:$IgnoreCollections -Depth $Depth -_Depth ($_Depth + 1) -_ParentNames ($_ParentNames + $PropName) -_ObjectName $objectName
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
   $f1 = Get-Item C:\Windows\notepad.exe; $f2 = Get-Item C:\Windows\System32\notepad.exe; Compare-Property -ReferenceObject $f1 -DifferenceObject $f2 -IncludeEqual -ExcludeDifferent -Exclude PS*

   In this example we compare the properties of the two notepad.exe file objects, exclude the properties that are different but include properties that are equal. We also exclude all properties whose name start with PS.
.EXAMPLE
    Compare-Property -ReferenceObject @{Name = 'First'; Number = 1; Array = 1,2; RefEmpty = $null} -DifferenceObject @{Name = 'Second'; Number = 2; Array = 2,3; DiffEmpty = @()} -Hide Empty -NameProperty Name -Exclude Name

    In this example we compare the keys of two hashtables. We exclude those properties that contain 'empty' values ($null, empty array, empty hashtables, System.DBNull) in either input objects. 
    We also include in the column names the content of the Name property of the respective hashtables, but exclude the Name property from the differences.
.INPUTS
   hashtable or psobject
.OUTPUTS
   Collection of custom objects having a Property, Relation and 'r:<reference object ID>', 'd:<difference object ID>' properties.
#>
[cmdletbinding()]
param(
    # The reference object or hashtable
    [Parameter(Mandatory = $true)] [AllowNull()][psobject] $ReferenceObject,
    # The difference object or hashtable
    [Parameter(Mandatory = $true)] [AllowNull()][psobject] $DifferenceObject,
    # Include equal properties/keys in the result
    [switch] $IncludeEqual,
    # Exclud differences from the result
    [switch] $ExcludeDifferent,
    # Include properties/keys to compare
    [string[]] $Property = "*",
    # Exclude properties/keys to compare
    [string[]] $Exclude,
    # Use this property or the result of executing the scriptblock as the name for the objects
    [ValidateScript({$_ -is [string] -or $_ -is [scriptblock]})] [psobject] $NameProperty,
    # Hide certain type of empty properties
    [string] [ValidateSet('None','Empty','NonEmpty','BothEmpty')] $Hide = 'None',
    [Parameter(Dontshow = $true)][int] $_Depth = 1,
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
    elseif($ReferenceObject -is [scriptblock] -and $PSBoundParameters.ContainsKey('_Depth')){
        if($ReferenceObject.ToString() -eq $DifferenceObject.tostring()){
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
    elseif($ReferenceObject.gettype().fullname -in 'System.RuntimeType', 'System.Reflection.RuntimeAssembly'){
        return
    }
    elseif($ReferenceObject -is [System.IO.FileSystemInfo] -and $PSBoundParameters.ContainsKey('_Depth')){
        if($ReferenceObject.fullname -eq $DifferenceObject.fullname){
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
                $diff = Compare-Property -ReferenceObject $ReferenceObject[$i] -DifferenceObject $DifferenceObject[$i] -_Depth ($_Depth + 1)
                if($diff){
                    $equal = "<>"
                    break
                }
            }
        }
    }

    if($NameProperty){
        if($NameProperty -is [string]){
            if(!$rObjName){
                $rObjName = $ReferenceObject.$NameProperty
            }
            if(!$dObjName){
                $dObjName = $DifferenceObject.$NameProperty
            }
        }
        else{
            if(!$rObjName){
                $rObjName = $ReferenceObject | &{process{ & $NameProperty}}
            }
            if(!$dObjName){
                $dObjName = $DifferenceObject | &{process{ & $NameProperty}}
            }
        }
    }
    else{
        if(!$rObjName){
            $rObjName = $ReferenceObject.tostring()
        }
        if(!$dObjName){
            $dObjName = $DifferenceObject.tostring()
        }
    }
    $rs = "r:" + $rObjName
    $ds = "d:" + $dObjName

    if(!$equal -and $MaxDepth -lt $_Depth){
        if($ReferenceObject.tostring() -eq $DifferenceObject.ToString()){
            $equal = "=="
        }
        else{
            $equal = "<>"
        }
    }
    
    if($equal){
        if($equal -ne '=='){
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
            if($NameProperty -is [string]){
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

        $rp = $referenceobject.psobject.Properties |    
                &{process{ if($_.membertype -ne 'AliasProperty'){$_}}} |    
                    Select-Object -ExpandProperty Name

        $allprops = @($rp)   

        $dp = $differenceobject.psobject.Properties |
                &{process {if($_.membertype -ne 'AliasProperty'){$_}}} |
                    Select-Object -ExpandProperty Name
        
        foreach($p in $dp){    
            if($allprops -notcontains $p){
                $allprops += $p
            }
        }

        $allprops = $allprops | &{process {
                $pp = $_
                if(($Property | &{process {if($pp -like $_){$_}}}) -and !($Exclude | &{process{if($pp -like $_){$_}}})) {$_}
            }} | Sort-Object

        foreach($p in $allprops){        
            if($rp -contains $p -and $dp -contains $p){
                $ra = $ReferenceObject.$p
                $da = $DifferenceObject.$p

                $diff = Compare-Property -ReferenceObject $ra -DifferenceObject $da -Property $Property -Exclude $Exclude -_Depth ($_Depth + 1)
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
                $dummy = 0
                if(($Hide -eq 'BothEmpty' -and $raempty -and $daempty) -or
                    ($Hide -eq 'Empty' -and ($raempty -or $daempty)) -or
                    ($Hide -eq 'NonEmpty' -and (!$raempty -or !$daempty))){
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
    Get-ChildItem C:\Windows\system32\*.exe | Get-Property -PropertyPath "VersionInfo.CompanyName", "PSDrive.Provider.Name" -ObjectNameProperty Name

    Gets the VersionInfo.CompanyName and PSDrive.Provider.Name properties of all EXE files under c:\windows\system32 folder. The result will have the Name of each files under the Object column.
.EXAMPLE
   $h = @{Name = "MyHashTable"; Array = @{n = 'First'; data = 'Text1'}, @{n = 'Second'; data = 'Text2'}}; Get-Property -Object $h -PropertyPath 'Array[1].data' -ValueOnly

   In this example we get the 'Text2' from hashtable $h. In this case the -PropertyPath contains an index as well and because we used the -ValueOnly switch only the value of 'data' is returned.
.INPUTS
   hashtables or psobjects
.OUTPUTS
   Collection of custom objects having an Object, PropertyPath, PropertyExists and Value properties, or only the value of the addressed property if the -ValueOnly switch is used.
#>
[cmdletbinding()]
param(
    # Input object to get its property
    [Parameter(Mandatory = $true, ValueFromPipeline = $true)] [psobject] $Object,
    # Path(s) of the value to query. This path is the full path to the value, including property names and key names and indexes.
    [Parameter(Mandatory = $true)] [string[]] $PropertyPath,
    # Property or key that can be used to reference the object. If not specified then the resullt of the ToString() method will be used.
    [string] $ObjectNameProperty,
    # Return only the addressed property/key value, not the complete custom object.
    [switch] $ValueOnly
)
begin{
    if(!$ObjectNameProperty){
        $parts = $null
        try{
            $mi = $MyInvocation
            $parts = [scriptblock]::Create($mi.Line).ast.findall({$true},$true)

            for($i = 0; $i -lt $parts.count; $i++){
                if($parts[$i].ParameterName -eq 'Object'){
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

        if(!$ObjectName -and $parts -and $parts[2].gettype().fullname -match 'PipelineAst'){
            $pipeline = $true            
        }

        if(!$ObjectName){
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
}
process{
    if($pipeline -or $Object -is [System.Collections.IList]){
        $ObjectName = $ObjectName -replace "\[\d+\]$" -replace '$', "[$objectCount]"
        $objectCount++
    }

    foreach($obj in $Object){
        if($null -eq $obj){
            continue
        }

        if($ObjectNameProperty){
            $ObjectName = $Object.$ObjectNameProperty
        }

        foreach($pp in $PropertyPath){
            $props = $pp -split "\.|(?<=.)(?=\[)"

            $currentObj = $obj

            $exists = $true

            foreach($p in $props){
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
                    if($currentObj.count -gt $index){
                        $currentObj = $currentObj[$index]
                    }
                    else{
                        $currentObj = $null
                        $exists = $false
                        break
                    }                    
                }
                elseif($null -ne $currentObj -and (($currentObj -is [System.Collections.IDictionary] -and $currentObj.containskey($p)) -or ($currentObj.psobject.properties.count -and $currentObj.psobject.properties.name -contains $p))){
                    $currentObj = $currentObj.$p
                    if($null -eq $currentObj){
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
                    Type = $(if($exists){$currentObj.gettype().fullname})
                    Value = $(if($exists){$currentObj})
                }

                $out.pstypenames.insert(0,'ScriptTools.Property.Get')
                $out
            }
        }

        if($Object -is [System.Collections.IList]){
            $ObjectName = $ObjectName -replace "\[\d+\]$" -replace '$', "[$objectCount]"
            $objectCount++
        }
    }
}
}

function Merge-Property {
<#
.Synopsis
   Merges properties / keys of the Secondary object / hashtable to the Primary object / hashtable.
.DESCRIPTION
   This function takes all properties or keys of the Secondary object / hashtable into the Primary object or hashtable. By default only those properties / keys are merge that doesn't exist in the Primary object / hashtable.
   If the -Force switch is used then the properties / keys of the Secondary object / hashtable always merged to the Primary.
.EXAMPLE
    $p = @{one = 1; three = 3}; $s = [pscustomobject]@{two = 2; three = 33; four = 4}; Merge-Property -Primary $p -Secondary $s -PassThru

    Merges $s into $p. The updated hashtable will have its key 'three' remained to be 3.
.EXAMPLE
   $p = @{one = 1; three = 3}; $s = [pscustomobject]@{two = 2; three = 33; four = 4}; Merge-Property -Primary $p -Secondary $s -PassThru -Force

   Merges $s into $p. The updated hashtable will have its key 'three' updated to be 33.
.INPUTS
   hashtables or psobjects
.OUTPUTS
   None or the updated object of the Primary object if the -PassThru switch is used.
#>
[cmdletbinding()]
param(
    # Primary object or hashtable to merge the properties of Secondary into.
    [Parameter(Mandatory = $true)][PSobject] $Primary,
    # Secondary object or hashtable whose properties or keys to be merged into Primary.
    [Parameter(Mandatory = $true)][PSobject] $Secondary,
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
                    $Primary.$prop = $Secondary.$prop
                }
            }
        }
    }
    else{
        if($Secondary -is [System.Collections.IDictionary]){
            foreach($key in $Secondary.keys){
                if($Force -or $Primary.psobject.properties.name -notcontains $key){
                    Add-Member -InputObject $Primary -MemberType NoteProperty -Name $key -Value $Secondary.$key -Force
                }
            }
        }
        else{
            foreach($prop in $Secondary.psobject.properties.name){
                if($Force -or $Primary.psobject.properties.name -notcontains $prop){
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
   Expand-Property -Object $PSVersionTable -MaxDepth 2 -SkipTypesAdditional system.version

   Expands the properties of the $PSVersionTable object down to 2 level deep, but any [system.version] type of property won't be expanded further.
.EXAMPLE
   Expand-Property -Object $PSVersionTable -MaxDepth 2 -SkipTypesAdditional system.version -Condensed

   Expands only the last properties in the hiararchy of properties in the $PSVersionTable object down to 2 level deep, but any [system.version] type of property won't be expanded further.
.INPUTS
   hashtables or psobjects
.OUTPUTS
   Collection of custom objects having a PropertyPath, Type, and Value properties.
#>
[cmdletbinding(PositionalBinding=$false)]
param(
    # Input object or hashtable
    [Parameter(ValueFromPipeline = $true)] $Object, 
    # Maximum depth of recursion, default is 1
    [int] $MaxDepth = 1,
    [Parameter(Dontshow = $true)]$ObjectName, 
    [Parameter(Dontshow = $true)]$PropertyPath,
    [Parameter(Dontshow = $true)]$_currentDepth = 1,
    # Only leaf properties / keys are returned
    [switch] $LeafOnly,
    # .NET types that are not expanded in properties / keys
    [string[]] $SkipTypesDefault = ('System.Int*', 'System.UInt*', 'System.Double', 'System.Decimal', 'System.String', 'System.DateTime', 'System.TimeSpan', 'System.RuntimeType',
        'System.Management.Automation.ScriptBlock', 'System.Management.Automation.PSModuleInfo', 'System.Version*', 'System.Object[]', 'System.Enum', 'System.Collections.ArrayList'),
    [string[]] $SkipTypesAdditional
)

begin{
    if(!$ObjectName){
        $parts = [scriptblock]::Create($MyInvocation.Line).ast.findall({$true},$true)

        for($i = 0; $i -lt $parts.count; $i++){
            if($parts[$i].ParameterName -eq 'Object'){
                $ObjectName = $parts[$i + 1].Extent.Text

                if($ObjectName -notmatch '^\(.*\)$' -and ($ObjectName -notmatch '^\$' -or ($parts[$i + 1].staticType -match "\[\]$" -and $ObjectName -notmatch "^\("))){
                    $ObjectName = "($ObjectName)"
                }
                break
            }
        }

        if(!$ObjectName -and $parts[2].gettype().fullname -match 'PipelineAst'){
            $pipeline = $true            
        }

        $excludeType = $SkipTypesDefault + $SkipTypesAdditional | &{process{$_ -replace "\[", '[[' -replace "\]", ']]'}}

        if(!$ObjectName){
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

    if($null -eq $Object){
        $r = [pscustomobject] @{
                Object = $displayPath
                PropertyPath = $PropertyPath
                Depth = $_currentDepth
                Type = $null
                Value = '$null'                
            }
        $r.pstypenames.insert(0, 'ScriptTools.Property.Expand')
        $r
        return
    }

    if($Object -is [System.DBNull]){
        $r = [pscustomobject] @{
                Object = $displayPath
                PropertyPath = $PropertyPath
                Depth = $_currentDepth
                Type = 'System.DBNull'
                Value = 'NULL'
            }
        $r.pstypenames.insert(0, 'ScriptTools.Property.Expand')
        $r
        return
    }
    
    $keys = $null

    if(!($excludeType | &{process{if($Object.gettype().fullname -like $_ -or $Object.pstypenames -contains $_){$_}}})){
        if($Object -is [System.Collections.IDictionary]){
            $keys = $Object.Keys
        }
        else{
            $keys = $Object.psobject.properties.name
        }

        if($Object.GetType().FullName -notmatch 'ordered'){
            $keys = $keys | Sort-Object
        }
    }

    if(!$LeafOnly -or (!$keys -and ($Object -isnot [System.Collections.IList] -or $Object.count -eq 0)) -or $_currentDepth -gt $MaxDepth){
        $r = [pscustomobject] @{
                Object = $displayPath
                PropertyPath = $PropertyPath
                Depth = $_currentDepth
                Type = $(if($null -ne $Object){$Object.GetType().fullname})
                Value = $Object
            }
        $r.pstypenames.insert(0, 'ScriptTools.Property.Expand')
        $r

        if($_currentDepth -gt $MaxDepth){
            return
        }
    }

    foreach($key in $keys){
        $displayKey = $key
        if($key -match '\W'){
            $displayKey = "'$key'"
        }

        Expand-Property -Object $Object.$key -ObjectName $displayPath -MaxDepth $MaxDepth -LeafOnly:$LeafOnly -_currentDepth ($_currentDepth + 1) -SkipTypesDefault $SkipTypesDefault -SkipTypesAdditional $SkipTypesAdditional -PropertyPath $(if($PropertyPath){$PropertyPath + '.' + $key}else{$key})
    }

    if($Object -is [System.Collections.IList] -and $_currentDepth -lt $MaxDepth){
        for($i = 0; $i -lt $Object.count; $i++){
            Expand-Property -Object $Object[$i] -ObjectName $displayPath -MaxDepth $MaxDepth -LeafOnly:$LeafOnly -_currentDepth ($_currentDepth + 1) -SkipTypesDefault $SkipTypesDefault -SkipTypesAdditional $SkipTypesAdditional -PropertyPath ("$PropertyPath[$i]")
        }
    }
}
}

#endregion

New-Alias -Name Compare-ObjectProperty -Value Compare-Property -Force
New-Alias -Name Expand-PSData -Value Expand-Property -Force

Export-ModuleMember -Variable scriptinvocation, astTypes, paramDef_ElementType -Function '*' -Alias Compare-ObjectProperty, Expand-PSData