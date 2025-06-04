#region Logging
function Initialize-Logging {
[CmdletBinding()]
param(
    [string] $title,
    [string] $name,
    [string] $path,
    # [hashtable[]] $additionalColumns,
    [string[]] $ignoreCommand = "HandleError",
    [int]    $keepdays = 60,
    [int]    $progressbarsec = 1,
    [int]    $progresslogfirst = 60,
    [int]    $progresslogmin   = 5,
    [string[]] $ignoreLocation = ("ScriptTools", "ScriptBlock"),
    [string] $mergeto,
    [string[]] $emailnotification,
    [string] $smtpserver,
    [switch] $BySeconds,
    [string] $datePart,
    [switch] $simulateRunbook
)
    if($mergeto){
        return $mergeto
    }

    (Get-Variable -Name Error -Scope global -ValueOnly).Clear()

    $cs = @(Get-PSCallStack)
    $scriptinvocation = $cs[1].InvocationInfo

    $version = "0.0.0"
    $releasedate = ""

    $additionalColumns = @(@{Name = "Function"; Rule = {$environmentInvocation.MyCommand.Name}; width = 26})

    if(($PSBoundParameters.ContainsKey('Debug') -and $PSBoundParameters.Debug) -or ($mergeto -and $global:logging.$mergeto._DebugMode)){
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

    if($simulateRunbook){
        $path = $env:TEMP
        $environment = 'Simulated Runbook'
        $BySeconds = $true
        $UseOutput = $true
    }
    elseif($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation'){
        $path = $env:TEMP
        $environment = $env:AZUREPS_HOST_ENVIRONMENT
        $BySeconds = $true
        $UseOutput = $true
    }
    elseif($host.name -eq 'Default Host'){
        $path = $env:TEMP
        $environment = "Hybrid Worker"
        $BySeconds = $true
        $UseOutput = $true
    }
    elseif(!$path){
        if($scriptinvocation.MyCommand.path){
            $path = Split-Path $scriptinvocation.MyCommand.path
        }
        else{
            $path = $env:TEMP
        }

        $path = Join-Path $path Logs
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

    if(!$name){
        $logname = "$($scriptname).log"
    }
    else{
        $logname = $name
    }
    
    if(!$global:logging -or $global:logging -isnot [hashtable]){
        $global:logging = @{}
    }

    $logFile = New-LogFile -name $logname -path $path -keepdays $keepdays -logname $logname -byseconds:$BySeconds -datepart $datePart

    $parentprocess = $null
    $myprocess = Get-CimInstance -ClassName Win32_process -Filter "ProcessID = '$PID'" -Verbose:$false
    if($myprocess.ParentProcessId){
        $parentprocess = Get-CimInstance -ClassName Win32_process -Filter "ProcessID = '$($myprocess.ParentProcessId)'" -Verbose:$false
    }

    $global:logging.$($logFile.Key) = [pscustomobject] @{
            Title = $title
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
                    BarSec  = $progressbarsec
                    BarNext  = $null
                    LogFirst = $progresslogfirst
                    LogNext  = $null
                    LogMin   = $progresslogmin
                }
            _AdditionalColumns = $additionalColumns
            _IgnoreCommand  = $ignoreCommand
            _ignoreLocation = $ignoreLocation
            _email          = $emailnotification
            _smtpserver     = $smtpserver
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

    $cs[1].InvocationInfo.BoundParameters.logname = $logFile.key

    return $logFile.key
}

function GetLogName {
    if($global:logging -and $global:logging -is [hashtable] -and $global:logging.Keys.Count -eq 1){
        $logname = $global:logging.Keys | Select-Object -First 1 
    }

    if(!$logname){
        $logname = Get-Variable -Name logname -Scope 1 -ValueOnly -ErrorAction Ignore
    }

    if(!$logname){
        $logname = Get-Variable -Name logname -Scope 2 -ValueOnly -ErrorAction Ignore
    }

    if(!$logname){
        $cs = @(Get-PSCallStack)

        for($i = 1; $i -lt $cs.Length; $i++){
            if(!$logname -and $cs[$i].InvocationInfo.BoundParameters.ContainsKey('logname')){
                $logname = $cs[$i].InvocationInfo.BoundParameters.logname            
            }
        }
    }

    if(!$logname -and $global:logname){
        $logname = $global:logname
    }

    $logname
}

function Write-LogProgress {
[cmdletbinding()]
    param(
        $inputarray,
        [string] $action,
        [int] $percent,
        [string] $logname,
        [int] $progresslogfirst
    )

    if(!$inputarray -or !$inputarray.count){
        return
    }

    if($PSBoundParameters.ContainsKey('logname') -and !$logname){
        return
    }

    $logname = GetLogName

    if(!$logname -or !$global:logging.ContainsKey($logname)){
        $logname = $null
        if($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation'){
            Write-Error "Logname '$logname' is not valid"
            $global:Error.RemoveAt(0)
        }
        else{
            Write-Host "Logname '$logname' is not valid" -ForegroundColor Red
        }
        return
    }

    if($progresslogfirst -eq 0){
        $progresslogfirst = $global:logging.$logname._Progress.LogFirst
    }

    if($inputarray.gethashcode() -ne $global:logging.$logname._Progress.ArrayID){
        $global:logging.$logname._Progress.ArrayID = $inputarray.gethashcode()
        $global:logging.$logname._Progress.Start   = get-date
        $global:logging.$logname._Progress.BarNext = get-date
        $global:logging.$logname._Progress.Counter = 0
        $global:logging.$logname._Progress.LogNext = (get-date).AddSeconds($progresslogfirst)
    }

    if((Get-Date) -ge $global:logging.$logname._Progress.BarNext -and ($global:logging.$logname._VerboseMode -or $PSBoundParameters.verbose)){
        if(!$PSBoundParameters.ContainsKey('percent')){
            $percent = $global:logging.$logname._Progress.Counter / $inputarray.count * 100
        }

        if($percent -gt 100){
            $percent = 100
        }

        if($global:logging.$logname._Progress.Counter -eq 0){
            $timeleft = [int]::MaxValue
        }
        else{
            $timeleft = ((Get-Date) - $global:logging.$logname._Progress.Start).totalseconds * ($inputarray.Count - $global:logging.$logname._Progress.Counter) / $global:logging.$logname._Progress.Counter
        }

        $done = "{0,$("$($inputarray.Count)".Length)}" -f $global:logging.$logname._Progress.Counter
        $left = "{0,$("$($inputarray.Count)".Length)}" -f ($inputarray.Count - $global:logging.$logname._Progress.Counter)
        Write-Progress -Activity $action -Status "All: $($inputarray.Count) Done: $done Left: $left" -PercentComplete $percent -SecondsRemaining $timeleft
        $global:logging.$logname._Progress.BarNext = (get-date).AddSeconds($global:logging.$logname._Progress.BarSec)
    }

    if((Get-Date) -ge $global:logging.$logname._Progress.LogNext){
        if($global:logging.$logname._Progress.Counter -eq 0){
            $timeleft = [int]::MaxValue
        }
        else{
            $timeleft = [int] (((Get-Date) - $global:logging.$logname._Progress.Start).totalseconds * ($inputarray.Count - $global:logging.$logname._Progress.Counter) / $global:logging.$logname._Progress.Counter)
        }

        $timeleft = [timespan]::FromSeconds($timeleft).tostring()

        $done = "{0,$("$($inputarray.Count)".Length)}" -f $global:logging.$logname._Progress.Counter
        $left = "{0,$("$($inputarray.Count)".Length)}" -f ($inputarray.Count - $global:logging.$logname._Progress.Counter)
        
        New-LogEntry -message "All: $($inputarray.Count) Done: $done Left: $left Estimated time left: $timeleft" -type Progress

        $global:logging.$logname._Progress.LogNext = (get-date).AddMinutes($global:logging.$logname._Progress.LogMin)
    }

    $global:logging.$logname._Progress.Counter++
}

function New-LogFile {
param(
    [string] $name,
    [string] $path,
    [int]    $keepdays = 60,
    [switch] $byseconds,
    [switch] $overwrite,
    [string] $datepart
)
    if(!$path){
        $logname = GetLogName

        $path = $global:logging.$logname.LogFolder
    }
    
    if(!(Test-Path -Path $path -PathType Container)){
        [void] (New-Item -Path $path -ItemType Directory -ErrorAction Stop)
    }
    
    if($byseconds){
        $datepart = Get-Date -Format 'yyyyMMddHHmmss'
    }
    elseif(!$datepart){
        $datepart = Get-Date -Format 'yyyyMMdd'
    }

    $filename = $name -replace "(?=\.(?!.*?\.))", "-$datepart"
    $searchname = $name -replace "(?=\.(?!.*?\.))", "-*"

    if($PSBoundParameters.ContainsKey('datepart')){
        $key = $filename
    }
    else{
        $key = $name
    }

    if($keepdays){
        Get-ChildItem -Path $path -Filter $searchname | Where-Object {((get-date) - $_.CreationTime).totaldays -gt $keepdays} |
            ForEach-Object {
                New-LogEntry "Removing obsolete file: '$($_.FullName)'" -indent 1
                Remove-Item -Path $_.FullName
            }
    }

    if($overwrite -or (!(Test-Path -Path (Join-Path -Path $path -ChildPath $filename)))){
        New-Item -Path $path -Name $filename -ItemType file -Force:$overwrite | Add-Member -MemberType NoteProperty -Name New -Value $true -PassThru | Add-Member -MemberType NoteProperty -Name Key -Value $key -PassThru
    }
    else{
        Get-Item -Path (Join-Path -Path $path -ChildPath $filename) | Add-Member -MemberType NoteProperty -Name New -Value $false -PassThru | Add-Member -MemberType NoteProperty -Name Key -Value $key -PassThru
    }
}

function FormatBorder {
param(
    [Parameter(ValueFromPipeline=$true)][string[]]$strings,
    [string] $title,
    [int] $indentlevel
)
begin{
    $lines = @()
    if($title){
        $lines += $title
    }
}
process{
    foreach($string in $strings){
        $lines += " " * $indentlevel * 4 + $string
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
    [Parameter(ValueFromPipeline = $true)]$object,
    [string[]] $property = "*",
    [string[]] $excludeproperty = $null,
    [switch] $divide,
    [switch] $hideNulls,
    [int] $indentlevel,
    [switch] $sort,
    $sortby,
    [switch] $bordered,
    [string[]] $hideProperty
)
begin {
    $lines = @()
}
process{
    
    $selecttedprops = @()
    $longest = 0

    foreach($p in $object.psobject.Properties){
        if($excludeproperty | Where-Object {$p.name -like $_} | Select-Object -First 1){
            continue
        }
        if(($property | Where-Object {$p.name -like $_} | Select-Object -First 1) -and (!$hideNulls -or $p.value)){
            $selecttedprops += $p

            if($p.name.length -gt $longest){
                $longest = $p.name.length + 1
            }
        }
    }

    if($object -is [string]){
        $lines += " " * $indentlevel * 4 + $object
    }
    elseif($selecttedprops){
        if($sort){
            if(!$sortby){
                $sortproperty = "name"
            }
            else{
                $sortproperty = $sortby
            }
        }
        else{
            $sortproperty = "dummy"
        }

        foreach($sp in ($selecttedprops | Sort-Object -Property $sortproperty -Debug:$false)){
            if($sp.value -as [string] -and ($hideProperty | Where-Object {$sp.name -like $_})){
                $value = '*' * ([string]$sp.value).length
            }
            else{
                $value = $sp.value
            }
            $lines += " " * $indentlevel * 4 + $sp.name.padright($longest) + ": " + $value
        }
    }
    if($divide){
        $lines += "-" * 100
    }
}
end{
    if($bordered){
        $lines | FormatBorder
    }
    else{
        $lines
    }
}
}

function Format-LogStringTable {
param(
    [Parameter(ValueFromPipeline = $true)]$object,
    [object[]] $Property = "*",
    [string[]] $ExcludeProperty = $null,
    [switch] $bordered
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

    if($bordered){
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
            $global:logging.$logname._UnhandledErrors++
        }
    }
}

function Add-LogTextWithRetry {
    [cmdletbinding()]
    param(
        [string] $path,
        [Parameter(ValueFromPipeline = $true)][string[]] $text,
        [ValidateScript( { $_ -is [System.Text.Encoding] })] $encoding = [System.Text.Encoding]::UTF8,
        [int] $timeout = 1,
        [switch] $force
    )   
    begin{
        $retry = $true
        $start = Get-Date
        $h = $null
        do {
            try {
                $locked = $false
                $h = [io.file]::AppendText($path)
            } 
            catch {
                $global:Error.Clear()
                if ($_.Exception.InnerException -and $_.Exception.InnerException.HResult -eq -2147024864) {
                    Start-Sleep -Milliseconds (Get-Random -Minimum 200 -Maximum 500)
                    $locked = $true
                } 
                else {
                    $retry = $false
                    $force = $true
                }
            }
            if (((Get-Date) - $start).totalseconds -gt $timeout) {
                $retry = $false
            }
        }while ((!$h -or !$h.BaseStream) -and $retry)

        if ($h -and $h.BaseStream -and $global:logging.$logname._LogCache.count) {
            while ($global:logging.$logname._LogCache.Count) {
                $cline = $global:logging.$logname._LogCache.dequeue()
                $h.Writeline($cline)
            }
        }
    }
    process{
        foreach($line in $text){
            if (!$h -or !$h.BaseStream) {            
                if ($force -or !$locked) {
                    throw "LogAppendText error"
                } 
                else {
                    $global:logging.$logname._LogCache.EnQueue($line)
                    if($global:logging.$logname._LogCache.Count -gt $global:logging.$logname._MaxCacheSize){
                        $tempfile = Join-Path -Path (Split-Path $path) -ChildPath "_Templog-$(get-date -Format 'yyyy-MM-dd-HH-mm-ss-fffffff').log" 
                        $global:logging.$logname._LogCache | Set-Content -Path $tempfile -Encoding ($encoding.EncodingName -replace 'US-')
                        $global:logging.$logname._LogCache.Clear()
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
    [Parameter(ValueFromPipeline = $true)] [string] $message,
    [Parameter()][ValidateSet('Info', 'Highlight', 'Warning', 'Error', 'Exit', 'Terminate', 'Unhandled', 'Progress', 'Debug', 'Header', 'Negative')]$type = 'Info',
    [int] $indentlevel,
    [switch] $useabsoluteindent,
    [switch] $nonewline,
    [switch] $displayonly,
    [string] $logname,
    [switch] $ignorelog
)
begin{
    if($PSBoundParameters.ContainsKey('logname') -and !$logname){
        return
    }
    if(!$logname){
        $logname = Get-Variable -Name logname -Scope 1 -ValueOnly -ErrorAction Ignore
    }
    if(!$logname -and $global:logging.Keys.Count -eq 1){
        $logname = $global:logging.Keys | Select-Object -First 1 
    }

    $relativelevel = 0

    $localverbose = $null
    $cs = @(Get-PSCallStack)

    for($i = 1; $i -lt $cs.Length; $i++){
        if(!$logname -and $cs[$i].InvocationInfo.BoundParameters.ContainsKey('logname')){
            $logname = $cs[$i].InvocationInfo.BoundParameters.logname            
        }

        if(!$relativelevel -and $cs[$i].ScriptName -ne $cs[0].ScriptName -and (!$logname -or $cs[$i].Command -notin $global:logging.$logname._IgnoreCommand)){
            $relativelevel = $i
        }

        if($null -eq $localverbose -and ($VerbosePreference -notin 'SilentlyContinue', 'Ignore' -or $cs[$i].InvocationInfo.BoundParameters.ContainsKey('Verbose'))){
            $localverbose = $cs[$i].InvocationInfo.BoundParameters.Verbose
        }
    }

    if(!$logname -and $global:logname){
        $logname = $global:logname
    }

    if(!$logname -or !$global:logging.ContainsKey($logname)){
        $logname = $null
        if($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation' -or $host.name -eq 'Default Host'){
            Write-Error "Logname '$logname' is not valid"
            $global:Error.RemoveAt(0)
        }
        else{
            Write-Host "Logname '$logname' is not valid" -ForegroundColor Red
        }
    }

    if($null -eq $localverbose){
        $localverbose = $global:logging.$logname._VerboseMode
    }

    $environmentInvocation = $cs | Where-Object {$_.Location -notmatch ($global:logging.$logname._IgnoreLocation -join "|") -and $_.command -notmatch ($global:logging.$logname._IgnoreCommand -join "|")} | Select-Object -First 1 -ExpandProperty InvocationInfo

    $baseindent = [math]::max($cs.count - $relativelevel - 2, 0)

    if($cs.Count -gt 2){
        $baseindent += $global:logging.$logname._BaseIndent
    }
    elseif($indentlevel){
        $global:logging.$logname._BaseIndent = $indentlevel
    }
    else{
        $global:logging.$logname._BaseIndent = 0
    }

    if(!$useabsoluteindent){
        $indentlevel = $indentlevel + $baseindent
    }

    $linenumber = $cs[$relativelevel].ScriptLineNumber
    
    switch($type){
        'Info'           {$param = @{ForegroundColor = "Gray"}}
        'Highlight'      {$param = @{ForegroundColor = "Green"}}
        'Header'         {$param = @{ForegroundColor = "Green"}}
        'Debug'          {$param = @{ForegroundColor = "Cyan"; BackgroundColor = 'DarkGray'}}
        'Warning'        {$param = @{ForegroundColor = "Yellow"; BackgroundColor = 'DarkGray'}; $global:logging.$logname._WarningsLogged++}
        'Error'          {$param = @{ForegroundColor = "Red"}; $global:logging.$logname._ErrorsLogged++}
        'Negative'       {$param = @{ForegroundColor = "Red"}}
        'Exit'           {$param = @{ForegroundColor = "Green"}}
        'Terminate'      {$param = @{ForegroundColor = "Red"; BackgroundColor = 'Black'}; $global:logging.$logname._ErrorsLogged++}
        'Unhandled'      {$param = @{ForegroundColor = "DarkRed"; BackgroundColor = 'DarkGray'}; $global:logging.$logname._ErrorsLogged++}
        'Progress'       {$param = @{ForegroundColor = "Magenta"}}
    }

    if($type -ne 'Unhandled'){
        Write-LogUnhandeldErrors
    }
}
process{
    if($logname){
        if($global:logging.$logname._LastLine){
            $line = " $message"
        }
        else{
            $line = "[$(Get-Date -Format 'yyyy.MM.dd HH:mm:ss')],[$(([string]$linenumber).PadLeft(6))],[$($type.toupper().padright(9))]"
            if($global:logging.$logname._additionalColumns){
                foreach($c in $global:logging.$logname._additionalColumns){
                    $line += ",[{0,$(-([math]::max($c.width,$c.name.length)))}]" -f ($c.Rule.GetNewClosure().invoke()[0])
                }
            }
            $line += ", »$(" " *$indentlevel * 4)$message"
        }

        if($nonewline -or $global:logging.$logname._LastLine){
            $global:logging.$logname._LastLine += $line
        }

        if($logname -and !$nonewline -and !$displayonly){
            if($global:logging.$logname._LastLine){
                #Add-Content -path $global:logging.$logname.LogPath -Value $global:logging.$logname._LastLine
                Add-LogTextWithRetry -path $global:logging.$logname.LogPath -text $global:logging.$logname._LastLine
                $global:logging.$logname._LastLine = ""
            }
            else{
                #Add-Content -path $global:logging.$logname.LogPath -Value $line
                Add-LogTextWithRetry -path $global:logging.$logname.LogPath -text $line
            }
        }
    }

    if($displayonly -or $localverbose -or $type -in 'Debug', 'Error', 'Terminate', 'Unhandled', 'Negative', 'Warning'){
        if($global:logging.$logname._UseOutput){
            if($type -in 'Error', 'Terminate', 'Unhandled'){
                Write-Error $line
                $global:Error.RemoveAt(0)
            }
            elseif($type -eq 'Warning'){
                Write-Warning $line
            }
        }
        else{
            Write-Host -Object $line @param -NoNewline:$nonewline
        }
    }
}
end{
    if($type -in 'Exit', 'Terminate'){
        if($logname){
            
            New-LogFooter -logname $logname

            if($global:logging.$logname._ErrorsLogged){
                $exitcode = 1
            }
            elseif($global:logging.$logname._WarningsLogged){
                $exitcode = 2
            }
            else{
                $exitcode = 0
            }

            if(!$ignorelog){
                if($global:logging.$logname._email -and $global:logging.$logname._smtpserver){
                    $contents = ""
                    foreach($log in $global:logging.Keys){
                        if($global:logging.$log._ErrorsLogged){
                            $contents += (Get-Content $global:logging.$log.LogPath -Encoding utf8) -join "`r`n"
                            $contents += "`r`n" + "`r`n" + ("-" * 200) + "`r`n"
                            $global:logging.$log._ErrorsLogged = 0
                        }
                    }

                    if($contents){
                        Send-MailMessage  -SmtpServer $global:logging.$logname._smtpserver -To $global:logging.$logname._email -Subject "PAMaaS Error Logs - $(get-date -Format 'yyyy.MM.dd HH.mm.ss')" -From "$($global:logging.$logname.ScriptName)@clearstream.com" -Body $contents -Encoding utf8
                    }
                }
            }
            else{
                Remove-Item -Path $global:logging.$logname.LogPath
            }

            if($global:logging.$logname._UseOutput){
                get-content -Path $global:logging.$logname.LogPath -encoding utf8

                if($cs.count -le 2){
                    return
                }
                else{
                    exit $exitcode
                }
            }
            elseif($global:logging.$logname.ScriptName -ne 'Interactive'){
                if($global:logging.$logname._parentprocess.Name -in 'exporer.exe', 'WindowsTerminal.exe' -or $Host.Name -match 'ISE|Visual Studio'){
                    exit $exitcode
                }
                else{
                    [environment]::Exit($exitcode)
                }
            }
        }

        if($cs.count -le 2){
            return
        }
        else{
            throw "Interactive exit: $exitcode"
        }
    }
}
}

function New-LogFooter {
param([string]$logname)

    if($PSBoundParameters.ContainsKey('logname') -and !$logname){
        return
    }

    $logname = GetLogName

    if(!$logname -or !$global:logging.ContainsKey($logname)){
        $logname = $null
        if($env:AZUREPS_HOST_ENVIRONMENT -eq 'AzureAutomation' -or $host.name -eq 'Default Host'){
            Write-Error "Logname '$logname' is not valid"
            $global:Error.RemoveAt(0)
        }
        else{
            Write-Host "Logname '$logname' is not valid" -ForegroundColor Red
        }
    }

    $seconds = [int] ((Get-Date) - $global:logging.$logname.LogStart).totalseconds

    $footer =   "LogName       : $logname",
                "Runtime       : $([timespan]::FromSeconds($seconds).tostring())",
                "ErrorsLogged  : $($global:logging.$logname._ErrorsLogged)",
                "WarningsLogged: $($global:logging.$logname._WarningsLogged)",
                "ParentProcess : $($global:logging.$logname._parentprocess.name)"
    $footer | FormatBorder | New-LogEntry -type Header
}

function Search-LogEntries {
param(
    [string[]] $lognames = $global:logging.Keys,
    [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true)] [string[]] $logpath,
    [scriptblock] $FilterScript,
    [switch] $alldates,
    [AllowNull()] [string[]] $sortBy,
    [switch] $descending
)
begin{
    if($logpath){
        if($PSBoundParameters.ContainsKey('lognames')){
            $logpath = Get-ChildItem -Path $logpath -Include $lognames -Recurse | Select-Object -ExpandProperty fullname
        }
        else{
            $logpath = Get-ChildItem -Path $logpath | Select-Object -ExpandProperty fullname
        }
    }
    elseif($lognames){
        foreach($ln in $lognames){
            $logpath += $global:logging.$ln.LogPath
        }
    }
}
process{
    foreach($lp in $logpath){
        if($alldates){
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

        if($sortBy){
            Get-Item -Path $lp -PipelineVariable p -ErrorAction Ignore | ForEach-Object {$_.fullname} | Import-Csv -Encoding Default | Where-Object -FilterScript $FilterScript | Sort-Object -Property $sortBy -Descending:$descending | select-object -Property @{n="LogName"; e={$p.name}}, * | Format-LogStringTable
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

#region Config management
function Import-Config {
param(
    [string[]]$pathsOrNames,
    [Parameter(Mandatory = $true)][hashtable] $PSConfig
)
    function ResolveDynamicData {
    param([hashtable] $confighive, $parentkeys = @())
       
        foreach($key in ($confighive.Clone().Keys | Sort-Object -Property {
                    if($_ -match '^Condition$'){"zz$($_)"}
                    elseif($_ -match 'ConfigAction'){"zzz$($_)"}
                    elseif($_ -match '^Conditional_'){"zzzz$($_)"}
                    else{"__$($_)"}
                }
            )
        ){
            if($confighive.$key -is [hashtable]){
                ResolveDynamicData -confighive $confighive.$key -parentkeys ($parentkeys + $key)
            }
            elseif($confighive.$key -is [scriptblock] -and (!$confighive.ContainsKey('Condition') -or $confighive.Condition)){
                $errorhappened = $false
                $errorcount = $Error.Count
                try{
                    $confighive.$key = &(& $confighive.$key)
                }
                catch{
                    $errorhappened = $true
                }

                if($errorhappened -or $errorcount -gt $error.Count){
                    throw "Configuration parsing error"
                }
            }
        }
    }

    function MergeHives {
        param(
            [hashtable] $hive,
            [hashtable] $target = $PSConfig
        )

        foreach($h in $hive.Clone().Getenumerator()){
            if($h.key -match '^Condition|^ConfigAction$'){
                continue
            }
            elseif($h.value -isnot [hashtable]){
                $target.($h.key) = $h.value
            }
            elseif(!$target.ContainsKey($h.key)){
                if($h.value.containskey('ConfigAction')){
                    $h.value.remove('ConfigAction')
                }
                
                $target.($h.key) = $h.value
            }
            else{
                try{
                    MergeHives -hive $h.value -target $target.($h.key)
                }
                catch{
                    $dummy = 0
                }
            }
        }
    }
    
    if($null -eq $PSConfig){
        $PSConfig = @{}
    }

    $scriptinvocation = (Get-PSCallStack)[1].InvocationInfo

    if($scriptinvocation.mycommand.path -match "\\\d+\.\d+\.\d+\\.*?psm1$"){
        $defaultconfig = "$($scriptinvocation.mycommand.path -replace "\.psm1$" -replace "\\\d+\.\d+\.\d+\\(?!.*?\\)","\Config\").psd1"
    }
    elseif($scriptinvocation.mycommand.path -match "\\.*?psm1$"){
        $defaultconfig = "$($scriptinvocation.mycommand.path -replace "\.psm1$" -replace "\\(?!.*?\\)","\Config\").psd1"
    }
    else{
        $defaultconfig = "$($scriptinvocation.mycommand.path -replace "\\(?!.*?\\)","\Config\").psd1"
    }

    if(!$pathsOrNames -and !(test-path -path $defaultconfig)){
        if(get-module -Name "PSConfigs" -ErrorAction Ignore -ListAvailable){
            Import-Module -Name PSConfigs -Force
            $defaultconfig = Get-PSConfigs -ScriptName $scriptinvocation.MyCommand.Name
        }
    }

    if($pathsOrNames -notcontains $defaultconfig -and (Test-Path $defaultconfig)){
        $pathsOrNames = @($defaultconfig) + $pathsOrNames | Where-Object {$_}
    }

    foreach($path in $pathsOrNames){
        if($path -notmatch "^\w:|^\."){
            $path = Join-Path (split-path $scriptinvocation.mycommand.path) "\Config\$path"
        }

        if(!(Test-Path -Path $path)){
            Write-Error "No config file was found at '$path'"
            continue
        }

        $config = Import-PowerShellDataFile -Path $path

        ResolveDynamicData -confighive $Config

        $ConfigClone = $Config.Clone()

        foreach($key in ($ConfigClone.keys -notmatch '^Condition' | Sort-Object)){
            MergeHives -hive $Config
        }

        foreach($key in ($ConfigClone.keys -match '^Conditional_' | Sort-Object)){
            if($ConfigClone.$key.condition){
                MergeHives -hive $Config.$key
            }
        }
    }
}

function Expand-Config {
    param($config, $path = "PSConfig")
    
    if(!$config -or ($config -is [hashtable] -and $config.Keys.Count -eq 0)){
        return
    }
    elseif($config -isnot [hashtable]){
        foreach($eelement in $config){
            [pscustomobject] @{
                    Path = $path
                    Value = $element
                }
        }
        return
    }
    
    foreach($key in $config.Keys){
        if($config.$key -is [hashtable]){
            Expand-Config -config $config.$key -path ($path + "." + $key)
        }
        else{
            foreach($element in $config.$key){
                Expand-Config -config $element -path ($path + "." + $key)
            }
        }
    }
}
#endregion

#region Miscellaneous functions
function New-DynamicParameter {
param(
    [Parameter(ValueFromPipelineByPropertyName = $true, ValueFromPipeline = $true, Mandatory = $true)] [string] $Name,
    [Parameter(ValueFromPipelineByPropertyName = $true)] [type]   $type,
    [Parameter(ValueFromPipelineByPropertyName = $true)] [string[]] $parameterSetName ="Default",
    [Parameter(ValueFromPipelineByPropertyName = $true)] $mandatory,
    [Parameter(ValueFromPipelineByPropertyName = $true)] [scriptblock] $validationSet,
    [Parameter(ValueFromPipelineByPropertyName = $true)] [switch] $ValueFromPipeline,
    [Parameter(ValueFromPipelineByPropertyName = $true)] [switch] $ValueFromPipelineByPropertyName,
    [Parameter(ValueFromPipelineByPropertyName = $true)] $defaultValue,
    [Parameter(ValueFromPipelineByPropertyName = $true)] [scriptblock] $condition,
    [Parameter(ValueFromPipelineByPropertyName = $true)] [string[]] $aliases,
    [int] $startposition = 0
)
begin{
    $paramDictionary = new-object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
    $position = $startposition
}
process{
    if($condition -eq $null -or (&$condition)){
        $attributeCollection = new-object -TypeName System.Collections.ObjectModel.Collection[Attribute]

        foreach($psn in $parameterSetName){
            $attribute = new-object -TypeName System.Management.Automation.ParameterAttribute
            $attribute.ParameterSetName = $psn
            if($PSBoundParameters.ContainsKey('startposition')){
                $attribute.Position = $position
                $position++
            }
            if($mandatory -is [scriptblock]){
                $attribute.Mandatory = &$mandatory
            }
            else{
                $attribute.Mandatory = $mandatory
            }
            $attribute.ValueFromPipeline = $ValueFromPipeline
            $attribute.ValueFromPipelineByPropertyName = $ValueFromPipelineByPropertyName

            $attributeCollection.Add($attribute)
        }

        if($validationSet){
            $vsa = New-Object -TypeName System.Management.Automation.ValidateSetAttribute -ArgumentList (&$validationSet)
            $attribute.HelpMessage = "Possible values: $((&$validationSet) -join ', ')"
            $attributeCollection.Add($vsa)           
        }

        if($aliases){
            $alias = New-Object -TypeName System.Management.Automation.AliasAttribute -ArgumentList $aliases
            $attributeCollection.Add($alias)           
        }

        $param = new-object -TypeName System.Management.Automation.RuntimeDefinedParameter -ArgumentList $name, $type, $attributeCollection
        
        $global:psb = $PSBoundParameters
        if($PSBoundParameters.ContainsKey('defaultValue') -and $null -ne $defaultValue){
            $si = Get-PSCallStack
            if($defaultValue -is [scriptblock]){
                $param.Value = &$defaultValue
                $si[1].InvocationInfo.BoundParameters.$name = $param.Value
            }
            else{
                $param.Value = $defaultValue
                $si[1].InvocationInfo.BoundParameters.$name = $defaultValue
            }
        }
        $paramDictionary.Add($name, $param)
    }    
}
end{
    $paramDictionary
}
}

function Invoke-Executable {
    # Runs the specified executable and captures its exit code, stdout
    # and stderr.
    # Returns: custom object.
    param(
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]$ExeFile,
        [Parameter(Mandatory=$false)]
        [String]$Arguments,
        [Parameter(Mandatory=$false)]
        [String]$Verb,
        [Parameter(Mandatory=$false)]
        [String]$User,
        [Parameter(Mandatory=$false)]
        [System.Security.SecureString]$Password
    )

    # Setting process invocation parameters.
    $oPsi = New-Object -TypeName System.Diagnostics.ProcessStartInfo
    $oPsi.CreateNoWindow = $true
    $oPsi.UseShellExecute = $false
    $oPsi.RedirectStandardOutput = $true
    $oPsi.RedirectStandardError = $true
    $oPsi.FileName = $ExeFile
    if (! [String]::IsNullOrEmpty($Arguments)) {
        $oPsi.Arguments = $Arguments
    }
    if (! [String]::IsNullOrEmpty($Verb)) {
        $oPsi.Verb = $Verb
    }

    if($User){
        $oPsi.Domain, $oPsi.UserName = $user.Split("\")
        $oPsi.WorkingDirectory = "c:\users\$env:username"        
    }
    if($Password){
        $oPsi.Password = $Password
    }

    # Creating process object.
    $oProcess = New-Object -TypeName System.Diagnostics.Process
    $oProcess.StartInfo = $oPsi

    # Creating string builders to store stdout and stderr.
    $oStdOutBuilder = New-Object -TypeName System.Text.StringBuilder
    $oStdErrBuilder = New-Object -TypeName System.Text.StringBuilder

    # Adding event handers for stdout and stderr.
    $sScripBlock = {
        if (! [String]::IsNullOrEmpty($EventArgs.Data)) {
            $Event.MessageData.AppendLine($EventArgs.Data)
        }
    }
    $oStdOutEvent = Register-ObjectEvent -InputObject $oProcess -Action $sScripBlock -EventName 'OutputDataReceived' -MessageData $oStdOutBuilder
    $oStdErrEvent = Register-ObjectEvent -InputObject $oProcess -Action $sScripBlock -EventName 'ErrorDataReceived' -MessageData $oStdErrBuilder

    # Starting process.
    try{
        [Void]$oProcess.Start()
    }
    catch{
        throw $_
    }
    $oProcess.BeginOutputReadLine()
    $oProcess.BeginErrorReadLine()
    [Void]$oProcess.WaitForExit()

    # Unregistering events to retrieve process output.
    Unregister-Event -SourceIdentifier $oStdOutEvent.Name
    Unregister-Event -SourceIdentifier $oStdErrEvent.Name

    $featureData = invoke-wmimethod -ErrorAction Ignore -Name GetServerFeature -namespace root\microsoft\windows\servermanager -Class MSFT_ServerManagerTasks
    $regData = Get-ItemProperty -path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -name "PendingFileRenameOperations" -ErrorAction Ignore
    if(($featureData -and $featureData.RequiresReboot) -or $regData){
        $needsreboot = $true
    }
    else{
        $needsreboot = $false
    }

    $oResult = New-Object -TypeName PSObject -Property @{
        "ExeFile"  = $ExeFile
        "Args"     = $Arguments 
        "ExitCode" = $oProcess.ExitCode
        "StdOut"   = $oStdOutBuilder.ToString().Trim()
        "StdErr"   = $oStdErrBuilder.ToString().Trim()
        "NeedsReboot" = $needsreboot
    }

    return $oResult
}

function Get-Encoding{
  param(
    [Parameter(Mandatory = $true,ValueFromPipeline = $true,ValueFromPipelineByPropertyName = $true)] [Alias('FullName')][string]$Path
  )

  process{
    $bom = New-Object -TypeName System.Byte[](4)
         
    $resolvedpath = Resolve-Path -Path $Path | Select-Object -ExpandProperty ProviderPath

    $file = New-Object System.IO.FileStream($resolvedpath, 'Open', 'Read')
     
    $null = $file.Read($bom,0,4)
    $file.Close()
    $file.Dispose()
     
    $enc = [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Ascii
    if ($bom[0] -eq 0x2b -and $bom[1] -eq 0x2f -and $bom[2] -eq 0x76) 
      { $enc =  [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::UTF7 }
    if ($bom[0] -eq 0xff -and $bom[1] -eq 0xfe) 
      { $enc =  [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::Unicode }
    if ($bom[0] -eq 0xfe -and $bom[1] -eq 0xff) 
      { $enc =  [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::BigEndianUnicode }
    if ($bom[0] -eq 0x00 -and $bom[1] -eq 0x00 -and $bom[2] -eq 0xfe -and $bom[3] -eq 0xff) 
      { $enc =  [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::UTF32}
    if ($bom[0] -eq 0xef -and $bom[1] -eq 0xbb -and $bom[2] -eq 0xbf) 
      { $enc =  [Microsoft.PowerShell.Commands.FileSystemCmdletProviderEncoding]::UTF8}
         
    [PSCustomObject]@{
      Encoding = $enc
      Path = $resolvedpath
    }
  }
}

function Get-SHA1 {
param(
    [Parameter(ValueFromPipeline = $true)] [string] $string
)
begin{
    $sha1 = New-Object System.Security.Cryptography.SHA1CryptoServiceProvider
}
process{
    $BytesToHash = [Text.Encoding]::UTF8.GetBytes($string)
    $hash = $sha1.ComputeHash($BytesToHash)
    [BitConverter]::ToString($hash).replace('-','')
}
end{
    $sha1.Dispose()
}
}

function Format-XML ([xml]$xml, $indent=2) { 
    $StringWriter = New-Object System.IO.StringWriter 
    $XmlWriter = New-Object System.XMl.XmlTextWriter $StringWriter 
    $xmlWriter.Formatting = "indented" 
    $xmlWriter.Indentation = $Indent 
    $xml.WriteContentTo($XmlWriter) 
    $XmlWriter.Flush() 
    $StringWriter.Flush() 
    Write-Output $StringWriter.ToString() 
}

function Search-Script {
param(
    [string] $pattern,
    [string] $path,
    [string[]] $extension = ("ps1", "psm1"),
    [string[]] $exclude = "wxyz",
    [switch] $SortByDate,
    [switch] $casesensitive
)
    if($extension -ne "*"){
        $include = $extension | ForEach-Object {$_ -replace "^(\*)?(\.)?","*." }
    }
    $exclude = $exclude | ForEach-Object {$_ -replace "^(\*)?(\.)?","*." }
    
    $sortparam = "Path", "LineNumber"
    
    if($SortByDate){
        $sortparam = @("LastWriteTime") + $sortparam
    }

    $selectstringsplatting = @{}
    if($casesensitive){
        $selectstringsplatting.CaseSensitive = $true
    }

    Get-ChildItem -Path $path -Include $include -Exclude $exclude -Recurse |
        Select-String -Pattern $pattern @selectstringsplatting |
            Select-Object -Property Path, @{n="LastWriteTime"; e = {(get-item -Path $_.Path).LastWriteTime}}, LineNumber, Line |
                Sort-Object -Property $sortparam
}
#endregion

#region Property management
function Update-Property {
param(
    [psobject] $object,
    [string]   $propname,
    [psobject] $value = 1,
    [switch]   $passthru,
    [switch]   $force
)
    if($null -eq $object){
        Write-Error "No object - update propery"        
        return
    }
    if($object -is [hashtable] -and !$object.containskey($propname)){
        $object.$propname = $value
    }
    elseif($object -isnot [hashtable] -and $object.psobject.Properties.Name -notcontains $propname){
        Add-Member -InputObject $object -MemberType NoteProperty -Name $propname -Value $value
    }
    elseif($force){
        $object.$propname = $value
    }
    elseif($object.$propname -is [int] -and $value -is [int]){
        $object.$propname += $value
    }
    elseif($object.$propname -is [string]){
        if($value -ne $object.$propname){
            $object.$propname = @($object.$propname) + $value
        }
    }
    elseif($object.$propname -is [collections.ilist]){
        if($object.$propname -is [collections.ilist] -and $object.$propname.count -gt 0 -and $object.$propname[0] -is [hashtable]){
            if($value -is [collections.ilist] -and $value.count -gt 0 -and $value[0] -is [hashtable]){
                $existingKeys = $object.$propname | ForEach-Object {$_.Keys}

                if($existingKeys -notcontains ($value.keys | Select-Object -First 1)){
                    $object.$propname += $value
                }
                else{                    
                    $equalfound = $false
                    foreach($v in $object.$propname){
                        $difffound = $false
                        foreach($k in $v.keys){
                            if($v.$k -ne $value[0].$k){
                                $difffound = $true
                                break
                            }
                        }
                        if(!$difffound){
                            $equalfound = $true
                            break
                        }
                    }
                    
                    if(!$equalfound){
                        $object.$propname += $value
                    }
                }
            }
        }
        else{
            foreach($v in $value){
                if($object.$propname -notcontains $v){
                    $object.$propname += $v
                }
            }
        }
    }
    elseif($object.$propname -is [System.Collections.Hashtable] -and $value -is [System.Collections.Hashtable]){
        $keys = [object[]] $value.keys
        foreach($key in $keys){
            $object.$propname.$key = $value.$key
        }
    }
    else{
        $object.$propname = @($object.$propname) + $value
    }

    if($passthru){
        $object
    }
}

function Search-Property {
    param(
        [parameter(Position=0)][string] $Pattern = ".",
        [parameter(ValueFromPipeline)][psobject[]] $Object,
        [switch] $SearchInPropertyNames,
        [switch] $ExcludeValues,
        [switch] $LiteralSearch,
        [string[]] $Property = "*",
        [string[]] $ExcludeProperty,
        [string] $ObjectNameProp,
        [switch] $CaseSensitive
    )
    begin{
        if($LiteralSearch -and $Pattern -ne "."){
            $Pattern = [regex]::Escape($Pattern)            
        }

        if($CaseSensitive){
            $Pattern = "(?-i)$Pattern"
        }

        $origpattern = $Pattern
    }
    process{
        foreach($o in $object){
            if(!$LiteralSearch -and $origpattern  -match "<[^>]+>"){
                $Pattern = [regex]::Replace($origpattern, "<([^>]+)>", {[regex]::Escape($o.($args[0].value -replace "<|>"))})
            }
            $o.psobject.properties | 
                Where-Object {
                    $propname = $_.name
                    $_.membertype -ne 'AliasProperty' -and 
                    (
                        $(if(!$ExcludeValues){$_.value -as [string] -and $_.value -match $Pattern}) -or
                        $(if($SearchInPropertyNames){$_.value -as [string] -and $_.name -match $Pattern})
                    ) -and
                    !($ExcludeProperty | Where-Object {$propname -like $_}) -and
                    ($Property | Where-Object {$propname -like $_})
                } | Sort-Object -Property Name | Select-Object -Property @{n = "Object"; e = {if($objectNameProp){$o.$objectNameProp}else{$o.tostring()}}}, Name, Value
        }
    }
}

function Compare-ObjectProperty {
param(
    $ReferenceObject,
    $DifferenceObject,
    [switch] $IncludeEqual,
    [switch] $ExcludeDifferent,
    [string[]] $Property = "*",
    [string[]] $Exclude,
    [string] $NameProperty,
    [string] [ValidateSet('None','Empty','NonEmpty','BothEmpty')] $Hide = 'None',
    [Parameter(Dontshow = $true)][object[]] $_refs,
    [Parameter(Dontshow = $true)][object[]] $_diffs
)

    $allprops = @()
    $rp = @()    
    $dp = @()    
    $rs = 'r:'
    $ds = 'd:'

    if($null -ne $referenceobject){    
        $rp = $referenceobject.psobject.Properties |    
                Where-Object {$_.membertype -ne 'AliasProperty'} |    
                    Select-Object -ExpandProperty Name

        $allprops = @($rp)   
         
        if($NameProperty){
            $objname = $ReferenceObject.$NameProperty
        }
        else{
            $objname = $referenceobject.tostring()
        }
        $rs = "r:" + $objname
    }

    if($null -ne $differenceobject){    
        $dp = $differenceobject.psobject.Properties |
                Where-Object {$_.membertype -ne 'AliasProperty'} |
                    Select-Object -ExpandProperty Name
        
        foreach($p in $dp){    
            if($allprops -notcontains $p){
                $allprops += $p
            }
        }

        if($NameProperty){
            $objname = $DifferenceObject.$NameProperty
        }
        else{
            $objname = $DifferenceObject.tostring()
        }

        $ds = "d:" + $objname
    }

    $allprops = $allprops | Where-Object {
            $pp = $_
            ($property | Where-Object {$pp -like $_}) -and !($exclude | Where-Object {$pp -like $_})
        } | Sort-Object
    
    if($_refs -eq $referenceobject -or $_diffs -eq $differenceobject){
        continue
    }

    if($ra -and $ra.gettype().fullname -in 'System.RuntimeType', 'System.Reflection.RuntimeAssembly'){
        continue
    }

    $_refs += $referenceobject
    $_diffs += $differenceobject

    foreach($p in $allprops){        
        $ra = $referenceobject.$p
        $da = $differenceobject.$p

        if($referenceobject -is [ScriptBlock] -and $p -in 'Id', 'StartPosition'){
            continue            
        }

        if($differenceobject -is [ScriptBlock] -and $p -in 'Id', 'StartPosition'){
            continue            
        }

        $raempty = $null -eq $ra -or
                    '' -eq $ra -or
                    (($ra -is [collections.ilist] -or $ra -is [Collections.IDictionary]) -and $ra.count -eq 0) -or
                    $ra -is [System.DBNull]

        $daempty = $null -eq $da -or    
                    '' -eq $da -or    
                    (($da -is [collections.ilist] -or $da -is [Collections.IDictionary]) -and $da.count -eq 0) -or
                    $ra -is [System.DBNull]

        $rtype = if($null -eq $ra){"NULL"}else{$ra.gettype().fullname}
        $dtype = if($null -eq $da){"NULL"}else{$da.gettype().fullname}

        $equal = $null
        
        if($hide -eq 'Empty' -and ($raempty -or $daempty)){    
            continue
        }    
        elseif($hide -eq 'BothEmpty' -and $raempty -and $daempty){    
            continue    
        }    
        elseif($hide -eq 'NonEmpty' -and (!$raempty -or !$daempty)){    
            continue    
        }

        if(($raempty -and !$daempty) -or ($dp -contains $p -and $rp -notcontains $p)){    
            $equal = "=>"    
        }    
        elseif((!$raempty -and $daempty) -or ($rp -contains $p -and $dp -notcontains $p)){    
            $equal = "<="    
        }    
        elseif($rtype -ne $dtype){    
            $equal = "<>"    
        }    
        elseif($ra -is [collections.idictionary]){    
            $ra = @($ra.GetEnumerator())    
            $da = @($da.GetEnumerator())

            if(Compare-Object -ReferenceObject $ra -DifferenceObject $da -Property Key, Value){    
                $equal = "<>"    
            }    
            else{    
                $equal = "=="    
            }    
        }
        
        if(!$equal){
            if($ra.psbase.count -and $da.psbase.count -and $ra -isnot [collections.ilist] -and $ra.psobject.methods.name -contains 'GetEnumerator' -and $da.psobject.methods.name -contains 'GetEnumerator'){
                $ra = $ra.getenumerator() | Select-Object -Property *
                $da = $da.getenumerator() | Select-Object -Property *
            }

            if($ra -is [collections.ilist]){    
                if(Compare-Object -ReferenceObject $ra -DifferenceObject $da){    
                    $equal = "<>"    
                }    
                else{    
                    $equal = "=="    
                }    
            }    
        }
        
        if(!$equal){
            if($ra -and $ra -is [scriptblock] -or $ra -is [System.Management.Automation.Language.ScriptBlockAst]){
                $equal = if($ra.tostring() -eq $da.tostring()){"=="}else{"<>"}    
            }
            elseif($ra -and $da -and $ra -isnot [string] -and !$ra.gettype().IsValueType){
                if(Compare-ObjectProperty -ReferenceObject $ra -DifferenceObject $da -_refs $_refs -_diffs $_diffs){    
                    $equal = "<>"    
                }    
                else{    
                    $equal = "=="    
                }    
            }               
            else{    
                $equal = if($ra -eq $da){"=="}else{"<>"}    
            }
        }

        if((!$excludedifferent -and $equal -ne '==') -or ($includeequal -and $equal -eq '==')){    
            [pscustomobject] @{    
                Property = $p    
                Equal = $equal    
                $rs = $ReferenceObject.$p
                $ds = $DifferenceObject.$p
            }    
        }
    }
}
#endregion

Export-ModuleMember -Variable scriptinvocation -Function '*' 
