<#
    Author : Tibor Soós
    Version: 1.0.0 (2025.06.14)
#>
param(
    [Parameter()][ValidateSet('00VerboseErrorWarning', '01Silent', '02Unhandled', '03TerminateMain','04TerminateFunction','05ProgressBar', 
        '06OutputObject', '07OutputFile', '08AlternateLogFile', '09ModuleLogging', '10ModuleLoggingWithAlternateLog', '11SimulateRunbook')] $LogScenario
)

function SubFunction {
    New-LogEntry "This is a highlighted entry from a function" -Type Highlight

    if($LogScenario -match 'Module'){
        New-LogEntry "value of `$a : $a" -Type Warning
    }

    if($LogScenario -match 'Verbose|Silent'){
        New-LogEntry "Indented entry from a function" -IndentLevel 1
        New-LogEntry "This is an absolute 0 indent" -IndentLevel 0 -UseAbsoluteIndent
    }

    if($LogScenario -match 'TerminateFunction'){
        New-LogEntry "Serious issue in a function" -Type Terminate
    }

    "This is some output"
}

<#
psedit "C:\Users\$env:USERNAME\OneDrive\Dokumentumok\WindowsPowerShell\Modules\DummyModule\DummyModule.psm1"
psedit "C:\Users\$env:USERNAME\OneDrive\Dokumentumok\WindowsPowerShell\Modules\ScriptTools\1.0.0\ScriptTools.psm1"
cd C:\Users\$env:USERNAME\OneDrive\PS\PSConfEU
dir .\logs | remove-item

$psISE.CurrentPowerShellTab.Files.RemoveAt(0)

10..20 | foreach-object{
    $newfile = new-item -path .\Logs -Name "DemoLog.ps1-202501$_.log" -ItemType File
    $newfile.LastWriteTime = [datetime] "2025.01.$_"
}

ii .\logs

Import-Module ScriptTools -Force
Import-Module DummyModule -Force

cls
#>

######################################################################################
#
# Body
# 
######################################################################################

Import-Module .\ScriptTools.psd1 -Force

if($LogScenario -match 'AlternateLog'){
    $LogName = Initialize-Logging -Title "Logging Demo" -Verbose -BySeconds
}
elseif($LogScenario -match 'SimulateRunbook'){
    $LogName = Initialize-Logging -Title "Logging Demo" -Verbose -simulateRunbook
}
elseif($LogScenario -match 'Silent'){
    $LogName = Initialize-Logging -Title "Logging Demo"
}
else{
    $LogName = Initialize-Logging -Title "Logging Demo" -Verbose
}

Import-Module .\DummyModule\DummyModule.psm1 -Force -ArgumentList $LogName

$a = "VARIABLE-DEFINED-IN-SCRIPT"
$PSBoundParameters.a = $a

New-LogEntry "This is a simple info"

if($LogScenario -match 'TerminateMain'){
    New-LogEntry "Some serious issue" -Type Terminate -ExitCode 33
}

if($LogScenario -match 'Verbose|Silent'){
    New-LogEntry "This is a detail entry" -IndentLevel 1 -Verbose

    New-LogEntry "Call stack item of the script:"
    (Get-PSCallStack)[0] | Format-LogStringList | New-LogEntry -IndentLevel 1
}

if($LogScenario -match 'Warning|SimulateRunbook'){
    New-LogEntry "This is a warning" -Type Warning
}

if($LogScenario -match 'Error|SimulateRunbook'){
    New-LogEntry "This is some error" -Type Error
}

if($LogScenario -match 'Unhandled'){
    Remove-Item -Path c:\nonexistent\dummy.txt
}

SubFunction

if($LogScenario -match 'Verbose|Silent|SimulateRunbook'){
    New-LogEntry "This is a highlighted entry" -Type Highlight
}

if($LogScenario -match 'ProgressBar|SimulateRunbook'){
    $array = 1..200 | ForEach-Object {Get-Random -Minimum 1 -Maximum 10000}

    foreach($a in $array){
        # Write-Progress -Activity "Processing element $a..." -Status "Processing..." -PercentComplete ($x/100) -SecondsRemaining ($calculate.the.seconds) -
        Write-LogProgress -InputArray $array -Action "Processing element $a..." -ProgressLogFirst 10
        Start-Sleep -Milliseconds 60
    }
}

$object1 = [PSCustomObject] @{
                One = 1
                Two = "Some text"
                Three = get-date
                Four = 11,22,33,44,55
                Empty = $null
                Secret = "This is a password"
            }

$object2 = [PSCustomObject] @{
                One = 2
                Two = "Some text 2"
                Three = get-date
                Four = 19,28,37,46
                Empty = $null
                Secret = "This is another password"
            }

if($LogScenario -match 'OutputObject'){
    New-LogEntry "List view:"
    $object1, $object2 | Format-LogStringList -Divide -HideNulls -HideProperty Secret | New-LogEntry -IndentLevel 1

    New-LogEntry "Table view:"
    $object1, $object2 | Format-LogStringTable -ExcludeProperty Secret | New-LogEntry -IndentLevel 1
}

if($LogScenario -match 'OutputFile'){
    $csv = New-LogFile -Name "exportdata.csv"
    New-LogEntry "Data is exported to '$csv'..."

    $object1, $object2 | Export-Csv -Path $csv -NoTypeInformation -Encoding Default
    psedit -filenames $csv
}

if($LogScenario -match "AlternateLog"){
    $mainLog = $LogName

    $LogName = Initialize-Logging -Title "This is another log file" -Name Item.log -datePart RITM1234567 -Verbose
    New-LogEntry "This is an entry in alternate log file" 
}

if($LogScenario -match 'ModuleLogging'){
    $result = Get-DMInfo
    New-LogEntry "Result of module function: $result"
}

if($LogScenario -match "AlternateLog"){
    New-LogFooter

    psedit $logging.$LogName.LogPath

    $LogName = $mainLog
    $PSBoundParameters.LogName = $LogName # HERE'S THE KEY STEP FOR MODULE FUNCTIONS!!!!
    New-LogEntry "This is an entry in the main log again"
}

if($LogScenario -match 'SimulateRunbook'){
    Wait-Debugger
}

if($LogScenario -match 'AlternateLog'){
    if($LogScenario -match '^\d{2}AlternateLog'){
        Invoke-Item $logging.$LogName.LogFolder
        Wait-Debugger

        $file = $psISE.CurrentPowerShellTab.Files | Where-Object {$_.DisplayName -match '^Item-'}
        [void] $psISE.CurrentPowerShellTab.Files.Remove($file)
    }

    New-LogEntry "Normal exit from the script" -Type Exit -IgnoreLog
}
else{
    New-LogEntry "Normal exit from the script" -Type Exit
} 

Write-Host "This will never get executed, it's after the 'exit'" -ForegroundColor Yellow