param(
    $LogName
)

function Get-DMInfo {
    New-LogEntry "Log entry from DummyModule, value of `$a : $a" -type Warning

    $cs = Get-PSCallStack

    New-LogEntry "Value of `$a via `$PSBoundParameters : $($cs[1].InvocationInfo.BoundParameters.a)" -type Highlight 

    "$(Get-Date) - SomeReturnValue"
}

if($LogName){
    $LogName = Initialize-Logging -MergeTo $LogName
}
else{
    $global:LogName = Initialize-Logging -Title "Dummy Module is imported directly" -Verbose -Path $env:TEMP
}