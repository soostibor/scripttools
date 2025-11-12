$dir = $PSScriptRoot

Remove-Variable psconfig -ErrorAction Ignore

Import-Module ScriptTools -Force

$psconfig

Import-Module (join-path $dir PAMModule) -Force
Get-PAMData

Expand-PSData -Object $psconfig -MaxDepth 10

Import-Module (join-path $dir PAMModule) -Force -ArgumentList Prod
Get-PAMData

Update-PAMConfig
Get-PAMData

Update-PAMConfig -Force
Get-PAMData

Update-PAMConfig -PAMEnvironment Prod 
Get-PAMData

Import-Module (join-path $dir 'ServiceDeskModule\ServiceDeskFunctions.psm1') -Force
Get-SDData

Import-Module (join-path $dir 'ServiceDeskModule\ServiceDeskFunctions.psm1') -ArgumentList Dev
Get-SDData

Update-SDConfig -ServiceDeskEnvironment Prod 
Get-SDData

Expand-PSData -Object $psconfig -MaxDepth 5 -LeafOnly