<#
    Script to demo the use of config files
#>

$dir = $PSScriptRoot

Import-Module scripttools -Force

$global:psconfig = @{}

Import-PSData -PSData $global:psconfig 

Import-Module (join-path $dir 'ServiceDeskModule\ServiceDeskFunctions.psm1') -Force
Import-Module (join-path $dir PAMModule) -Force

Expand-PSData -Object $global:psconfig -MaxDepth 10 -LeafOnly

return
