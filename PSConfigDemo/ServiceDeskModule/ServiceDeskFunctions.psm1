param(
    [ValidateSet('Prod', 'Dev', 'Test')][string] $ServiceDeskEnvironment = 'Test'
)

#region Function definitions

function Get-SDData {
    $global:psconfig.ServiceDeskConfig.SDServer
}

function Update-SDConfig {
param(
    [ValidateSet('Prod', 'Dev', 'Test')][string] $ServiceDeskEnvironment = 'Test',
    [switch] $Force
)
    Update-Config -Environment $ServiceDeskEnvironment -prefix ServiceDesk -Force:$Force
}

#endregion

#region Config management
if(!(Get-Variable -Name PSConfig -ErrorAction Ignore -Scope Global)){
    $global:psconfig = @{}
}

Update-SDConfig -ServiceDeskEnvironment $ServiceDeskEnvironment -Force

#endregion