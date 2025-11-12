param(
    [ValidateSet('UAT', 'Prod')] [string] $PAMEnvironment = 'UAT'
)

#region Function definitions

function Get-PAMData {
    $global:psconfig.PAMConfig.PAMServer
}

function Update-PAMConfig {
param(
    [ValidateSet('UAT', 'Prod')] [string] $PAMEnvironment = 'UAT',
    [switch] $Force
)
    Update-Config -Environment $PAMEnvironment -prefix PAM -Force:$Force
}
#endregion

#region Config management
if(!(Get-Variable -Name PSConfig -ErrorAction Ignore -Scope Global)){
    $global:psconfig = @{}
}

Update-PAMConfig -PAMEnvironment $PAMEnvironment -Force

#endregion