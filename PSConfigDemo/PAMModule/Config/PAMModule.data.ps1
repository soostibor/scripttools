[ordered] @{
    PAMConfig = @{
        PAMServer = "PAMTest.mycompany.com"
    }

    Conditional_2_Environment = @{
        Condition = {$global:psconfig.PAMEnvironment -eq 'Prod'}
        PAMConfig = @{
            PAMServer = 'PAM.mycompany.com'
        }
    }
}