[ordered] @{
    ServiceDeskConfig = @{
        SDServer = "MyCompanyTest.ServiceNow.com"
    }

    Conditional_1_Environment = @{
        Condition = {$global:psconfig.ServiceDeskEnvironment -eq 'Dev'}
        ServiceDeskConfig = @{
            SDServer = 'MyCompanyDev.ServiceNow.com'
        }
    }

    Conditional_2_Environment = @{
        Condition = {$global:psconfig.ServiceDeskEnvironment -eq 'Prod'}
        ServiceDeskConfig = @{
            SDServer = 'MyCompany.ServiceNow.com'
        }
    }
}