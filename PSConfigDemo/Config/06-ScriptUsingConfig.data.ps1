@{
    ConfigAction_1 = {$script:cs = @(Get-PSCallStack)[-1].InvocationInfo.MyCommand.Path}

    ScriptData = [ordered] @{
        Name = "Tibor Soós"
        Email = "soos.tibor@hotmail.com"
        DynamicDate = {Get-Date}
        StaticDate = [DateTime] '2025.11.05'
        Environment = "Test"
        Array = 1,2,3,4
        ScriptBlock = {<#DontExpand#> get-date}
        HashTable = @{
            Key1 = 'One'
            Key2 = 'Two', 'Three'
        }
    }

    Conditional_1_EnvironmentProd = @{
        Condition = {$script:cs -match 'PSConfigDemoProd'}
        ScriptData = [ordered] @{
            Environment = "Prod"
        }
        ServiceDeskEnvironment = 'Prod'
        PAMEnvironment = 'Prod'
    }

    Conditional_2_EnvironmentDev = @{
        Condition = {$script:cs -match 'PSConfigDemo'}
        ScriptData = [ordered] @{
            Environment = "Dev"
        }
        ServiceDeskEnvironment = 'Test'
        PAMEnvironment = 'UAT'
    }

    Conditional_3_EnvironmentTest = @{
        Condition = {$script:cs -match 'PSConfigDemoTest'}
        ServiceDeskEnvironment = 'Test'
        PAMEnvironment = 'Prod'
    }

}