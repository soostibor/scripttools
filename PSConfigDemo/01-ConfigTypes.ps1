$dir = $PSScriptRoot

. (Join-Path -Path $dir -ChildPath format-xml.ps1)

$data = @{
    number = 14
    string = 'this is a text'
    array = 1, 'bla'
    date = get-date
    date2 = [datetime] "2025.11.12"
    hash = @{
        Key1 = 1
        Key2 = 'foo'
    }
    object = [pscustomobject]@{
        Prop1 = 2
        Prop2 = 'bar'
    }

    expression = 1 + 2
}

######################
# 
# XML
# 
######################

$xmldata = ConvertTo-Xml -Depth 10 -InputObject $data
Format-XML -xml $xmldata 

######################
# 
# JSON
# 
######################

ConvertTo-Json -InputObject $data -Depth 10 

######################
# 
# YAML
# 
######################

Import-Module powershell-yaml
ConvertTo-Yaml -Data $data 

######################
# 
# PSD1
# 
######################

# ST:\PSConfigDemo\02-data.psd1

$data2 = Import-PowerShellDataFile -Path (join-path $dir 02-data.psd1)

######################
# 
# data.ps1
# 
######################

# ST:\PSConfigDemo\03-mydata.data.ps1

Import-Module ScriptTools -Force

$data2 = Import-PSData -PathsOrNames (join-path $dir 03-mydata.data.ps1) -PassThru
