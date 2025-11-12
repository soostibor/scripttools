
$result =[pscustomobject] @{
                Status = 'Success'
                Value  = 123
                StatusText = "Value was successfully captured"
                Array = "a", "b", "c"
                Date = Get-Date
                True =  $true
                Decimal = [decimal] 1234567890
                DeepStruct = @{
                    Level1 = @{
                        Level2 = @{
                            Level3 = @{
                                Data1 = 'First data'
                            },
                            @{
                                Data2 = 'Second data'
                            }
                        }
                    }
                }
            }

Write-Host "`$result converted to PSData:" -ForegroundColor DarkGreen -BackgroundColor Yellow
ConvertTo-PSData -Object $result

Write-Host "`$result converted to compressed PSData:" -ForegroundColor DarkGreen -BackgroundColor Yellow
$compressedDataString = ConvertTo-PSData -Object $result -Compress

$compressedDataString

Write-Host "compressed data back to object:" -ForegroundColor DarkGreen -BackgroundColor Yellow
$resolvedData = ConvertFrom-PSData -PSDataString $compressedDataString
Expand-PSData -Object $resolvedData -MaxDepth 10

Export-PSData 