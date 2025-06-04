<#
.SYNOPSIS
    Collects various pieces of volatile system data for incident response.
.DESCRIPTION
    This script gathers live system information that can change quickly,
    including currently logged-on users, ARP cache entries, and DNS client cache.
    It can output this information to the console and optionally to a text file.
.PARAMETER OutputFilePath
    Optional. The full path to a text file where the collected volatile data will be saved.
    If not provided, output is to the console only.
.EXAMPLE
    .\Collect-VolatileData.ps1
    Displays collected volatile data to the console.
.EXAMPLE
    .\Collect-VolatileData.ps1 -OutputFilePath "C:\temp\VolatileData.txt"
    Displays the data and also saves it to C:\temp\VolatileData.txt.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
    Requires Administrator privileges for full access to all data sources.
    The DNS cache might only show entries resolved by the current user/process.
#>
param (
    [string]$OutputFilePath
)

$AllOutput = [System.Collections.Generic.List[string]]::new()

function Add-OutputSection {
    param(
        [string]$Title,
        [scriptblock]$ScriptBlock
    )
    $AllOutput.Add("`n--- $($Title) ---`n")
    Write-Host "`n--- $($Title) ---" -ForegroundColor Cyan
    try {
        $output = Invoke-Command -ScriptBlock $ScriptBlock -ErrorAction Stop
        if ($output) {
            $formattedOutput = $output | Out-String
            $AllOutput.Add($formattedOutput)
            Write-Output $output # Let PowerShell's default formatting handle console display for objects
        } else {
            $AllOutput.Add("No data found or command returned no output.`n")
            Write-Host "No data found for this section." -ForegroundColor Yellow
        }
    }
    catch {
        $errorMessage = "Error collecting $($Title): $($_.Exception.Message)`n"
        $AllOutput.Add($errorMessage)
        Write-Error $errorMessage.Trim()
    }
    $AllOutput.Add("`n")
}

Write-Host "Collecting Volatile System Data..." -ForegroundColor Yellow
$AllOutput.Add("Volatile Data Collection Report - $(Get-Date)`n")

# Current Date and Time
Add-OutputSection -Title "Current System Date and Time" -ScriptBlock { Get-Date }

# Logged-on Users (using Win32_LoggedOnUser and Win32_LogonSession)
Add-OutputSection -Title "Logged-On Users" -ScriptBlock {
    Get-CimInstance -ClassName Win32_LogonSession -ErrorAction SilentlyContinue | 
    Where-Object {$_.LogonType -in (2,10)} | # Interactive, RemoteInteractive
    ForEach-Object {
        $logonSession = $_
        Get-CimAssociatedInstance -InputObject $logonSession -ResultClassName Win32_LoggedOnUser -ErrorAction SilentlyContinue |
        ForEach-Object {
            $account = Get-CimInstance -CimInstance $_.Antecedent -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                UserName = "$($account.Domain)\$($account.Name)"
                LogonId = $logonSession.LogonId
                LogonType = switch ($logonSession.LogonType) {
                    2 {"Interactive"}
                    3 {"Network"}
                    4 {"Batch"}
                    5 {"Service"}
                    7 {"Unlock"}
                    8 {"NetworkCleartext"}
                    9 {"NewCredentials"}
                    10 {"RemoteInteractive"}
                    11 {"CachedInteractive"}
                    default {"Unknown ($($logonSession.LogonType))"}
                }
                LogonTime = $logonSession.StartTime # This is CIM DateTime
            }
        }
    } | Select-Object UserName, LogonType, LogonTime, LogonId | Sort-Object UserName | Format-Table -AutoSize
}

# ARP Cache (Get-NetNeighbor)
Add-OutputSection -Title "ARP Cache (Network Neighbors)" -ScriptBlock {
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | 
    Select-Object IPAddress, LinkLayerAddress, State, InterfaceAlias | 
    Format-Table -AutoSize
}

# DNS Client Cache
Add-OutputSection -Title "DNS Client Cache" -ScriptBlock {
    Get-DnsClientCache -ErrorAction SilentlyContinue | 
    Where-Object {$_.Status -eq 'Success'} | # Only show successfully resolved entries
    Select-Object Entry, Type, Data, Status, Section | 
    Sort-Object Entry | 
    Format-Table -AutoSize
}

# Running Processes (brief summary - more detail in Find-SuspiciousProcess.ps1)
Add-OutputSection -Title "Running Processes (Summary - Name, ID, Path)" -ScriptBlock {
    Get-Process -IncludeUserName -ErrorAction SilentlyContinue | 
    Select-Object Name, Id, Path, UserName | 
    Format-Table -AutoSize -Wrap
}


if ($PSBoundParameters.ContainsKey('OutputFilePath')) {
    try {
        Write-Host "`nSaving collected data to: $OutputFilePath" -ForegroundColor Yellow
        $AllOutput -join "" | Set-Content -Path $OutputFilePath -Encoding UTF8 -Force -ErrorAction Stop
        Write-Host "Successfully saved data to $OutputFilePath" -ForegroundColor Green
    }
    catch {
        Write-Error "Failed to save data to '$OutputFilePath': $($_.Exception.Message)"
    }
}

Write-Host "`nVolatile data collection complete." -ForegroundColor Yellow
