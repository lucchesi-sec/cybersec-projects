<#
.SYNOPSIS
    Gathers comprehensive system information.
.DESCRIPTION
    This script collects various details about the local system,
    including OS version, hardware, running processes, services,
    and network configuration.
.EXAMPLE
    .\Get-SystemInfo.ps1
    Runs the script and outputs system information to the console.
.EXAMPLE
    .\Get-SystemInfo.ps1 -OutFile C:\temp\SystemInfo.txt
    Runs the script and saves the output to the specified file.
.NOTES
    Author: Your Name
    Date: $(Get-Date)
#>
param (
    [string]$OutFile
)

Write-Host "Gathering System Information..." -ForegroundColor Yellow

$output = @()

# Operating System Information
Write-Host "Collecting OS Information..."
$osInfo = Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, InstallDate, LastBootUpTime
$output += $osInfo | Format-List | Out-String

# Computer System Information
Write-Host "Collecting Computer System Information..."
$csInfo = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer, Model, TotalPhysicalMemory, NumberOfLogicalProcessors
$output += $csInfo | Format-List | Out-String

# Processor Information
Write-Host "Collecting Processor Information..."
$cpuInfo = Get-CimInstance -ClassName Win32_Processor | Select-Object Name, Manufacturer, MaxClockSpeed, NumberOfCores
$output += $cpuInfo | Format-List | Out-String

# Disk Information
Write-Host "Collecting Disk Information..."
$diskInfo = Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object {$_.DriveType -eq 3} | Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace
$output += $diskInfo | Format-Table | Out-String

# Network Adapter Configuration
Write-Host "Collecting Network Adapter Configuration..."
$netAdapterInfo = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled} | Select-Object Description, IPAddress, IPSubnet, DefaultIPGateway, MACAddress, DNSServerSearchOrder
$output += $netAdapterInfo | Format-List | Out-String

# Running Processes (Top 10 by CPU)
Write-Host "Collecting Top 10 Processes by CPU..."
$processes = Get-Process | Sort-Object CPU -Descending | Select-Object -First 10 | Select-Object Name, Id, CPU, WorkingSet
$output += $processes | Format-Table | Out-String

# Services (Running)
Write-Host "Collecting Running Services..."
$services = Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status
$output += $services | Format-Table | Out-String

# Output results
$finalOutput = $output -join "`r`n"

if ($OutFile) {
    Write-Host "Saving output to $OutFile..." -ForegroundColor Green
    $finalOutput | Out-File -FilePath $OutFile -Encoding UTF8
} else {
    Write-Host $finalOutput
}

Write-Host "System Information gathering complete." -ForegroundColor Green
