<#
.SYNOPSIS
    Run PowerShell script on a remote host.

    Author: Timothée MENOCHET (@synetis)

.DESCRIPTION
    Invoke-PSScript run a PowerShell script on a remote host using WMI, and display output.

.PARAMETER ComputerName
    Specify the target host.

.PARAMETER Credential
    Specify the privileged account to use.

.PARAMETER FileName
    Specify the PowerShell script to run.

.EXAMPLE
    PS C:\> .\Invoke-PSScript.ps1 -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -FileName .\Script.ps1

.EXAMPLE
    PS C:\> .\Invoke-PSScript.ps1 -ComputerName SRV.ADATUM.CORP -FileName .\Script.ps1
#>

Param (
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $ComputerName,

    [ValidateNotNullOrEmpty()]
    [System.Management.Automation.PSCredential]
    [System.Management.Automation.Credential()]
    $Credential = [System.Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory=$true)]
	[ValidateNotNullOrEmpty()]
    [String]
    $FileName
)

# Encode the payload and run it
$EncScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes([System.IO.File]::ReadAllText((Resolve-Path $FileName))))
$Command = "powershell.exe -Command `"powershell -Exec Bypass -Nol -Enc $EncScript > C:\Windows\Temp\out.log`""
$Process = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $Command -ComputerName $ComputerName -Credential $Credential
$ProcessId = $Process.ProcessId
Do 
{
	Start-Sleep -m 250
}
Until ((Get-WMIobject -Class Win32_process -Filter "ProcessId='$ProcessId'" -ComputerName $ComputerName -Credential $Credential | Where {$_.Name -eq "powershell.exe"}).ProcessID -eq $null)

# Display the output and clean up
New-PSDrive -Name "S" -Root "\\$ComputerName\c$" -Credential $Credential -PSProvider "FileSystem" | Out-Null
Get-Content -Path S:\Windows\Temp\out.log
Remove-Item S:\Windows\Temp\out.log
Remove-PSDrive S
