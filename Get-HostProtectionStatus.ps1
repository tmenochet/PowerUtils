function Get-HostProtectionStatus
{
<#
.SYNOPSIS
    Get remote host protection status.

    Author: Timothée MENOCHET (@synetis)

.DESCRIPTION
    Get-HostProtectionStatus queries a remote host though WMI about firewall and antivirus products.

.PARAMETER ComputerName
    Specify the target host.

.PARAMETER Credential
    Specify the privileged account to use.

.EXAMPLE
    PS C:\> Import-Module .\Get-HostProtectionStatus.ps1
    PS C:\> Get-HostProtectionStatus -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator
#>

	Param (
		[ValidateNotNullOrEmpty()]
		[String]
		$ComputerName = $env:COMPUTERNAME,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	# Get antivirus status
	$Command = 'powershell -W Hidden -NonI -NoP -Command "Get-MpComputerStatus | Select-Object -Property PSComputername,Antivirusenabled,AntivirusSignatureLastUpdated,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled | Export-CSV C:\Windows\Temp\out.csv -NoTypeInformation -Encoding UTF8"'
	$Process = Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $Command -ComputerName $ComputerName -Credential $Credential
	$ProcessId = $Process.ProcessId
	Do 
	{
		Start-Sleep -m 250
	}
	Until ((Get-WMIobject -Class Win32_process -Filter "ProcessId='$ProcessId'" -ComputerName $ComputerName -Credential $Credential | Where {$_.Name -eq "powershell.exe"}).ProcessID -eq $null)
	New-PSDrive -Name "S" -Root "\\$ComputerName\c$" -Credential $Credential -PSProvider "FileSystem" | Out-Null
	$MpComputerStatus = Import-CSV -Path S:\Windows\Temp\out.csv
	Remove-Item S:\Windows\Temp\out.csv
	Remove-PSDrive S

	# Get firewall status
	[uint32]$Hive = 2147483650
	$Key = 'SYSTEM\\CurrentControlSet\\Services\\SharedAccess\\Parameters\\FirewallPolicy\\DomainProfile'
	$Value = 'EnableFirewall'
	$FirewallDomainProfileStatus = (Invoke-WmiMethod -Class StdRegProv -Name GetDWordValue -ArgumentList $Hive, $Key, $Value -ComputerName $ComputerName -Credential $Credential).uValue

	# If the host is a workstation, get AV product details
	$OSDetails = Get-WmiObject Win32_OperatingSystem -ComputerName $ComputerName -Credential $Credential
	If ($OSDetails.ProductType -eq 1) {
		$AntivirusDetails = Get-WmiObject -Namespace ROOT/SecurityCenter2 -Class AntiVirusProduct -ComputerName $ComputerName -Credential $Credential
		$AntispywareDetails = Get-WmiObject -Namespace ROOT/SecurityCenter2 -Class AntiSpywareProduct -ComputerName $ComputerName -Credential $Credential
		$FirewallDetails = Get-WmiObject -Namespace ROOT/SecurityCenter2 -Class FirewallProduct -ComputerName $ComputerName -Credential $Credential
	}

	$Result = New-Object -TypeName PSObject -Property ([ordered]@{
		'Host' = $ComputerName
		'AntiVirus-Product' = $AntivirusDetails.displayName
		'AntiVirus-Status' = $MpComputerStatus.AntivirusEnabled
		'AntiVirus-LastUpdate' = $MpComputerStatus.AntivirusSignatureLastUpdated
		'AntiMalware-Status' = $MpComputerStatus.AMServiceEnabled
		'AntiSpyware-Product' = $AntispywareDetails.displayName
		'AntiSpyware-Status' = $MpComputerStatus.AntispywareEnabled
		'BehaviorMonitor-Status' = $MpComputerStatus.BehaviorMonitorEnabled
		'OfficeProtection-Status' = $MpComputerStatus.IoavProtectionEnabled
		'NIS' = $MpComputerStatus.NISEnabled
		'OnAccessProtection-Status' = $MpComputerStatus.OnAccessProtectionEnabled
		'RealTimeProtection-Status' = $MpComputerStatus.RealTimeProtectionEnabled 
		'Firewall-Product' = $FirewallDetails.displayName
		'Firewall-DomainProfileStatus' = $FirewallDomainProfileStatus
	})
	Write-Output $Result
}