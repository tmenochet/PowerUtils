function Invoke-UserSniper {
<#
.SYNOPSIS
    Find logon machine(s) of a specific user in Active Directory
    Author: Timothée MENOCHET (@synetis)

.DESCRIPTION
    Invoke-UserSniper queries domain contollers for logon events matching a target user.

.PARAMETER Identity
    Specify the target user to search for.

.PARAMETER DomainController
    Specify a specific domain controller to query.

.PARAMETER Credential
    Specify the privileged account to use (typically Domain Admin).

.EXAMPLE
    PS C:\> . .\Invoke-UserSniper.ps1
    PS C:\> Invoke-UserSniper -Identity john.doe

.EXAMPLE
    PS C:\> Invoke-UserSniper -Identity john.doe -Domain ADATUM.CORP -Credential ADATUM\Administrator
#>

	Param (
		[Parameter(Mandatory=$true)]
		[ValidateNotNullOrEmpty()]
		[String]
		$Identity,

		[ValidateNotNullOrEmpty()]
		[String]
		$DomainController,

		[ValidateNotNullOrEmpty()]
		[System.Management.Automation.PSCredential]
		[System.Management.Automation.Credential()]
		$Credential = [System.Management.Automation.PSCredential]::Empty
	)

	$DomainControllers = @()
	If ($DomainController) {
		$DomainControllers += $DomainController
	} Else {
		$Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().name
		$DN = "DC=$($Domain.Replace('.', ',DC='))"
		$SearchString = "LDAP://" + $DN
		$Filter = "(userAccountControl:1.2.840.113556.1.4.803:=8192)"
		If ($Credential.UserName) {
			$DomainObject = New-Object System.DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
			$Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
		} Else {
			$Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
		}
		$Searcher.filter = $Filter
		Try {
			$Results = $Searcher.FindAll()
			$Results | Where-Object {$_} | ForEach-Object {
				$Up = Test-Connection -Count 1 -Quiet -ComputerName $_.properties.dnshostname
				if($Up) {
					$DomainControllers += $_.properties.dnshostname
				}
			}
			$Results.dispose()
			$Searcher.dispose()
		} Catch {
			Write-Warning "Error: $_"
		}
	}

	$Props = @{Name='Domain';Expression={$_.Properties[6].Value}}, `
		 @{Name='sAMAccountName';Expression={$_.Properties[5].Value}}, `
		 @{Name='IpAddress';Expression={$_.Properties[18].Value}}, `
		 @{Name='HostName';Expression={$_.Properties[11].Value}}, `
		 @{Name='LogonProcess';Expression={$_.Properties[9].Value}}
	ForEach ($DomainController in $DomainControllers) {
		$Params = @{
			'Computername' = $DomainController
			'LogName' = 'Security'
			'FilterXPath' = "*[System[EventID=4624] and EventData[Data[@Name='TargetUserName']='$Identity']]"
			'MaxEvents' = 10
		}
		Get-WinEvent @Params -Credential $Credential | Select-Object -Property  $Props | Sort-Object -Property 'IpAddress' -Unique
	}
}