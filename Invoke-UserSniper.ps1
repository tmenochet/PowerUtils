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

	$results = @()
	ForEach ($DomainController in $DomainControllers) {
		$FilterXPath = "*[System[EventID=4624] and EventData[Data[@Name='TargetUserName']='$Identity']]"
		If ($Credential.UserName) {
			$Username = $Credential.UserName
			$Password = $Credential.GetNetworkCredential().Password
			WevtUtil query-events Security /query:$FilterXPath /remote:$DomainController /username:$Username /password:$Password /format:XML | ForEach {
				[XML] $XML = ($_)
				$Status = $XML.Event.System.Keywords
				if ($Status -eq "0x8020000000000000") {
					$results += ParseEventLog($XML)
				}
			}
		} Else {
			WevtUtil query-events Security /query:$FilterXPath /remote:$DomainController /format:XML | ForEach {
				[XML] $XML = ($_)
				$Status = $XML.Event.System.Keywords
				if ($Status -eq "0x8020000000000000") {
					$results += ParseEventLog($XML)
				}
			}
		}
	}
	$results | Sort-Object -Property 'IpAddress' -Unique | Select TargetDomainName, TargetUserName, LogonType, IpAddress, WorkstationName
}

function ParseEventLog($XML) {
	$props = @{}
	$props.Add('DCEvent',$XML.Event.System.Computer)
	$props.Add('Date',$XML.Event.System.TimeCreated.SystemTime)
	$props.Add('EventId', $XML.Event.System.EventID)
	$props.Add('SubjectUserSid', $XML.Event.EventData.Data[0].'#text')
	$props.Add('SubjectUserName', $XML.Event.EventData.Data[1].'#text')
	$props.Add('SubjectDomainName', $XML.Event.EventData.Data[2].'#text')
	$props.Add('SubjectLogonId', $XML.Event.EventData.Data[3].'#text')
	$props.Add('TargetUserSid', $XML.Event.EventData.Data[4].'#text')
	$props.Add('TargetUserName', $XML.Event.EventData.Data[5].'#text')
	$props.Add('TargetDomainName', $XML.Event.EventData.Data[6].'#text')
	$props.Add('TargetLogonId', $XML.Event.EventData.Data[7].'#text')
	$props.Add('LogonType', $XML.Event.EventData.Data[8].'#text')
	$props.Add('LogonProcessName', $XML.Event.EventData.Data[9].'#text')
	$props.Add('AuthenticationPackageName', $XML.Event.EventData.Data[10].'#text')
	$props.Add('WorkstationName', $XML.Event.EventData.Data[11].'#text')
	$props.Add('LogonGuid', $XML.Event.EventData.Data[12].'#text')
	$props.Add('TransmittedServices', $XML.Event.EventData.Data[13].'#text')
	$props.Add('LmPackageName', $XML.Event.EventData.Data[14].'#text')
	$props.Add('KeyLength', $XML.Event.EventData.Data[15].'#text')
	$props.Add('ProcessId', $XML.Event.EventData.Data[16].'#text')
	$props.Add('ProcessName', $XML.Event.EventData.Data[17].'#text')
	$props.Add('IpAddress', $XML.Event.EventData.Data[18].'#text')
	$props.Add('IpPort', $XML.Event.EventData.Data[19].'#text')
	return New-Object -TypeName psobject -Property $props
}