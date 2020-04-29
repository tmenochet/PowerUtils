function Get-LdapPassword {
<#
.SYNOPSIS
    Retrieve plaintext passwords from Active Directory.

    Author: Timothee MENOCHET (@TiM0)

.DESCRIPTION
    Get-LdapPassword queries domain controller via LDAP protocol for accounts with sensitive data in Description attribute and common attributes containing passwords (UnixUserPassword, UserPassword, msSFU30Password, unicodePwd, or ms-MCS-AdmPwd).

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specify the domain account to use.

.PARAMETER Keywords
    Specify specific keywords to search for.

.EXAMPLE
    PS C:\> Get-LdapPassword -Server ADATUM.CORP -Credential ADATUM\testuser

.EXAMPLE
    PS C:\> Get-LdapPassword -Server ADATUM.CORP -Keywords pw,mdp
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Keywords = @("cred", "pass", "pw")
    )

    $searchString = "LDAP://$Server/RootDSE"
    $domainObject = New-Object System.DirectoryServices.DirectoryEntry($searchString, $null, $null)
    $rootDN = $domainObject.rootDomainNamingContext[0]
    $ADSpath = "LDAP://$Server/$rootDN"

    # Search for passwords in description attribute
    $filter = $null
    ForEach ($keyword in $Keywords) {
        $filter += "(description=*$keyword*)"
    }
    $filter = "(&(objectClass=user)(|$filter))"
    $accounts = Get-LdapObject -ADSpath $ADSpath -Filter $filter -Properties samAccountName,description -Credential $Credential
    ForEach ($account in $accounts) {
        if ($account.description) {
            $password = $account.description
            $result = New-Object PSObject                                       
            $result | Add-Member Noteproperty SamAccountName $account.sAMAccountName
            $result | Add-Member Noteproperty Attribute 'Description'
            $result | Add-Member Noteproperty Value $password
            $result
        }
    }

    # Search for encoded password attributes
    $filter = "(&(objectClass=user)(|(UnixUserPassword=*)(UserPassword=*)(msSFU30Password=*)(unicodePwd=*)(ms-MCS-AdmPwd=*)))"
    $accounts = Get-LdapObject -ADSpath $ADSpath -Filter $filter -Credential $Credential
    ForEach ($account in $accounts) {
        if ($account.UnixUserPassword) {
            $password = [System.Text.Encoding]::ASCII.GetString($account.UnixUserPassword)
            $result = New-Object PSObject                                       
            $result | Add-Member Noteproperty SamAccountName $account.sAMAccountName
            $result | Add-Member Noteproperty Attribute 'UnixUserPassword'
            $result | Add-Member Noteproperty Value $password
            $result
        }
        if ($account.UserPassword) {
            $password = [System.Text.Encoding]::ASCII.GetString($account.UserPassword)
            $result = New-Object PSObject                                       
            $result | Add-Member Noteproperty SamAccountName $account.sAMAccountName
            $result | Add-Member Noteproperty Attribute 'UserPassword'
            $result | Add-Member Noteproperty Value $password
            $result
        }
        if ($account.msSFU30Password) {
            $password = [System.Text.Encoding]::ASCII.GetString($account.msSFU30Password)
            $result = New-Object PSObject                                       
            $result | Add-Member Noteproperty SamAccountName $account.sAMAccountName
            $result | Add-Member Noteproperty Attribute 'msSFU30Password'
            $result | Add-Member Noteproperty Value $password
            $result
        }
        if ($account.unicodePwd) {
            $password = [System.Text.Encoding]::ASCII.GetString($account.unicodePwd)
            $result = New-Object PSObject                                       
            $result | Add-Member Noteproperty SamAccountName $account.sAMAccountName
            $result | Add-Member Noteproperty Attribute 'unicodePwd'
            $result | Add-Member Noteproperty Value $password
            $result
        }
        if ($account.'ms-MCS-AdmPwd') {
            if ($account.'ms-MCS-AdmPwdExpirationTime' -ge 0) {
                $expiration = $([datetime]::FromFileTime([convert]::ToInt64($account.'ms-MCS-AdmPwdExpirationTime',10)))
            }
            else{
                $expiration = 'N/A'
            }
            $result = New-Object PSObject
            $result | Add-Member Noteproperty SamAccountName $account.sAMAccountName
            $result | Add-Member Noteproperty Attribute 'ms-MCS-AdmPwd'
            $result | Add-Member Noteproperty Value $account.'ms-MCS-AdmPwd'
            $result | Add-Member Noteproperty Expiration $expiration
        }
    }
}

function Local:Get-LdapObject {
    Param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ADSpath,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Filter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties = '*',

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200,

        [ValidateNotNullOrEmpty()]
        [System.Management.Automation.PSCredential]
        [System.Management.Automation.Credential()]
        $Credential = [System.Management.Automation.PSCredential]::Empty
    )

    if ($Credential.UserName) {
        $domainObject = New-Object System.DirectoryServices.DirectoryEntry($ADSpath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($domainObject)
    }
    else {
        $searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$ADSpath)
    }
    $searcher.PageSize = $PageSize
    $searcher.CacheResults = $false
    $searcher.filter = $Filter
    $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
    $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
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
        Write-Error $_ -ErrorAction Stop
    }
}
