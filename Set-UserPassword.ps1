function Set-UserPassword {	
<#
.SYNOPSIS
    Change the password of a given Active Directory account.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Set-UserPassword renews the password of an Active Directory account, using its current password (expired or not).
    The code is highly inspired from Set-PasswordRemotely by @chryzsh.

.PARAMETER Server
    Specifies the domain controller to query.

.PARAMETER UserName
    Specifies the account name to use (sAMAccountName without domain name or NetBIOS name).

.PARAMETER CurrentPassword
    Specifies the current password of the account.

.PARAMETER NewPassword
    Specifies the new password to set.

.EXAMPLE
    PS C:\> Set-UserPassword

.EXAMPLE
    PS C:\> Set-UserPassword -Server dc.adatum.corp -UserName testuser -CurrentPassword P@ssw0rd -NewPassword Str0ngP@ssw0rd
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $Server = $Env:USERDNSDOMAIN,

        [ValidateNotNullOrEmpty()]
        [String]
        $UserName,

        [String]
        $CurrentPassword,

        [String]
        $NewPassword
    )
	
    $DllImport = @'
[DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
public static extern bool NetUserChangePassword(string domain, string username, string currentPassword, string newpassword);
'@
    $NetApi32 = Add-Type -MemberDefinition $DllImport -Name 'NetApi32' -Namespace 'Win32' -PassThru

    if (-not $PSBoundParameters.ContainsKey('CurrentPassword')) {
        $currentPasswordSecure = Read-Host "Current password" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($currentPasswordSecure)
        $CurrentPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }

    if (-not $PSBoundParameters.ContainsKey('NewPassword')) {
        $newPasswordSecure = Read-Host "New password" -AsSecureString
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($newPasswordSecure)
        $NewPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
    }

    if ($NetApi32::NetUserChangePassword($Server, $UserName, $CurrentPassword, $NewPassword)) {
        Write-Error "Password change failed on $Server."
    }
    else {
        Write-Host "Password change succeeded on $Server."
    }
}
