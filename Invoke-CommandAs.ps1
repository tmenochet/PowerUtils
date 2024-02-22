Function Invoke-CommandAs {
<#
.SYNOPSIS
    Invoke PowerShell script block as an account logged on a remote computer.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-CommandAs runs PowerShell script block on remote computer via scheduled task and retrieves output via a named pipe.

.PARAMETER ComputerName
    Specifies the target host.

.PARAMETER Credential
    Specifies the privileged account to use for remote connection.

.PARAMETER Authentication
    Specifies what authentication method should be used.

.PARAMETER Protocol
    Specifies the protocol to use, defaults to DCOM.

.PARAMETER Timeout
    Specifies the duration to wait for a response from the target host (in seconds), defaults to 3.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ArgumentList
    Specifies the PowerShell script block arguments.

.PARAMETER Identity
    Specifies the accounts to use for remote execution, defaults to all logged on users.

.EXAMPLE
    PS C:\> Invoke-CommandAs -ComputerName SRV.ADATUM.CORP -Credential ADATUM\Administrator -ScriptBlock {whoami} -Identity 'ADATUM\testuser'
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
        $Protocol = 'Dcom',

        [Int]
        $Timeout = 3,

        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock,

        [Object[]]
        $ArgumentList,

        [String[]]
        $Identity = '*'
    )

    Begin {
        # Init variables
        $cimOption = New-CimSessionOption -Protocol $Protocol

        if ($Credential.UserName) {
            $logonToken = Invoke-UserImpersonation -Credential $Credential
        }
    }

    Process {
        # Init remote session
        try {
            if (-not $PSBoundParameters['ComputerName']) {
                $cimSession = New-CimSession -SessionOption $cimOption -ErrorAction Stop -Verbose:$false -OperationTimeoutSec $Timeout
            }
            elseif ($Credential.Username) {
                $cimSession = New-CimSession -ComputerName $ComputerName -Credential $Credential -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false -OperationTimeoutSec $Timeout
            }
            else {
                $cimSession = New-CimSession -ComputerName $ComputerName -Authentication $Authentication -SessionOption $cimOption -ErrorAction Stop -Verbose:$false -OperationTimeoutSec $Timeout
            }
        }
        catch [System.Management.Automation.PSArgumentOutOfRangeException] {
            Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
            return
        }
        catch [Microsoft.Management.Infrastructure.CimException] {
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x8033810c,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Warning "Alternative authentication method and/or protocol should be used with implicit credentials."
                return
            }
            if ($Error[0].FullyQualifiedErrorId -eq 'HRESULT 0x80070005,Microsoft.Management.Infrastructure.CimCmdlets.NewCimSessionCommand') {
                Write-Verbose "[$ComputerName] Access denied."
                return
            }
            else {
                Write-Verbose "[$ComputerName] Failed to establish CIM session."
                return
            }
        }

        $loggedonUsers = @()
        if ($Identity -eq '*') {
            Get-CimInstance -ClassName Win32_LogonSession -CimSession $cimSession -Verbose:$false | Where-Object {$_.LogonType -ne 3} | ForEach-Object {
                $session = $_
                try {
                    $loggedonUsers += (Get-CimAssociatedInstance -InputObject $session -Association Win32_LoggedOnUser -CimSession $cimSession -ErrorAction Stop -Verbose:$false).Name
                }
                catch [Microsoft.Management.Infrastructure.CimException] {
                    break
                }
            }
            $loggedonUsers = $loggedonUsers | Select -Unique
        }
        else {
            $loggedonUsers += $Identity
        }

        foreach ($loggedonUser in $loggedonUsers) {
            # Init named pipe client
            $pipeTimeout = 10000 # 10s
            $pipename = [guid]::NewGuid().Guid
            $pipeclient = New-Object IO.Pipes.NamedPipeClientStream($ComputerName, $pipename, [IO.Pipes.PipeDirection]::InOut, [IO.Pipes.PipeOptions]::None, [Security.Principal.TokenImpersonationLevel]::Impersonation)

            # Build loader
            $loader = ''
            $loader += '$s = New-Object IO.Pipes.NamedPipeServerStream(''' + $pipename + ''', 3); '
            $loader += '$s.WaitForConnection(); '
            $loader += '$r = New-Object IO.StreamReader $s; '
            $loader += '$x = ''''; '
            $loader += 'while (($y=$r.ReadLine()) -ne ''''){$x+=$y+[Environment]::NewLine}; '
            $loader += '$z = [ScriptBlock]::Create($x); '
            $loader += '& $z'
            $argument = '-NoP -NonI -W 1 -C "' + $loader + '"'

            # Build payload
            $script = ''
            $script += '[ScriptBlock]$scriptBlock = {' + $ScriptBlock.Ast.Extent.Text + '}' + [Environment]::NewLine -replace '{{','{' -replace '}}','}'
            if ($ArgumentList) {
                $args = $ArgumentList -join ','
                $script += '$args = ' + $args + [Environment]::NewLine
            }
            else {
                $script += '$args = $null' + [Environment]::NewLine
            }
            $script += '$output = [Management.Automation.PSSerializer]::Serialize(((New-Module -ScriptBlock $scriptBlock -ArgumentList $args -ReturnResult) *>&1))' + [Environment]::NewLine
            $script += '$encOutput = [char[]]$output' + [Environment]::NewLine
            $script += '$writer = [IO.StreamWriter]::new($s)' + [Environment]::NewLine
            $script += '$writer.AutoFlush = $true' + [Environment]::NewLine
            $script += '$writer.WriteLine($encOutput)' + [Environment]::NewLine
            $script += '$writer.Dispose()' + [Environment]::NewLine
            $script += '$r.Dispose()' + [Environment]::NewLine
            $script += '$s.Dispose()' + [Environment]::NewLine
            $script = $script -creplace '(?m)^\s*\r?\n',''
            $payload = [char[]] $script

            # Create scheduled task
            try {
                $taskParameters = @{
                    TaskName = [guid]::NewGuid().Guid
                    Action = New-ScheduledTaskAction -WorkingDirectory "%windir%\System32\WindowsPowerShell\v1.0\" -Execute "powershell" -Argument $argument
                    Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
                    Principal = New-ScheduledTaskPrincipal -UserID $loggedonUser -LogonType Interactive -RunLevel Highest -CimSession $cimSession
                }
                Write-Verbose "Registering scheduled task $($taskParameters.TaskName)"
                $scheduledTask = Register-ScheduledTask @taskParameters -CimSession $cimSession -ErrorAction Stop
                Write-Verbose "Running scheduled task as $loggedonUser"
                $cimJob = $scheduledTask | Start-ScheduledTask -AsJob -ErrorAction Stop

                Write-Verbose "Connecting to named pipe server \\$ComputerName\pipe\$pipename"
                $pipeclient.Connect($pipeTimeout)
                $writer = New-Object  IO.StreamWriter($pipeclient)
                $writer.AutoFlush = $true
                $writer.WriteLine($payload)
                $reader = New-Object IO.StreamReader($pipeclient)
                $output = ''
                while (($data = $reader.ReadLine()) -ne $null) {
                    $output += $data + [Environment]::NewLine
                }
                Write-Output ([Management.Automation.PSSerializer]::Deserialize($output))

                $scheduledTaskInfo = $scheduledTask | Get-ScheduledTaskInfo
                if ($scheduledTaskInfo.LastRunTime.Year -ne (Get-Date).Year) { 
                    Write-Warning "Failed to execute scheduled task."
                }
            }
            catch { 
                Write-Error "Task execution failed. $_"
            }
            finally {
                if ($reader) {
                    $reader.Dispose()
                }
                $pipeclient.Dispose()

                Write-Verbose "Unregistering scheduled task $($taskParameters.TaskName)"
                if ($Protocol -eq 'Wsman') {
                    $scheduledTask | Get-ScheduledTask -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$False | Out-Null
                }
                else {
                    $scheduledTask | Get-ScheduledTask -ErrorAction SilentlyContinue | Unregister-ScheduledTask | Out-Null
                }
            }
        }
    }

    End {
        # End remote session
        if ($cimSession) {
            Remove-CimSession -CimSession $cimSession
        }

        if ($logonToken) {
            Invoke-RevertToSelf -TokenHandle $logonToken
        }
    }
}

Function Local:Get-DelegateType {
    Param (
        [Type[]]
        $Parameters = (New-Object Type[](0)),

        [Type]
        $ReturnType = [Void]
    )
    $domain = [AppDomain]::CurrentDomain
    $dynAssembly = New-Object Reflection.AssemblyName('ReflectedDelegate')
    $assemblyBuilder = $domain.DefineDynamicAssembly($dynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
    $moduleBuilder = $assemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
    $typeBuilder = $moduleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [MulticastDelegate])
    $constructorBuilder = $typeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [Reflection.CallingConventions]::Standard, $Parameters)
    $constructorBuilder.SetImplementationFlags('Runtime, Managed')
    $methodBuilder = $typeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
    $methodBuilder.SetImplementationFlags('Runtime, Managed')
    Write-Output $typeBuilder.CreateType()
}

Function Local:Get-ProcAddress {
    Param (
        [Parameter(Mandatory = $True)]
        [String]
        $Module,

        [Parameter(Mandatory = $True)]
        [String]
        $Procedure
    )
    $systemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
    $unsafeNativeMethods = $systemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
    $getModuleHandle = $unsafeNativeMethods.GetMethod('GetModuleHandle')
    $getProcAddress = $unsafeNativeMethods.GetMethod('GetProcAddress', [Type[]]@([Runtime.InteropServices.HandleRef], [String]))
    $kern32Handle = $getModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $handleRef = New-Object Runtime.InteropServices.HandleRef($tmpPtr, $kern32Handle)
    Write-Output $getProcAddress.Invoke($null, @([Runtime.InteropServices.HandleRef]$handleRef, $Procedure))
}

Function Local:Invoke-UserImpersonation {
    Param(
        [Parameter(Mandatory = $True)]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential
    )

    $logonUserAddr = Get-ProcAddress Advapi32.dll LogonUserA
    $logonUserDelegate = Get-DelegateType @([String], [String], [String], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
    $logonUser = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($logonUserAddr, $logonUserDelegate)

    $impersonateLoggedOnUserAddr = Get-ProcAddress Advapi32.dll ImpersonateLoggedOnUser
    $impersonateLoggedOnUserDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $impersonateLoggedOnUser = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($impersonateLoggedOnUserAddr, $impersonateLoggedOnUserDelegate)

    $logonTokenHandle = [IntPtr]::Zero
    $networkCredential = $Credential.GetNetworkCredential()
    $userDomain = $networkCredential.Domain
    $userName = $networkCredential.UserName

    if (-not $logonUser.Invoke($userName, $userDomain, $networkCredential.Password, 9, 3, [ref]$logonTokenHandle)) {
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[UserImpersonation] LogonUser error: $(([ComponentModel.Win32Exception] $lastError).Message)"
    }

    if (-not $impersonateLoggedOnUser.Invoke($logonTokenHandle)) {
        throw "[UserImpersonation] ImpersonateLoggedOnUser error: $(([ComponentModel.Win32Exception] $lastError).Message)"
    }
    Write-Output $logonTokenHandle
}

Function Local:Invoke-RevertToSelf {
    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    $closeHandleAddr = Get-ProcAddress Kernel32.dll CloseHandle
    $closeHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $closeHandle = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($closeHandleAddr, $closeHandleDelegate)

    $revertToSelfAddr = Get-ProcAddress Advapi32.dll RevertToSelf
    $revertToSelfDelegate = Get-DelegateType @() ([Bool])
    $revertToSelf = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($revertToSelfAddr, $revertToSelfDelegate)

    if ($PSBoundParameters['TokenHandle']) {
        $closeHandle.Invoke($TokenHandle) | Out-Null
    }
    if (-not $revertToSelf.Invoke()) {
        $lastError = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "[RevertToSelf] Error: $(([ComponentModel.Win32Exception] $lastError).Message)"
    }
}
