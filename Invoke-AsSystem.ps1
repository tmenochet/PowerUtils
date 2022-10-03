#requires -version 3

Function Invoke-AsSystem {
<#
.SYNOPSIS
    Invoke PowerShell script block as NT\AUTHORITY SYSTEM.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-AsSystem runs PowerShell script block on local computer via scheduled job.

.PARAMETER ScriptBlock
    Specifies the PowerShell script block to run.

.PARAMETER ArgumentList
    Specifies the PowerShell script block arguments.

.PARAMETER Method
    Specifies the execution method to use, defaults to ScheduledTask.

.EXAMPLE
    PS C:\> Invoke-AsSystem -ScriptBlock {whoami}
#>

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]
        $ScriptBlock,

        [Object[]]
        $ArgumentList,

        [ValidateSet('ScheduledTask', 'Service', 'Token')]
        [String]
        $Method = 'ScheduledTask'
    )

    try {
        $jobParameters = @{
            Name = [guid]::NewGuid().Guid
            ScheduledJobOption = New-ScheduledJobOption -StartIfOnBattery -ContinueIfGoingOnBattery
        }
        $jobArgumentList = @{
            ScriptBlock  = $ScriptBlock
            Using = @()
        }
        if ($ArgumentList) {
            $jobArgumentList['ArgumentList'] = $ArgumentList
        }
        $usingVariables = $ScriptBlock.ast.FindAll({$args[0] -is [Management.Automation.Language.UsingExpressionAst]},$True)
        if ($usingVariables) {
            $scriptText = $ScriptBlock.Ast.Extent.Text
            $scriptOffSet = $ScriptBlock.Ast.Extent.StartOffset
            foreach ($subExpression in ($usingVariables.SubExpression | Sort-Object { $_.Extent.StartOffset } -Descending)) {
                $name = '__using_{0}' -f (([Guid]::NewGuid().guid) -Replace '-')
                $expression = $subExpression.Extent.Text.Replace('$Using:','$').Replace('${Using:','${'); 
                $value = [Management.Automation.PSSerializer]::Serialize((Invoke-Expression $expression))
                $jobArgumentList['Using'] += [PSCustomObject]@{ Name = $name; Value = $value } 
                $scriptText = $scriptText.Substring(0, ($subExpression.Extent.StartOffSet - $scriptOffSet)) + "`${Using:$name}" + $scriptText.Substring(($subExpression.Extent.EndOffset - $scriptOffSet))
            }
            $jobArgumentList['ScriptBlock'] = [ScriptBlock]::Create($scriptText.TrimStart('{').TrimEnd('}'))
        }
        $jobScriptBlock = [ScriptBlock]::Create(@'
            Param($Parameters)
            $jobParameters = @{}
            if ($Parameters.ScriptBlock)  { $jobParameters['ScriptBlock']  = [ScriptBlock]::Create($Parameters.ScriptBlock) }
            if ($Parameters.ArgumentList) { $jobParameters['ArgumentList'] = $Parameters.ArgumentList }
            if ($Parameters.Using) { 
                $Parameters.Using | % { Set-Variable -Name $_.Name -Value ([Management.Automation.PSSerializer]::Deserialize($_.Value)) }
                Start-Job @JobParameters | Receive-Job -Wait -AutoRemoveJob
            }
            else {
                Invoke-Command @JobParameters
            }
'@)
        $scheduledJob = Register-ScheduledJob  @jobParameters -ScriptBlock $jobScriptBlock -ArgumentList $jobArgumentList -ErrorAction Stop

        switch ($Method) {
            'ScheduledTask' {
                Invoke-ScheduledTaskCmd -Command $scheduledJob.PSExecutionPath -Arguments $scheduledJob.PSExecutionArgs
            }
            'Service' {
                Invoke-ServiceCmd -Command $scheduledJob.PSExecutionPath -Arguments $scheduledJob.PSExecutionArgs
            }
            'Token' {
                Invoke-TokenCmd -Command $scheduledJob.PSExecutionPath -Arguments $scheduledJob.PSExecutionArgs
            }
        }

        $job = Get-Job -Name $scheduledJob.Name -ErrorAction SilentlyContinue
        if ($job) {
            $job | Wait-Job | Receive-Job -Wait -AutoRemoveJob
        }
    }
    catch { 
        Write-Error $_ 
    }
    finally {
        if ($scheduledJob) {
            Get-ScheduledJob -Id $scheduledJob.Id -ErrorAction SilentlyContinue | Unregister-ScheduledJob -Force -Confirm:$False | Out-Null
        }
    }
}

Function Local:Invoke-ScheduledTaskCmd {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [String]
        $Command,

        [String]
        $Arguments
    )
    try {
        $scheduleService = New-Object -ComObject ('Schedule.Service')
        $scheduleService.Connect()
        $scheduleTaskFolder = $scheduleService.GetFolder("\")
        $taskDefinition = $scheduleService.NewTask(0)
        $taskDefinition.Settings.StopIfGoingOnBatteries = $false
        $taskDefinition.Settings.DisallowStartIfOnBatteries = $false
        $taskName = [guid]::NewGuid().Guid
        $taskAction = $taskDefinition.Actions.Create(0)
        $taskAction.Path = $Command
        $taskAction.Arguments = $Arguments
        Write-Verbose "Registering scheduled task $taskName..."
        $registeredTask = $scheduleTaskFolder.RegisterTaskDefinition($taskName, $taskDefinition, 6, 'System', $null, 5)
        Write-Verbose "Running scheduled task..."
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
            Write-Error 'Task execution failed.'
            return 
        }
    }
    catch { 
        Write-Error "Task execution failed. $_"
    }
    finally {
        if ($scheduledTask) { 
            Write-Verbose "Unregistering scheduled task..."
            $scheduleTaskFolder.DeleteTask($scheduledTask.Name, 0) | Out-Null
        }
    }
}

Function Local:Invoke-ServiceCmd {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [String]
        $Command,

        [String]
        $Arguments
    )

    try  {
        $serviceName = [guid]::NewGuid().Guid
        $servicePath = "%COMSPEC% /c $Command $Arguments"
        Write-Verbose "Creating service $serviceName..."
        $result = Invoke-WmiMethod -Class Win32_Service -Name Create -ArgumentList @($false, $serviceName, 1, $null, $null, $serviceName, $servicePath, $null, 16, 'Manual', 'LocalSystem', ' ')
        if ($result.ReturnValue -eq 0) {
            Write-Verbose "Starting service..."
            $service = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
            $service.InvokeMethod('StartService', $null) | Out-Null
            do {
                Start-Sleep -Seconds 1
                $service = Get-WmiObject -Class Win32_Service -Filter "Name='$serviceName'"
            }
            until ($service.ExitCode -ne 1077 -or $service.State -ne 'Stopped')
        }
        else {
            Write-Error "Service creation failed ($($result.ReturnValue))."
        }
    }
    catch {
        Write-Error "Service execution failed. $_"
    }
    finally {
        if ($service) {
            Write-Verbose "Deleting service..."
            $service.InvokeMethod('Delete', $null) | Out-Null
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
        $Arguments
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

        $CreateProcessWithTokenWAddr = Get-ProcAddress advapi32.dll CreateProcessWithTokenW
        $CreateProcessWithTokenWDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
        $CreateProcessWithTokenW = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessWithTokenWAddr, $CreateProcessWithTokenWDelegate)

        $memsetAddr = Get-ProcAddress msvcrt.dll memset
        $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
        $memset = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)

        Function Local:Get-PrimaryToken {
            Param(
                [Parameter(Mandatory = $True)]
                [UInt32]
                $ProcessId
            )

            # 0x4 = TOKEN_IMPERSONATE
            # 0x2 = TOKEN_DUPLICATE
            $tokenPrivs = 0x4 -bor 0x2
            [IntPtr] $hToken = [IntPtr]::Zero

            # Get handle for the process
            # 0x400 = PROCESS_QUERY_INFORMATION
            $hProcess = $OpenProcess.Invoke(0x400, $False, $ProcessId)
            if ($hProcess -ne [IntPtr]::Zero) {
                # Get process token
                Write-Verbose "Getting primary token of process ID $ProcessId..."
                $retVal = $OpenProcessToken.Invoke(([IntPtr][Int] $hProcess), $tokenPrivs, [ref] $hToken)
                if (-not $retVal -or $hToken -eq [IntPtr]::Zero) {
                    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Verbose "Failed to get processes primary token. ProcessId: $ProcessId. ProcessName $((Get-Process -Id $ProcessId).Name). Error: $errorCode"
                }
                # Close handle
                if (-not $CloseHandle.Invoke($hProcess)) {
                    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Verbose "Failed to close process handle, this is unexpected. ErrorCode: $errorCode"
                }
                $hProcess = [IntPtr]::Zero
                return $hToken
            }
            return [IntPtr]::Zero
        }

        Function Local:Invoke-ProcessWithToken {
            Param(
                [Parameter(Mandatory=$true)]
                [IntPtr]
                $hToken,

                [Parameter()]
                [String]
                $CreateProcess,

                [Parameter()]
                [String]
                $ProcessArgs
            )

            $success = $False
            [IntPtr] $hDulicateToken = [IntPtr]::Zero

            # Duplicate the primary token
            Write-Verbose "Duplicating the process primary token..."
            # 0x02000000 = MAXIMUM_ALLOWED
            $retVal = $DuplicateTokenEx.Invoke($hToken, 0x02000000, [IntPtr]::Zero, 3, 1, [Ref] $hDulicateToken)
            if (-not $retVal) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Verbose "DuplicateTokenEx failed. Error code: $errorCode"
            }

            # Close handle for the primary token
            if (-not $CloseHandle.Invoke($hToken)) {
                $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                Write-Verbose "Failed to close token handle, this is unexpected. Error code: $errorCode"
            }
            if ($hDulicateToken -ne [IntPtr]::Zero) {
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

                Write-Verbose "Creating a new process with alternate token..."
                $retValue = $CreateProcessWithTokenW.Invoke($hDulicateToken, 0x0, $processNamePtr, $processArgsPtr, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
                if ($retValue) {
                    $processInfo = [Runtime.InteropServices.Marshal]::PtrToStructure($processInfoPtr, [Type] $PROCESS_INFORMATION)
                    $process = [Diagnostics.Process]::GetProcessById($processInfo.dwProcessId)
                    $process.WaitForExit()
                    # Free the handles returned in the ProcessInfo structure
                    $CloseHandle.Invoke($processInfo.hProcess) | Out-Null
                    $CloseHandle.Invoke($processInfo.hThread) | Out-Null
                }
                else {
                    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Warning "Process creation failed. Error code: $errorCode"
                }

                # Free StartupInfo memory and ProcessInfo memory
                [Runtime.InteropServices.Marshal]::FreeHGlobal($startupInfoPtr)
                [Runtime.InteropServices.Marshal]::FreeHGlobal($processInfoPtr)
                [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($processNamePtr)

                # Close handle for the token duplicated
                if (-not $CloseHandle.Invoke($hDulicateToken)) {
                    $errorCode = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    Write-Warning "CloseHandle failed to close NewHToken. Error code: $errorCode"
                }
                else {
                    $success = $True
                }
            }
            return $success
        }

        Function Local:Get-SystemToken {
            Param(
                [Parameter()]
                [String]
                $CreateProcess,

                [Parameter()]
                [String]
                $ProcessArgs
            )

            $success = $False
            $localSystemNTAccount = (New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([Security.Principal.WellKnownSidType]::'LocalSystemSid', $null)).Translate([Security.Principal.NTAccount]).Value

            # Enumerate processes
            Get-WmiObject -Class Win32_Process | ForEach-Object {
                if ($success) {
                    break
                }
                else {
                    $ownerInfo = $_.GetOwner()
                    $ownerString = "$($ownerInfo.Domain)\$($ownerInfo.User)".ToUpper()
                    if ($ownerString -eq $localSystemNTAccount.ToUpper()) {
                        try {
                            # Get primary token
                            $hToken = Get-PrimaryToken -ProcessId $_.ProcessId
                            # Impersonate user
                            if ($hToken -ne [IntPtr]::Zero) {
                                if ($success = Invoke-ProcessWithToken -hToken $hToken -CreateProcess $CreateProcess -ProcessArgs $ProcessArgs) {
                                    Write-Verbose "Process $($_.Name) (PID $($_.ProcessId)) impersonated!"
                                }
                            }
                        }
                        catch {
                            Write-Error $_
                        }
                    }
                }
            }
            if (-not $success) {
                Write-Error 'Unable to obtain a handle to a system process.'
            }
        }
    }

    Process {
        # Ensure token duplication works correctly
        if ([Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
            Write-Error "This script must be run in STA mode, relaunch powershell.exe with -STA flag" -ErrorAction Stop
        }

        # Attempt to elevate to SYSTEM
        Get-SystemToken -CreateProcess $Env:COMSPEC -ProcessArgs "/c $Command $Arguments"
    }

    End {}
}
