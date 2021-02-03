function Get-HookedFunction {
<#
.SYNOPSIS
    Detect API hooks on NTDLL's functions.
    Privileges required: low

    Author: Timothée MENOCHET (@_tmenochet)

.DESCRIPTION
    Get-HookedFunction is a PowerShell implementation of HookDetector by @matterpreter.

.EXAMPLE
    PS C:\> Get-HookedFunction
#>

    $functions = @(
        "NtClose"
        "NtAllocateVirtualMemory"
        "NtAllocateVirtualMemoryEx"
        "NtCreateThread"
        "NtCreateThreadEx"
        "NtCreateUserProcess"
        "NtFreeVirtualMemory"
        "NtLoadDriver"
        "NtMapViewOfSection"
        "NtOpenProcess"
        "NtProtectVirtualMemory"
        "NtQueueApcThread"
        "NtQueueApcThreadEx"
        "NtResumeThread"
        "NtSetContextThread"
        "NtSetInformationProcess"
        "NtSuspendThread"
        "NtUnloadDriver"
        "NtWriteVirtualMemory"
    )

    [byte[]] $safeBytes = (
        0x4C, 0x8B, 0xD1, # mov r10, rcx
        0xB8              # mov eax, ??
    )

    if (-not (Get-ProcessArch)) {
        Write-Warning "It looks like you're not running x64."
        return
    }

    # Get the base address of ntdll.dll in our own process
    $ntdllBase = Get-NTDLLBase
    if ($ntdllBase -eq [IntPtr]::Zero) {
        Write-Warning "Couldn't get find ntdll.dll"
        return
    }
    else {
        Write-Verbose ("NTDLL Base Address: 0x{0:X}" -f $ntdllBase.ToInt64())
    }

    # Get the address of each of the target functions in ntdll.dll
    $funcAddresses = Get-FuncAddress $ntdllBase $functions

    # Check the first DWORD at each function's address for proper SYSCALL setup
    $i = 0
    foreach ($func in $funcAddresses.GetEnumerator()) {
        $instructions = New-Object byte[] 4
        [Runtime.InteropServices.Marshal]::Copy([IntPtr]$func.Value, [byte[]]$instructions, [Int32]0, [Int32]4)
        $safe = [Linq.Enumerable]::SequenceEqual($safeBytes, $instructions)
        $fmtFunc = [string]::Format("    {0,-25} 0x{1:X} ", $func.Key, $func.Value.ToInt64())
        if ($safe) {
            $instructions = "N/A"
        }
        else {
            $hookInstructions = New-Object byte[] 32
            [Runtime.InteropServices.Marshal]::Copy($func.Value, $hookInstructions, 0, 32)
            $instructions = [BitConverter]::ToString($hookInstructions).Replace("-", " ")
        }
        Write-Output (
            [pscustomobject] @{
                Function = $func.Key
                Address = $func.Value.ToInt64()
                Hooked = (-not $safe)
                Instructions = $instructions
            }
        )
        $i++
    }
}

function Local:Get-ProcessArch {
    $wow64 = $false
    [Win32]::IsWow64Process([Diagnostics.Process]::GetCurrentProcess().Handle, [ref] $wow64) | Out-Null
    if ([Environment]::Is64BitProcess -and -not $wow64) {
        return $true
    }
    else {
        return $false
    }
}

function Local:Get-NTDLLBase {
    $hProc = [Diagnostics.Process]::GetCurrentProcess()
    $module = ($hProc.Modules | Where-Object {$_.ModuleName -eq "ntdll.dll"})[0]
    if (-not ($baseAddr = $module.BaseAddress)) {
        $baseAddr = [IntPtr]::Zero
    }
    return $baseAddr
}

function Local:Get-FuncAddress {
    Param (
        [IntPtr] $HModule,
        [string[]] $Functions
    )
    $funcAddresses = @{}
    foreach ($function in $functions) {
        $funcPtr = [Win32]::GetProcAddress($HModule, $function)
        if ($funcPtr -ne [IntPtr]::Zero) {
            $funcAddresses.Add($function, $funcPtr)
        }
        else {
            Write-Warning ("Couldn't locate the address for {0}! (Error: {1})" -f $function, [Runtime.InteropServices.Marshal]::GetLastWin32Error())
        }
    }
    return $funcAddresses
}

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
    public static extern bool IsWow64Process(IntPtr hProcess, out bool Wow64Process);
}
"@