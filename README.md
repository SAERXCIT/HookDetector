# HookDetector

HookDetector identifies DLL-imported functions that have been hooked in its own process.

## How

It first retrieves all loaded DLLs from its own PEB, then for each module:

1. Retrieve and map in memory a clean copy of the module: first from `KnownDLLs`/`KnownDLLs32`, otherwise from the current architecture's system directory (`System32` or `SysWOW64`).
2. Compare byte-by-byte the loaded and mapped modules' `.text` sections. Each mismatch is stored in a structure. The next 15 bytes are skipped to avoid processing the same hook multiple times (max x86/x64 instruction length).
3. Parse the mapped module's export directory to locate the exported function closest to the mismatch.

Note: offsets will differ whether the module is mapped from `KnownDLLs` or the filesystem, as modules in `KnownDLLs` will have their sections mapped to specific aligned memory pages, as opposed to modules mapped from the filesystem which will not. A logic has been implemented to handle these differences.

## Building

Open the solution and compile in `Release` (configured with `/MT` compilation so the binary will be large but portable).

x64 and x86 versions are available, to find hooked functions in both architectures.

## Limitations

On x86, due to the absence of RIP-relative addressing, the `.text` section must be patched to process relocations, leading to numerous false positives when mapping a module from the filesystem (relocations have already been processed by the system when mapping from `KnownDLLs`). As such, the x86 version only maps modules from `KnownDLLs` and skips analysis when a module is not found there.

DLL search order is not implemented. The analysis will only be performed on modules found in the current architecture's system directory.

## TODO

* [ ] Stuff IAT with additional unused DLLs to bait more hooking targets.
* [ ] Only parse headers of the mapped module instead of the loaded one, to not trigger any `PAGE_GUARD` on the header page (e.g. EAF).

## Example output

```
C:\> .\HookDetector64.exe
[*] Sleeping for 2 seconds to let all initialization and hooking happen...
[*] Analyzing module ntdll.dll...
[+] In module ntdll.dll:
        [*] Hook found at RVA 0x243e0 in function RtlImageNtHeaderEx (at RVA 0x243e0)
        [*] Hook found at RVA 0x9f460 in function NtWriteFile (at RVA 0x9f460)
        [*] Hook found at RVA 0x9f500 in function NtSetInformationThread (at RVA 0x9f500)
        [*] Hook found at RVA 0x9f540 in function NtClose (at RVA 0x9f540)
        [*] Hook found at RVA 0x9f680 in function NtQueryInformationProcess (at RVA 0x9f680)
        [*] Hook found at RVA 0x9f820 in function NtOpenProcess (at RVA 0x9f820)
        [*] Hook found at RVA 0x9f860 in function NtMapViewOfSection (at RVA 0x9f860)
        [*] Hook found at RVA 0x9f8a0 in function NtUnmapViewOfSection (at RVA 0x9f8a0)
        [*] Hook found at RVA 0x9f8e0 in function NtTerminateProcess (at RVA 0x9f8e0)
        [*] Hook found at RVA 0x9faa0 in function NtWriteVirtualMemory (at RVA 0x9faa0)
        [*] Hook found at RVA 0x9fae0 in function NtDuplicateObject (at RVA 0x9fae0)
        [*] Hook found at RVA 0x9fb40 in function NtReadVirtualMemory (at RVA 0x9fb40)
        [*] Hook found at RVA 0x9fb80 in function NtAdjustPrivilegesToken (at RVA 0x9fb80)
        [*] Hook found at RVA 0x9fc00 in function NtQueueApcThread (at RVA 0x9fc00)
        [*] Hook found at RVA 0x9fca0 in function NtCreateSection (at RVA 0x9fca0)
        [*] Hook found at RVA 0x9fd00 in function NtCreateProcessEx (at RVA 0x9fd00)
        [*] Hook found at RVA 0x9fd20 in function NtCreateThread (at RVA 0x9fd20)
        [*] Hook found at RVA 0x9fda0 in function NtResumeThread (at RVA 0x9fda0)
        [*] Hook found at RVA 0xa0270 in function NtAlpcConnectPort (at RVA 0xa0270)
        [*] Hook found at RVA 0xa02b0 in function NtAlpcCreatePort (at RVA 0xa02b0)
        [*] Hook found at RVA 0xa04d0 in function NtAlpcSendWaitReceivePort (at RVA 0xa04d0)
        [*] Hook found at RVA 0xa06b0 in function NtCommitTransaction (at RVA 0xa06b0)
        [*] Hook found at RVA 0xa0a50 in function NtCreateMutant (at RVA 0xa0a50)
        [*] Hook found at RVA 0xa0b10 in function NtCreateProcess (at RVA 0xa0b10)
        [*] Hook found at RVA 0xa0bd0 in function NtCreateSectionEx (at RVA 0xa0bd0)
        [*] Hook found at RVA 0xa0c10 in function NtCreateSymbolicLinkObject (at RVA 0xa0c10)
        [*] Hook found at RVA 0xa0c30 in function NtCreateThreadEx (at RVA 0xa0c30)
        [*] Hook found at RVA 0xa0cf0 in function NtCreateTransaction (at RVA 0xa0cf0)
        [*] Hook found at RVA 0xa0d30 in function NtCreateUserProcess (at RVA 0xa0d30)
        [*] Hook found at RVA 0xa14d0 in function NtLoadDriver (at RVA 0xa14d0)
        [*] Hook found at RVA 0xa16d0 in function NtMapViewOfSectionEx (at RVA 0xa16d0)
        [*] Hook found at RVA 0xa20b0 in function NtQuerySystemEnvironmentValueEx (at RVA 0xa20b0)
        [*] Hook found at RVA 0xa2150 in function NtQueueApcThreadEx (at RVA 0xa2150)
        [*] Hook found at RVA 0xa21b0 in function NtRaiseHardError (at RVA 0xa21b0)
        [*] Hook found at RVA 0xa24f0 in function NtRollbackTransaction (at RVA 0xa24f0)
        [*] Hook found at RVA 0xa2650 in function NtSetContextThread (at RVA 0xa2650)
        [*] Hook found at RVA 0xa28b0 in function NtSetInformationTransaction (at RVA 0xa28b0)
        [*] Hook found at RVA 0xa2a50 in function NtSetSystemEnvironmentValueEx (at RVA 0xa2a50)
        [*] Hook found at RVA 0xa2bb0 in function NtShutdownSystem (at RVA 0xa2bb0)
        [*] Hook found at RVA 0xa2cd0 in function NtSuspendThread (at RVA 0xa2cd0)
        [*] Hook found at RVA 0xe6cc0 in function RtlWow64SetThreadContext (at RVA 0xe6cc0)
        [*] Hook found at RVA 0x1278d0 in function PssNtCaptureSnapshot (at RVA 0x1278d0)
[*] Analyzing module KERNEL32.DLL...
[+] In module KERNEL32.DLL:
        [*] Hook found at RVA 0x14550 in function Process32NextW (at RVA 0x14550)
        [*] Hook found at RVA 0x24330 in function CreateToolhelp32Snapshot (at RVA 0x24330)
        [*] Hook found at RVA 0x27360 in function MoveFileExA (at RVA 0x27360)
        [*] Hook found at RVA 0x62800 in function CreateNamedPipeA (at RVA 0x62800)
        [*] Hook found at RVA 0x63360 in function CreateFileTransactedW (at RVA 0x63360)
        [*] Hook found at RVA 0x65150 in function MoveFileWithProgressA (at RVA 0x65150)
        [*] Hook found at RVA 0x66240 in function DefineDosDeviceA (at RVA 0x66240)
        [*] Hook found at RVA 0x68660 in function WinExec (at RVA 0x68660)
[*] Analyzing module KERNELBASE.dll...
[+] In module KERNELBASE.dll:
        [*] Hook found at RVA 0x24060 in function CloseHandle (at RVA 0x24060)
        [*] Hook found at RVA 0x24b00 in function CreateFileA (at RVA 0x24b00)
        [*] Hook found at RVA 0x24c60 in function CreateFileW (at RVA 0x24c60)
        [*] Hook found at RVA 0x2d150 in function DeleteFileW (at RVA 0x2d150)
        [*] Hook found at RVA 0x366e0 in function GetNativeSystemInfo (at RVA 0x366e0)
        [*] Hook found at RVA 0x36770 in function GetSystemInfo (at RVA 0x36770)
        [*] Hook found at RVA 0x3efb0 in function CreateRemoteThreadEx (at RVA 0x3efb0)
        [*] Hook found at RVA 0x3ff00 in function CreateProcessInternalW (at RVA 0x3ff00)
        [*] Hook found at RVA 0x51f40 in function GetProcAddress (at RVA 0x51f40)
        [*] Hook found at RVA 0x60970 in function GetModuleBaseNameW (at RVA 0x60970)
        [*] Hook found at RVA 0x60a50 in function EnumProcessModules (at RVA 0x60a50)
        [*] Hook found at RVA 0x60ca0 in function GetModuleFileNameExW (at RVA 0x60ca0)
        [*] Hook found at RVA 0x60e50 in function GetModuleInformation (at RVA 0x60e50)
        [*] Hook found at RVA 0x673c0 in function GetVolumeInformationW (at RVA 0x673c0)
        [*] Hook found at RVA 0x72650 in function EnumDeviceDrivers (at RVA 0x72650)
        [*] Hook found at RVA 0x737e0 in function OpenThread (at RVA 0x737e0)
        [*] Hook found at RVA 0x77e10 in function QueueUserAPC (at RVA 0x77e10)
        [*] Hook found at RVA 0x7ada0 in function SetEnvironmentVariableW (at RVA 0x7ada0)
        [*] Hook found at RVA 0x7c470 in function MoveFileExW (at RVA 0x7c470)
        [*] Hook found at RVA 0x7c4a0 in function MoveFileWithProgressW (at RVA 0x7c4a0)
        [*] Hook found at RVA 0x7e570 in function GetLogicalProcessorInformationEx (at RVA 0x7e570)
        [*] Hook found at RVA 0x7e5e0 in function CreateNamedPipeW (at RVA 0x7e5e0)
        [*] Hook found at RVA 0x809b0 in function CreateProcessW (at RVA 0x809b0)
        [*] Hook found at RVA 0x82460 in function LoadLibraryW (at RVA 0x82460)
        [*] Hook found at RVA 0x83bf0 in function LoadLibraryA (at RVA 0x83bf0)
        [*] Hook found at RVA 0x84600 in function GetLogicalProcessorInformation (at RVA 0x84600)
        [*] Hook found at RVA 0x85f70 in function CreateProcessA (at RVA 0x85f70)
        [*] Hook found at RVA 0x85ff0 in function CreateProcessInternalA (at RVA 0x85ff0)
        [*] Hook found at RVA 0x88bf0 in function TerminateProcess (at RVA 0x88bf0)
        [*] Hook found at RVA 0xccbd1 in function GetApplicationRestartSettings (at RVA 0xccbd0)
        [*] Hook found at RVA 0xce340 in function EnumProcessModulesEx (at RVA 0xce340)
        [*] Hook found at RVA 0x100260 in function GetApplicationRecoveryCallback (at RVA 0x100260)
        [*] Hook found at RVA 0x147a90 in function GenerateConsoleCtrlEvent (at RVA 0x147a90)
        [*] Hook found at RVA 0x1579f0 in function CreateRemoteThread (at RVA 0x1579f0)
        [*] Hook found at RVA 0x159840 in function DefineDosDeviceW (at RVA 0x159840)
        [*] Hook found at RVA 0x15a800 in function SetEnvironmentVariableA (at RVA 0x15a800)
        [*] Hook found at RVA 0x15b840 in function GetVolumeInformationA (at RVA 0x15b840)
```
