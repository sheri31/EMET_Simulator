#pragma once
#include "struct.h"

#define PE32 0x10B
#define PE64 0x20B
   


typedef DWORD (NTAPI *NTUNMAPVIEWOFSECTION)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress
);

typedef
DWORD (NTAPI *NTALLOCATEVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG AllocationType,
    _In_ ULONG Protect
);

typedef
DWORD (NTAPI *NTMAPVIEWOFSECTION)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
);

typedef 
ULONG (NTAPI *RTLRANDOM)(
    _Inout_ PULONG Seed
);

typedef
DWORD (NTAPI *NTPROTECTVIRTUALMEMORY)(
    _In_ HANDLE ProcessHandle,
    _Inout_ PVOID *BaseAddress,
    _Inout_ PSIZE_T RegionSize,
    _In_ ULONG NewProtect,
    _Out_ PULONG OldProtect
);


void SplitStringForDllAndFunc(const char *pszPath, char *pszDllName, char *pszFuncName);

void __declspec(dllexport) Proxy_HookDispatcherPtr(PHOOKINFO hookInfo);
DWORD HookDispatcher(PHOOKINFO hookInfo);
void __declspec(dllexport) HookFunctions();
DWORD Proxy_ApiCaller(int nApiArgCount, DWORD pApiArgv, DWORD pTrueApiAddr);
void HookCurFunction(int nIndex);
DWORD NullPage();
DWORD HeapSpray();
DWORD BottomUpASLR();
DWORD proxy_NtAllocateVirtualMemory(PVOID BaseAddr_, SIZE_T RegionSize_);
DWORD GetModuleSize(PVOID BaseAddr);
BOOL IsDllDynamicBase(PVOID BaseAddr);
DWORD MandatoryASLR(PHOOKINFO hookInfo);
DWORD  CheckStack(PEXCEPTION_POINTERS ExceptionInfo);
LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo);
DWORD LockGlobalInfo();
DWORD UnLockGlobalInfo();
void EAF_PLUS(UNION_HOOKEDFUNCINFO::PMEMPROT_INFO pMemProt, HMODULE hModuleBase);
BOOL IsUNCPath(LPCSTR pszPath);
BOOL MatchStr(PCSTR pszDllName, PCSTR pszDllFormat);
BOOL InitializeFuncInfo(UNION_HOOKEDFUNCINFO::PUNKNOWN_INFO a1, int API_index, int API_argAddr);
BOOL MemProt(UNION_HOOKEDFUNCINFO::PMEMPROT_INFO pMemProtStruct);
BOOL LoadLib(UNION_HOOKEDFUNCINFO::PLOADLIB_INFO pLoadLibInfo, PHOOKINFO pHookInfo);
BOOL ASR(UNION_HOOKEDFUNCINFO::PLOADLIB_INFO pStrucASR);
typedef DWORD(__stdcall *HOOKDISPATCHER)(PHOOKINFO hookInfo);