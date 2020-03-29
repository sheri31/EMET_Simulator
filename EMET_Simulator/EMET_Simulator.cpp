// MyEMET.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "EMET_Simulator.h"
#include "Decode2Asm.h"

typedef DWORD(*__stdcall HOOKDISPATCHER)(PHOOKINFO hookInfo);

GLOBLEINFO g_Info;

BYTE g_hookShellCode[] = {
    0x68, 0x00, 0x00, 0x00, 0x00,   //push Api index
    0x68, 0x00, 0x00, 0x00, 0x00,   //push hookdispatcher
    0x68, 0x00, 0x00, 0x00, 0x00,   //push true Api addr
    0x68, 0x00, 0x00, 0x00, 0x00,   //push argc1
    0x53,  //push ebx
    0x60,  //pushad
    0x54,  //push esp
    0xE8, 0x00, 0x00, 0x00, 0x00,
    0x61,  //popad
    0x83, 0xC4, 0x14, //add esp,14
    0xC2, 0x00, 0x00  //ret argc*4

};


//不要打乱顺序
struct FUNCINFO g_hookedFuncInfo[] = {
    {"kernel32.LoadLibraryA", 1, 1},
    {"kernel32.LoadLibraryW", 1, 1},
    {"kernel32.LoadLibraryExA", 3, 1},
    {"kernel32.LoadLibraryExW", 3, 1},
    {"kernelbase.LoadLibraryExA", 3, 1},
    {"kernelbase.LoadLibraryExW", 3, 1},
    {"kernel32.LoadPackagedLibrary", 2, 1},
    {"ntdll.LdrLoadDll", 4, 1},
    {"kernel32.VirtualAlloc", 4, 1},
    {"kernel32.VirtualAllocEx", 5, 1},
    {"kernelbase.VirtualAlloc", 4, 1},
    {"kernelbase.VirtualAllocEx", 5, 1},
    {"ntdll.NtAllocateVirtualMemory", 6, 1},
    {"kernel32.VirtualProtect", 4, 1},
    {"kernel32.VirtualProtectEx", 5, 1},
    {"kernelbase.VirtualProtect", 4, 1},
    {"kernelbase.VirtualProtectEx", 5, 1},
    {"ntdll.NtProtectVirtualMemory", 5, 1},
    {"kernel32.HeapCreate", 3, 1},
    {"kernelbase.HeapCreate", 3, 1},
    {"ntdll.RtlCreateHeap", 6, 1},
    {"kernel32.CreateProcessA", 10, 1},
    {"kernel32.CreateProcessW", 10, 1},
    {"kernel32.CreateProcessInternalA", 12, 1},
    {"kernel32.CreateProcessInternalW", 12, 1},
    {"ntdll.NtCreateUserProcess", 11, 1},
    {"ntdll.NtCreateProcess", 8, 1},
    {"ntdll.NtCreateProcessEx", 9, 1},
    {"kernel32.CreateRemoteThread", 7, 1},
    {"kernel32.CreateRemoteThreadEx", 8, 1},
    {"kernelbase.CreateRemoteThreadEx", 8, 1},
    {"ntdll.NtCreateThreadEx", 11, 1},
    {"kernel32.WriteProcessMemory", 5, 1},
    {"kernelbase.WriteProcessMemory", 5, 1},
    {"ntdll.NtWriteVirtualMemory", 5, 1},
    {"kernel32.WinExec", 2, 1},
    {"kernel32.CreateFileA", 7, 1},
    {"kernel32.CreateFileW", 7, 1},
    {"kernelbase.CreateFileW", 7, 1},
    {"ntdll.NtCreateFile", 11, 1},
    {"kernel32.CreateFileMappingA", 6, 1},
    {"kernel32.CreateFileMappingW", 6, 1},
    {"kernelbase.CreateFileMappingW", 6, 1},
    {"kernelbase.CreateFileMappingNumaW", 7, 1},
    {"ntdll.NtCreateSection", 7, 1},
    {"kernel32.MapViewOfFile", 5, 1},
    {"kernel32.MapViewOfFileEx", 6, 1},
    {"kernelbase.MapViewOfFile", 5, 1},
    {"kernelbase.MapViewOfFileEx", 6, 1},
    {"kernel32.MapViewOfFileFromApp", 4, 1},
    {"ntdll.NtUnmapViewOfSection", 2, 0x1},
    {"ntdll.NtMapViewOfSection", 10, 0x1},
    {"ntdll.RtlAddVectoredExceptionHandler", 2, 1},
    {"kernel32.SetProcessDEPPolicy", 1, 1},
    {"kernel32.GetProcessDEPPolicy", 3, 1},
    {"ntdll.LdrHotPatchRoutine", 1, 1}
};


void __declspec(dllexport) Proxy_HookDispatcherPtr(PHOOKINFO hookInfo) {
    hookInfo->dwArgAddr = (DWORD)&hookInfo->ApiArg;
    hookInfo->dwEax = ((HOOKDISPATCHER)hookInfo->pHookDispatcher)(hookInfo);
    return;
}

BOOL IsUNCPath(LPCSTR pszPath) {
    int nPathLen = 0;
    LPCSTR tempPath = NULL;

    if (pszPath == NULL) {
        return FALSE;
    }

    if ((nPathLen = strlen(pszPath)) < 5) {
        return FALSE;
    }

    if (pszPath[0] != '\\') {
        return FALSE;
    }

    if (pszPath[1] != '\\' && pszPath[1] != '/' && pszPath[1] != '?') {
        return FALSE;
    }

    if (pszPath[2] != '.' && pszPath[2] != '?') {
        return TRUE;
    }

    if (pszPath[strspn(pszPath, ".?/\\")] != 0) {
        tempPath = &pszPath[strspn(pszPath, ".?/\\")];
    }

    if (tempPath) {
        if (strncmp("unc", tempPath, 3) == 0) {
            wchar_t wcUncBehind = *(tempPath + 3);
            if (wcUncBehind != 0) {
                if (wcUncBehind != '.') {
                    
                }
                else {
                    wcUncBehind = *(tempPath + 3 + 1);
                    if (wcUncBehind == 0) {
                        return FALSE;
                    }
                }

                if (wcUncBehind == '\\') {
                    return TRUE;
                }
                else {
                    if (wcUncBehind == '/') {
                        return TRUE;
                    }
                }

            }
        }
    }
    return FALSE;
}




DWORD HookDispatcher(PHOOKINFO pHookInfo) {

    DWORD dwIndexApi = pHookInfo->dwIndexApi;
    DWORD dwApiRet = 0;
    DWORD dwApiMask = g_hookedFuncInfo[dwIndexApi].dwFuncMask;

    if (pHookInfo == NULL) {
        Proxy_ApiCaller(pHookInfo->dwArgc, pHookInfo->dwArgAddr, pHookInfo->dwTrueApiAddr);
    }


    if (dwApiMask & 0x100000 && g_Info.MandatoryASLR) {
        DWORD dwViewOfSecRet = MandatoryASLR(pHookInfo);
        if (dwViewOfSecRet != 0) {
            return dwViewOfSecRet;
        }
    }


    
    if (1) {

    }


    dwApiRet = Proxy_ApiCaller(pHookInfo->dwArgc, pHookInfo->dwArgAddr, pHookInfo->dwTrueApiAddr);

    if (dwIndexApi == 52) {
        BOOL bIsVehFirst = pHookInfo->ApiArg[0] != 0;
        if (bIsVehFirst == TRUE) {
            PVOID pVEH = (PVOID)dwApiRet;
            if (pVEH != 0) {
                PVOID pVEH_EMET = AddVectoredExceptionHandler(bIsVehFirst, VectoredHandler);
                if (pVEH_EMET != 0) {
                    RemoveVectoredExceptionHandler(g_Info.hExceptionHandler);
                    g_Info.hExceptionHandler = pVEH_EMET;

                }
                else {
                    RemoveVectoredExceptionHandler(pVEH);
                    TerminateProcess(GetCurrentProcess(), -1);
                }
            }
        }
    }



    return dwApiRet;
}

void HookFunctions() {

    
    for (int i = 0; i < sizeof(g_hookedFuncInfo) / sizeof(g_hookedFuncInfo[0]); i++) {
        HookCurFunction(i);
    }

}


void HookCurFunction(int nIndex) {
    DWORD dwOldProctect = 0;
    BYTE *pApiHeadCode = NULL;
    BYTE *phookShellCode = NULL;
    FARPROC pProc = NULL;
    HMODULE hDll = NULL;
    FUNCINFO *pCur = NULL;
    char szASM[0x100] = { 0 };
    char *pszFunName = NULL;
    char *pszDllName = NULL;
    int nPathLen = 0;
    UINT uCodeSize = 0;
    int nHookedBytes = 0;
    DWORD dwDisAsmAddr = 0;
    pCur = &g_hookedFuncInfo[nIndex];
    nPathLen = strlen(pCur->pszFuncPath) + 1;
    pszFunName = new char[nPathLen];
    pszDllName = new char[nPathLen];
    memset(pszFunName, 0, nPathLen);
    memset(pszDllName, 0, nPathLen);
    SplitStringForDllAndFunc(pCur->pszFuncPath, pszDllName, pszFunName);

    hDll = GetModuleHandleA(pszDllName);
    if (!hDll) {
        goto END;
    }
    pProc = GetProcAddress(hDll, pszFunName);
    if (!pProc) {
        goto END;
    }

    dwDisAsmAddr = (DWORD)pProc;
    do {
        Decode2Asm((PBYTE)dwDisAsmAddr, szASM, &uCodeSize, (UINT)dwDisAsmAddr);
        nHookedBytes += uCodeSize;
        dwDisAsmAddr += uCodeSize;
    } while (nHookedBytes < 5);
    


    pApiHeadCode = new BYTE[nHookedBytes + 5];
    pApiHeadCode[nHookedBytes] = 0xE9;
    *(DWORD*)&pApiHeadCode[nHookedBytes + 1] = (DWORD)pProc + nHookedBytes - (DWORD)(pApiHeadCode + nHookedBytes + 5);
    memcpy(pApiHeadCode, pProc, nHookedBytes);
    VirtualProtect(pApiHeadCode, nHookedBytes + 5, PAGE_EXECUTE_READWRITE, &dwOldProctect);

    phookShellCode = new BYTE[sizeof(g_hookShellCode)];
    memcpy(phookShellCode, g_hookShellCode, sizeof(g_hookShellCode));
    VirtualProtect(phookShellCode, sizeof(g_hookShellCode), PAGE_EXECUTE_READWRITE, &dwOldProctect);
    *(DWORD*)&phookShellCode[1] = nIndex;
    *(DWORD*)&phookShellCode[6] = (DWORD)HookDispatcher;
    *(DWORD*)&phookShellCode[11] = (DWORD)pApiHeadCode;
    *(DWORD*)&phookShellCode[16] = pCur->nFuncArgc;
    *(DWORD*)&phookShellCode[24] = (DWORD)Proxy_HookDispatcherPtr - (DWORD)&phookShellCode[23 + 5];
    *(DWORD*)&phookShellCode[33] = pCur->nFuncArgc * 4;




    VirtualProtect(pProc, 5, PAGE_EXECUTE_READWRITE, &dwOldProctect);
    *((BYTE*)pProc) = 0xE9;
    *(DWORD*)((BYTE*)pProc + 1) = (DWORD)phookShellCode - ((DWORD)pProc + 5);
    VirtualProtect(pProc, 5, dwOldProctect, &dwOldProctect);

END:
    delete pszFunName;
    delete pszDllName;
}


void SplitStringForDllAndFunc(const char *pszPath, char *pszDllName, char *pszFuncName) {
    int nPathLen = strlen(pszPath);
    for (int i = 0; i < nPathLen; i++) {
        if (pszPath[i] == '.') {

            memcpy(pszDllName, pszPath, i);
            memcpy(pszFuncName, pszPath + i + 1, nPathLen - i - 1);
            break;
        }
    }
}


DWORD MandatoryASLR(PHOOKINFO hookInfo) {
    DWORD dwRet = 0;
    if (hookInfo->dwIndexApi - 50) {
        //mapviewofsection
        dwRet = Proxy_ApiCaller(hookInfo->dwArgc, hookInfo->dwArgAddr, hookInfo->dwTrueApiAddr);
        if (dwRet >= 0) {
            MEMORY_BASIC_INFORMATION MemInfo = {0};
            PVOID BaseAddr = (PVOID)*(hookInfo->ApiArg + 2);
            if (VirtualQuery(BaseAddr, &MemInfo, sizeof(MEMORY_BASIC_INFORMATION))) {
                if (MemInfo.Type == MEM_IMAGE && IsDllDynamicBase(BaseAddr)) {
                    HANDLE hProcess = (HANDLE)*(hookInfo->ApiArg + 1);
                    NTUNMAPVIEWOFSECTION pNtUnmapViewofSection = (NTUNMAPVIEWOFSECTION)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtUnmapViewofSection");
                    proxy_NtAllocateVirtualMemory(BaseAddr, 0x1000);
                    *(hookInfo->ApiArg + 2) = 0;
                    dwRet = Proxy_ApiCaller(hookInfo->dwArgc, hookInfo->dwArgAddr, hookInfo->dwTrueApiAddr);
                    
                }
            }
        }
    }
    else {
        dwRet = Proxy_ApiCaller(hookInfo->dwArgc, hookInfo->dwArgAddr, hookInfo->dwTrueApiAddr);
    }

    return dwRet;
}

BOOL StackPivot() {
    NtCurrentTeb();
    return 0;
}

BOOL MemProt(PSTRUCT_MEMPROT pMemProtStruct) {
    
    if (pMemProtStruct->dwType != 2) {
        return TRUE;
    }

    if (!(pMemProtStruct->dwNewProtect & 0xF0)) {
        return TRUE;
    }

    if (pMemProtStruct->dwProcess) {
        if (GetCurrentProcessId() != GetProcessId((HANDLE)pMemProtStruct->dwProcess)) {
            return TRUE;
        }
    }
    DWORD dwAddr = pMemProtStruct->dwAddress;
    DWORD teb = (DWORD)NtCurrentTeb();
    DWORD dwStackLimit = *(DWORD*)(teb + 8);
    DWORD dwStackBase = *(DWORD*)(teb + 4);
    if (((dwAddr + pMemProtStruct->dwSize + 0xFFF) & 0xFFFFF000) <= dwStackLimit
        || (dwAddr & 0xFFFFF000) >= dwStackBase) 
    {
        return TRUE;
    }

    return FALSE;
}
BOOL Caller() {
    return 0;
}

//BOOL SimExecFlow() {
//
//    return 0;
//}

BOOL BannedFunctions() {

    return 0;
}
BOOL ASR() {

    return 0;
}

BOOL DEP() {
    DWORD dwFlag = 0;
    BOOL bPerManent = FALSE;
    BOOL bRet = GetProcessDEPPolicy(GetCurrentProcess(), &dwFlag, &bPerManent);
    if (bRet) {
        if (!dwFlag & PROCESS_DEP_ENABLE) {
            dwFlag = PROCESS_DEP_ENABLE;
        }
        bRet = SetProcessDEPPolicy(dwFlag);
    }
    return bRet;
}

BOOL LoadLib(LPCSTR str) {


    if (str != NULL && IsUNCPath(str)) {
        if (GetFileAttributesA(str) != INVALID_FILE_ATTRIBUTES) {
            //error
        }

    }
    return 0;
}


DWORD Proxy_ApiCaller(int nApiArgCount, DWORD pApiArgv, DWORD pTrueApiAddr) {
    __asm {
        
        mov eax, nApiArgCount;
        mov ecx, eax;
        shl eax, 2;
        sub esp, eax;

        mov edi, esp;
        mov esi, pApiArgv;
        rep movsd;

        mov eax, pTrueApiAddr;
        call eax;
    }

    return 1;
}


BOOL IsDllDynamicBase(PVOID BaseAddr) {


    return 0;
}

DWORD GetModuleSize(PVOID BaseAddr) {

    return 1;
}


DWORD proxy_NtAllocateVirtualMemory(PVOID BaseAddr_, SIZE_T RegionSize_) {
    PVOID BaseAddr = BaseAddr_;
    SIZE_T RegionSize = RegionSize_;
    NTALLOCATEVIRTUALMEMORY pNtAllocateVirtualMemory = (NTALLOCATEVIRTUALMEMORY)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtAllocateVirtualMemory");
    return pNtAllocateVirtualMemory(GetCurrentProcess(), &BaseAddr, 0, &RegionSize, MEM_RESERVE, PAGE_NOACCESS);
}

DWORD NullPage() {
    return proxy_NtAllocateVirtualMemory((PVOID)1, 0x1000);
}

DWORD HeapSpray() {
    DWORD dwRet = 0;

    for (int i = 0; i < 14; i++) {
        PVOID BaseAddr = (PVOID)g_Info.HeapSprayAddrTable[i];
        if (BaseAddr == 0) {
            break;
        }
        dwRet = proxy_NtAllocateVirtualMemory(BaseAddr, 0x1000);
    }

    return dwRet;
}


DWORD BottomUpASLR() {

    //call proxy_VerifyVersionInfoW

    DWORD dwPid = GetCurrentProcessId();
    DWORD dwSeed = GetTickCount() ^ dwPid;
    RTLRANDOM pRtlRandom = (RTLRANDOM)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlRandom");
    DWORD dwRandomVal = pRtlRandom(&dwSeed);
    while (dwRandomVal) {
        proxy_NtAllocateVirtualMemory(0, 0x10000);
        dwRandomVal--;
    }


    return 0;
}


DWORD EAF() {

    DWORD dwRet = 0;

    for (int i = 0; i < 3; i++) {

        PEAF_DLLINFO pDllInfo = &g_Info.EafDllInfo[i];
        PVOID BaseAddr = (PVOID)pDllInfo->dwPageAddrOfEAT;
        SIZE_T RegionSize = pDllInfo->dwSize;

        if (BaseAddr) {
            NTPROTECTVIRTUALMEMORY pNtProtectVirtualMemory = (NTPROTECTVIRTUALMEMORY)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtProtectVirtualMemory");
            dwRet = pNtProtectVirtualMemory(GetCurrentProcess(), &BaseAddr, &RegionSize, PAGE_GUARD | PAGE_EXECUTE_READ, &RegionSize);
        }
    }




    return 0;
}

LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS ExceptionInfo) 
{
    PEXCEPTION_RECORD pExceptionRecord = ExceptionInfo->ExceptionRecord;
    DWORD dwExceptionCode = pExceptionRecord->ExceptionCode;
    DWORD dwExceptionAddress = (DWORD)pExceptionRecord->ExceptionAddress;
    if (dwExceptionCode == STATUS_SINGLE_STEP || dwExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        
        //return eaf handler;
    }

    if (dwExceptionCode == STATUS_ACCESS_VIOLATION && pExceptionRecord->NumberParameters == 2) {
        if (dwExceptionAddress - g_Info.dwBaseAddrEMET >= g_Info.dwSizeEMET) {
            if (g_Info.MandatoryASLR) {

            }

            if (g_Info.HeapSpray) {

            }

            if (g_Info.DEP) {

            }

        }
    }



    return 0;
}


LONG EAF_Handler(PEXCEPTION_POINTERS ExceptionInfo) {
    PCONTEXT pContext = ExceptionInfo->ContextRecord;
    PEXCEPTION_RECORD pExceptReg = ExceptionInfo->ExceptionRecord;
    BOOL bAccessAddrInEATPage = FALSE;
    if (pExceptReg->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        if (g_Info.EAF) {
            DWORD dwEip = pContext->Eip;
            ULONG_PTR uAccessedAddr = pExceptReg->ExceptionInformation[1];
            PEAF_DLLINFO pEAFInfo = NULL;
            int nIndex = 0;
            for(nIndex = 0; nIndex < 3; nIndex++){
                pEAFInfo = &g_Info.EafDllInfo[nIndex];
                DWORD dwEATPageAddr = pEAFInfo->dwPageAddrOfEAT;
                bAccessAddrInEATPage = dwEip - dwEATPageAddr < pEAFInfo->dwSize;
                

                if ((uAccessedAddr & 0xFFFFF000) == dwEATPageAddr) {
                    break;
                }
            }

            if (nIndex < 3 &&
                bAccessAddrInEATPage == FALSE &&
                uAccessedAddr == g_Info.EafDllInfo[nIndex].dwEATAddr
                ){

                CheckStack(ExceptionInfo);




            }




        }
    }









    return 0;
}


DWORD  CheckStack(PEXCEPTION_POINTERS ExceptionInfo) {
    DWORD dwTEB = (DWORD)NtCurrentTeb();
    DWORD dwStackBase = *(DWORD*)(dwTEB + 4);
    DWORD dwStackLimit = *(DWORD*)(dwTEB + 8);
    if (ExceptionInfo->ContextRecord->Esp < dwStackLimit ||
        ExceptionInfo->ContextRecord->Ebp > dwStackBase) {
        //error
    }

    return 0;
}