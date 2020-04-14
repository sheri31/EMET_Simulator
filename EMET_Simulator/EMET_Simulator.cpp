// MyEMET.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "EMET_Simulator.h"
#include "Decode2Asm.h"


GLOBALINFO g_Info;
GLOBALINFOLOCK g_Infowithlock;
NTPROTECTVIRTUALMEMORY pNtProtectVirtualMemory = (NTPROTECTVIRTUALMEMORY)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtProtectVirtualMemory");
BYTE g_CodeOriginalSEH[] = { 0x8B, 0xFF, 0x55, 0x8B, 0xEC, 0xFF, 0x75, 0x14,
    0xFF, 0x75, 0x10, 0xFF, 0x75, 0x0C, 0xFF, 0x75, 0x08 };

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

#define DLLMAX 10
REGINFO g_RegInfo[DLLMAX] = { 0 };

//不要打乱顺序
struct FUNCINFO g_hookedFuncInfo[] = {
    {"kernel32.LoadLibraryA", 1, 0x3D4CE},
    {"kernel32.LoadLibraryW", 1, 0x3D4CE},
    {"kernel32.LoadLibraryExA", 3, 0x3D4CE},
    {"kernel32.LoadLibraryExW", 3, 0x3D4CE},
    {"kernelbase.LoadLibraryExA", 3, 0x3D4CF},
    {"kernelbase.LoadLibraryExW", 3, 0x3D4CF},
    {"kernel32.LoadPackagedLibrary", 2, 0x14CE},
    {"ntdll.LdrLoadDll", 4, 0x14CF},
    {"kernel32.VirtualAlloc", 4, 0X14C2},
    {"kernel32.VirtualAllocEx", 5, 0X14C2},
    {"kernelbase.VirtualAlloc", 4, 0X14C3},
    {"kernelbase.VirtualAllocEx", 5, 0X14C3},
    {"ntdll.NtAllocateVirtualMemory", 6, 0X14C3},
    {"kernel32.VirtualProtect", 4, 0X14F2},
    {"kernel32.VirtualProtectEx", 5, 0X14F2},
    {"kernelbase.VirtualProtect", 4, 0X14F3},
    {"kernelbase.VirtualProtectEx", 5, 0X14F3},
    {"ntdll.NtProtectVirtualMemory", 5, 0X14F3},
    {"kernel32.HeapCreate", 3, 0X14C2},
    {"kernelbase.HeapCreate", 3, 0X14C3},
    {"ntdll.RtlCreateHeap", 6, 0X14C3},
    {"kernel32.CreateProcessA", 10, 0X14C2},
    {"kernel32.CreateProcessW", 10, 0X14C2},
    {"kernel32.CreateProcessInternalA", 12, 0X14C2},
    {"kernel32.CreateProcessInternalW", 12, 0X14C2},
    {"ntdll.NtCreateUserProcess", 11, 0x14C3},
    {"ntdll.NtCreateProcess", 8, 0X14C3},
    {"ntdll.NtCreateProcessEx", 9, 0X14C3},
    {"kernel32.CreateRemoteThread", 7, 0X14C2},
    {"kernel32.CreateRemoteThreadEx", 8, 0X14C2},
    {"kernelbase.CreateRemoteThreadEx", 8, 0X14C3},
    {"ntdll.NtCreateThreadEx", 11, 0X14C3},
    {"kernel32.WriteProcessMemory", 5, 0X14C2},
    {"kernelbase.WriteProcessMemory", 5, 0X14C3},
    {"ntdll.NtWriteVirtualMemory", 5, 0X14C3},
    {"kernel32.WinExec", 2, 0x14C2},
    {"kernel32.CreateFileA", 7, 0x14C2},
    {"kernel32.CreateFileW", 7, 0x14C2},
    {"kernelbase.CreateFileW", 7, 0x14C3},
    {"ntdll.NtCreateFile", 11, 0x14C3},
    {"kernel32.CreateFileMappingA", 6, 0x14C2},
    {"kernel32.CreateFileMappingW", 6, 0X14C2},
    {"kernelbase.CreateFileMappingW", 6, 0X14C3},
    {"kernelbase.CreateFileMappingNumaW", 7, 0X14C3},
    {"ntdll.NtCreateSection", 7, 0X14C3},
    {"kernel32.MapViewOfFile", 5, 0X14C2},
    {"kernel32.MapViewOfFileEx", 6, 0X14C2},
    {"kernelbase.MapViewOfFile", 5, 0X14C3},
    {"kernelbase.MapViewOfFileEx", 6, 0X14C3},
    {"kernel32.MapViewOfFileFromApp", 4, 0X14C3},
    {"ntdll.NtUnmapViewOfSection", 2, 0x300002},
    {"ntdll.NtMapViewOfSection", 10, 0x300002},
    {"ntdll.RtlAddVectoredExceptionHandler", 2, 2},
    {"kernel32.SetProcessDEPPolicy", 1, 0},
    {"kernel32.GetProcessDEPPolicy", 3, 0},
    {"ntdll.LdrHotPatchRoutine", 1, 0X102}
};


HMODULE proxy_GetModuleHandleEx(LPCSTR lpModuleName) {
    HMODULE hModule = NULL;
    BOOL bRet = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        lpModuleName,
        &hModule);

    if (bRet) {
        return hModule;
    }

    return 0;
}

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
        return Proxy_ApiCaller(pHookInfo->dwArgc, pHookInfo->dwArgAddr, pHookInfo->dwTrueApiAddr);
    }

    if (dwApiMask & 0x100000 && g_Info.MandatoryASLR) {
        DWORD dwViewOfSecRet = MandatoryASLR(pHookInfo);
        if (dwViewOfSecRet != 0) {
            return dwViewOfSecRet;
        }
    }


    UNION_HOOKEDFUNCINFO::UNKNOWN_INFO FuncInfo;
    if (InitializeFuncInfo(&FuncInfo, dwIndexApi, pHookInfo->dwArgAddr)) {

        if (dwApiMask & 0x40 && g_Info.StackPivot != 0) {
            //StackPivot(pHookInfo->dwRetAddr, pHookInfo.);
        }

        if (dwApiMask & 0x10 && g_Info.MemProt != 0) {
            MemProt((UNION_HOOKEDFUNCINFO::PMEMPROT_INFO)&FuncInfo);
        }

        if (0) {
            //caller  SimExecFlow
        }

        if (dwApiMask & 4 && g_Info.LoadLib != 0) {
            LoadLib((UNION_HOOKEDFUNCINFO::PLOADLIB_INFO)&FuncInfo, pHookInfo);
        }

        if (dwApiMask & 0x4000 && g_Info.ASR != 0) {
            ASR((UNION_HOOKEDFUNCINFO::PASR_INFO)&FuncInfo);
        }
    }

    Proxy_ApiCaller(pHookInfo->dwArgc, pHookInfo->dwArgAddr, pHookInfo->dwTrueApiAddr);

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
                LockGlobalInfo();
                g_Info.hVEH = pVEH_EMET;
                UnLockGlobalInfo();
            }
        }
    }

    if (dwApiMask & 0x10000 && g_Info.EAF_plus) {

        HMODULE hModule = (HMODULE)dwApiRet;
        EAF_PLUS((UNION_HOOKEDFUNCINFO::PEAFP_INFO)&FuncInfo, hModule);

    }

    return dwApiRet;
}

void HookFunctions() {
    for (int i = 0; i < sizeof(g_hookedFuncInfo) / sizeof(g_hookedFuncInfo[0]); i++) {
        HookCurFunction(i);
    }
    return;
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
            MEMORY_BASIC_INFORMATION MemInfo = { 0 };
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


BOOL StackPivot(DWORD dwRetAddr, DWORD dwOriginalAPIAddr, PHOOKINFO hookInfo) {

    PNT_TIB pTib = (PNT_TIB)NtCurrentTeb();
    DWORD dwStackLimit = (DWORD)pTib->StackLimit;
    DWORD dwStackBase = (DWORD)pTib->StackBase;

    if (hookInfo->dwArgAddr > dwStackBase || hookInfo->dwArgAddr < dwStackLimit) {
        //error
    }

    //xxx

    return 0;
}

BOOL MemProt(UNION_HOOKEDFUNCINFO::PMEMPROT_INFO pMemProtStruct) {

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


BOOL ASR_IsDLLInBlackList(PCSTR pszDllName) {

    for (int i = 0; i < sizeof(g_Info.pszASRCheckedDllNameAry) / sizeof(g_Info.pszASRCheckedDllNameAry[0]); i++) {
        if (MatchStr(pszDllName, g_Info.pszASRCheckedDllNameAry[i]) == TRUE) {
            //match    save infomation
            break;
        }
    }

    return 0;
}


BOOL ASR(UNION_HOOKEDFUNCINFO::PLOADLIB_INFO pStrucASR) {
    char *pszDllName_alloc = NULL;
    char *pszDllName = NULL;

    if (pStrucASR->dwType != 4 ||
        (pStrucASR->dwIsExVersion != FALSE && pStrucASR->dwFlags & LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_DATAFILE))
    {
        return TRUE;
    }


    if (pStrucASR->dwIsWideVersion) {

        int nDLLnameLen = wcslen((const wchar_t *)pStrucASR->dwFileNamePtr);
        pszDllName_alloc = new char[wcslen((const wchar_t *)pStrucASR->dwFileNamePtr) + 1];
        WideCharToMultiByte(CP_ACP, 0, (LPCWCH)pStrucASR->dwFileNamePtr, -1, pszDllName_alloc, nDLLnameLen, NULL, NULL);
        pszDllName = pszDllName_alloc;
    }
    else {
        pszDllName = (char*)pStrucASR->dwFileNamePtr;
    }

    //BOOL bRet =

    if (pszDllName_alloc != NULL) {
        delete[] pszDllName_alloc;
    }

    /*if () {

    }*/
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


BOOL LoadLib(UNION_HOOKEDFUNCINFO::PLOADLIB_INFO pLoadLibInfo, PHOOKINFO pHookInfo) {

    char *pszDllName_alloc = NULL;
    char *pszDllName = NULL;
    if (pLoadLibInfo->dwFlags != TYPE_LIBLOAD ||
        (pLoadLibInfo->dwIsExVersion == TRUE && pLoadLibInfo->dwFlags & LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE | LOAD_LIBRARY_AS_DATAFILE))
    {
        return TRUE;
    }

    if (pLoadLibInfo->dwIsWideVersion == TRUE) {

        int nDLLnameLen = wcslen((const wchar_t *)pLoadLibInfo->dwFileNamePtr);
        pszDllName_alloc = new char[wcslen((const wchar_t *)pLoadLibInfo->dwFileNamePtr) + 1];
        WideCharToMultiByte(CP_ACP, 0, (LPCWCH)pLoadLibInfo->dwFileNamePtr, -1, pszDllName_alloc, nDLLnameLen, NULL, NULL);
        pszDllName = pszDllName_alloc;
    }

    if (pLoadLibInfo->dwFileNamePtr) {

        BOOL bRet = IsUNCPath((LPCSTR)pLoadLibInfo->dwFileNamePtr);
        if (bRet) {
            if (GetFileAttributes((LPCSTR)pLoadLibInfo->dwFileNamePtr) != INVALID_FILE_ATTRIBUTES) {
                //error
                return 1;
            }
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
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)BaseAddr;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(dosHeader->e_lfanew + (DWORD)BaseAddr);
    PIMAGE_OPTIONAL_HEADER opHeader = (PIMAGE_OPTIONAL_HEADER)&ntHeader->OptionalHeader;
    WORD wDllCharacteristics = 0;
    DWORD dwImageBase = 0;
    if (opHeader->Magic == PE32) {
        wDllCharacteristics = opHeader->DllCharacteristics;
        dwImageBase = opHeader->ImageBase;
    }
    else {
        if (opHeader->Magic != PE64) {
            return 0;
        }
        wDllCharacteristics = opHeader->DllCharacteristics;
        dwImageBase = opHeader->ImageBase;
    }

    if ((wDllCharacteristics & 0x40) == 0 && (DWORD)BaseAddr == dwImageBase) {
        return 0;
    }

    return 1;
}

DWORD GetModuleSize(PVOID BaseAddr) {
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)BaseAddr;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(dosHeader->e_lfanew + (DWORD)BaseAddr);
    PIMAGE_OPTIONAL_HEADER opHeader = (PIMAGE_OPTIONAL_HEADER)&ntHeader->OptionalHeader;
    if (opHeader->Magic != PE32 && opHeader->Magic != PE64) {
        return 0;
    }

    return opHeader->SizeOfImage;
}


BOOL MatchStr(PCSTR pszDllName, PCSTR pszDllFormat) {
    if (pszDllName && pszDllFormat) {
        char cFormatStr = *pszDllFormat;
        if (cFormatStr != '*' || pszDllFormat[1] != 0) {
            char cDllName = *pszDllName;
            if (cDllName == 0) {
                return cFormatStr == 0;
            }

            if (cFormatStr != '*') {
                if (cFormatStr != '?') {
                    if (cFormatStr != cDllName) {
                        return FALSE;
                    }
                }
                return MatchStr(pszDllName + 1, pszDllFormat + 1);
            }

            if (MatchStr(pszDllName, pszDllFormat + 1) == FALSE)
            {
                return MatchStr(pszDllName + 1, pszDllFormat);
            }
        }
        return TRUE;
    }
    return FALSE;
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
            dwRet = pNtProtectVirtualMemory(GetCurrentProcess(), &BaseAddr, &RegionSize, PAGE_GUARD | PAGE_EXECUTE_READ, &RegionSize);
        }
    }
    return 0;
}

LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo)
{
    PEXCEPTION_RECORD pExceptionRecord = pExceptionInfo->ExceptionRecord;
    DWORD dwExceptionCode = pExceptionRecord->ExceptionCode;
    DWORD dwExceptionAddress = (DWORD)pExceptionRecord->ExceptionAddress;
    if (dwExceptionCode == STATUS_SINGLE_STEP || dwExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        return EAF_Handler(pExceptionInfo);
    }

    if (dwExceptionCode == STATUS_ACCESS_VIOLATION && pExceptionRecord->NumberParameters == 2) {
        if (dwExceptionAddress - g_Info.dwBaseAddrEMET >= g_Info.dwSizeEMET) {
            if (g_Info.MandatoryASLR && pExceptionRecord->ExceptionInformation[1] == dwExceptionAddress) {
                
                //judge

            }

            if (g_Info.HeapSpray) {
                DWORD dwAccessedAddrPage = pExceptionRecord->ExceptionInformation[1] & 0xFFFF0000;

                for (int i = 0; g_Info.HeapSprayAddrTable[i] == 0; i++) {
                    if (dwAccessedAddrPage == (g_Info.HeapSprayAddrTable[i] & 0xFFFF0000)) {
                        if (CheckExceptAddrAndSEH(pExceptionRecord)) {
                            return 0;
                        }
                        else {
                            //error
                        }
                    }
                }
            }

            if (g_Info.DEP &&
                pExceptionRecord->ExceptionInformation[0] == 8 &&
                dwExceptionAddress == pExceptionRecord->ExceptionInformation[1] && 00) {

                MEMORY_BASIC_INFORMATION MemInfo;
                if (VirtualQuery((LPCVOID)dwExceptionAddress, &MemInfo, sizeof(MemInfo))) {
                    if ((MemInfo.Protect & PAGE_NOACCESS) != 0 &&
                        (MemInfo.State & MEM_COMMIT) == 0) {
                        if (dwExceptionAddress != (dwExceptionAddress & 0xFFFF0000) ||
                            *(DWORD*)dwExceptionAddress != 0xC3 ||
                            *(DWORD*)(dwExceptionAddress + 4) ||
                            *(DWORD*)(dwExceptionAddress + 8) ||
                            *(DWORD*)(dwExceptionAddress + 0xC)
                            ) {

                            //error
                        }
                    }
                }


            }

        }
    }
    return 0;
}


LONG EAF_Handler(PEXCEPTION_POINTERS pExceptionInfo) {
    PCONTEXT pContext = pExceptionInfo->ContextRecord;
    PEXCEPTION_RECORD pExceptReg = pExceptionInfo->ExceptionRecord;
    BOOL bAccessAddrInEATPage = FALSE;
    DWORD dwCurEsp = pContext->Esp;
    DWORD dwCurEip = pContext->Eip;

    if (pExceptReg->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {

        if (g_Info.EAF) {

            int nIndexDll = 0;
            DWORD dwEip = dwCurEip;
            ULONG_PTR uAccessedAddr = pExceptReg->ExceptionInformation[1];
            PEAF_DLLINFO pEAFInfo = NULL;
            int nIndexEAT = 0;
            for (nIndexEAT = 0; nIndexEAT < 3; nIndexEAT++) {
                pEAFInfo = &g_Info.EafDllInfo[nIndexEAT];
                DWORD dwEATPageAddr = pEAFInfo->dwPageAddrOfEAT;
                bAccessAddrInEATPage = dwEip - dwEATPageAddr < pEAFInfo->dwSize;

                if ((uAccessedAddr & 0xFFFFF000) == dwEATPageAddr) {
                    break;
                }
            }

            if (nIndexEAT < 3 &&
                bAccessAddrInEATPage == FALSE &&
                uAccessedAddr == g_Info.EafDllInfo[nIndexEAT].dwEATAddr
                ) {

                CheckStack(pExceptionInfo);
                int nMaxIndexDll = sizeof(g_Info.SystemDllInfo) / sizeof(g_Info.SystemDllInfo[0]);
                for (nIndexDll = 0; nIndexDll < nMaxIndexDll; nIndexDll++) {
                    PMODULEINFO pSysDllInfo = &g_Info.SystemDllInfo[nIndexDll];
                    if (pSysDllInfo != 0 && dwEip - pSysDllInfo->dwModuleBase <= pSysDllInfo->dwModuleSize) {
                        break;
                    }
                }

                if (nIndexDll >= nMaxIndexDll) {

                    if (proxy_GetModuleHandleEx((LPCSTR)dwEip) == 0) {
                        //error
                    }
                }
            }


            PREGINFO pRegInfo = &g_RegInfo[nIndexDll];

            if (InterlockedCompareExchange(&pRegInfo->dwEsp_Guard_, dwCurEsp, 0) == 0) {
                pContext->EFlags |= 0x100;

                int nDifferenceEsp = pRegInfo->dwEsp1_Recover - dwCurEsp;
                if (nDifferenceEsp < 0) {
                    nDifferenceEsp = dwCurEsp - pRegInfo->dwEsp1_Recover;
                }

                if ((nDifferenceEsp & 0xFFF00000) != 0 ){

                    pRegInfo->dwEip_LastGuard = pRegInfo->dwEip_Guard;
                    pRegInfo->dwEsp_Guard = dwCurEsp;
                    pRegInfo->dwEsp1_LastRecover = pRegInfo->dwEsp1_Recover;
                    pRegInfo->dwEip1_LastRecover = pRegInfo->dwEip1_Recover;

                }
                pRegInfo->dwEip_Guard = dwCurEip;
            }
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    if (g_Info.EAF == 0 || pExceptReg->ExceptionCode != STATUS_SINGLE_STEP) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    //// 恢复PAGE_GUARD
    PREGINFO pRegInfo = &g_RegInfo[0];
    for (int i = 0; pRegInfo <= &g_RegInfo[DLLMAX - 1]; i++) {
        if (pRegInfo->dwEsp_Guard_ != 0) {
            if (i < 4) {
                if (g_Info.EAF) {
                    PEAF_DLLINFO pEafInfo = &g_Info.EafDllInfo[i];
                    if (pRegInfo->dwEip_Guard - pEafInfo->dwPageAddrOfEAT < pEafInfo->dwSize) {
                        pRegInfo->dwEsp_Guard_ = 0;
                        pRegInfo->dwEsp1_Recover = dwCurEsp;
                        pRegInfo->dwEip1_Recover = dwCurEip;
                        SIZE_T protSize = 0x1000;
                        PVOID pProtAddr = (PVOID)pEafInfo->dwPageAddrOfEAT;
                        pNtProtectVirtualMemory(GetCurrentProcess(), &pProtAddr, &protSize, pEafInfo->dwProtect, &pEafInfo->dwProtect);
                        return EXCEPTION_CONTINUE_EXECUTION;
                    }
                }
            }
        }
    }

    pRegInfo = &g_RegInfo[0];
    for (int i = 0; pRegInfo <= &g_RegInfo[DLLMAX - 1]; i++) {
        if (pRegInfo->dwEsp1_Recover != dwCurEsp || pRegInfo->dwEip1_Recover != dwCurEip) {
            if (pRegInfo->dwEsp1_LastRecover == dwCurEsp 
                && pRegInfo->dwEip1_LastRecover == dwCurEip 
                && dwCurEip - pRegInfo->dwEip_LastGuard < 0x10) {
                int nDifferenceEsp = pRegInfo->dwEsp_Guard - dwCurEsp;
                if (nDifferenceEsp < 0) {
                    nDifferenceEsp = dwCurEsp - pRegInfo->dwEsp_Guard;
                }

                if (nDifferenceEsp & 0xFFF0000) {
                    return EXCEPTION_CONTINUE_EXECUTION;
                }
            }
        }
        else if (dwCurEip - pRegInfo->dwEip_Guard < 0x10) {
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }

    if (g_Info.EAF != 0) {
        PEAF_DLLINFO pEafInfo = &g_Info.EafDllInfo[0];

        for (int i = 0; i < 4; i++) {
            if (dwCurEip - pEafInfo->dwPageAddrOfEAT < pEafInfo->dwSize) {
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }

    if (dwCurEip - (DWORD)g_Info.pNtdllKiUserExceptionDispatcher < 8 && (*(PEXCEPTION_RECORD*)dwCurEsp)->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}


DWORD CheckStack(PEXCEPTION_POINTERS ExceptionInfo) {
    DWORD dwTEB = (DWORD)NtCurrentTeb();
    DWORD dwStackBase = *(DWORD*)(dwTEB + 4);
    DWORD dwStackLimit = *(DWORD*)(dwTEB + 8);
    if (ExceptionInfo->ContextRecord->Esp < dwStackLimit ||
        ExceptionInfo->ContextRecord->Ebp > dwStackBase) {
        //error
    }

    return 0;
}


void EAF_PLUS(UNION_HOOKEDFUNCINFO::PEAFP_INFO pMemProt, HMODULE hModuleBase) {
    char szFileName[0x1000];

    if (pMemProt->dwSize == 4 && hModuleBase != NULL) {

        if (GetModuleFileName(hModuleBase, szFileName, 0x1000)) {
            char *pszCurLoadingFileName = strchr(szFileName, '\\');
            if (pszCurLoadingFileName != NULL) {
                pszCurLoadingFileName += 1;
            }
            else {
                pszCurLoadingFileName = szFileName;
            }

            for (int i = 0; i < 8; i++) {
                PMODULEINFO pEafPlus = g_Info.SystemDllInfo_EAFPlus;
                DWORD dwModuleName = pEafPlus->dwModuleName;
                DWORD dwModuleBase = pEafPlus->dwModuleBase;
                DWORD dwModuleSize = pEafPlus->dwModuleSize;
                DWORD dwProtect = pEafPlus->dwProtect;

                if (dwModuleName == 0) {
                    break;
                }

                if (dwModuleBase != 0) {
                    if (MatchStr(pszCurLoadingFileName, (PCSTR)dwModuleName)) {
                        DWORD dwSize = GetModuleSize(hModuleBase);
                        PMEMORY_BASIC_INFORMATION MemInfo = { 0 };
                        if (dwSize != 0 && VirtualQuery(hModuleBase, MemInfo, sizeof(MemInfo)) != 0) {
                            LockGlobalInfo();
                            if (_InterlockedCompareExchange((volatile ULONG64*)pEafPlus, (ULONG64)hModuleBase, 0) == 0) {
                                DWORD dwNewProtect = MemInfo->Protect | PAGE_GUARD;
                                DWORD dwSize = 0x1000;
                                PVOID pBaseAddr = hModuleBase;
                                DWORD dwOldProtect = 0;
                                pEafPlus->dwProtect = dwNewProtect;
                                pEafPlus->dwModuleSize = dwSize;
                                pNtProtectVirtualMemory(GetCurrentProcess(), &pBaseAddr, &dwSize, dwNewProtect, &dwOldProtect);
                            }
                            UnLockGlobalInfo();
                        }
                        return;
                    }
                }
            }
        }
    }

    return;
}

DWORD LockGlobalInfo() {
    EnterCriticalSection(&g_Infowithlock.CriSec);
    if (g_Infowithlock.dwRefCount > 0) {
        g_Infowithlock.dwRefCount++;
    }
    else {
        PVOID pBaseAddr = g_Infowithlock.info;
        DWORD dwNumberOfBytesToProtect = g_Infowithlock.dwPageSize;
        DWORD dwOldAccessProtection = 0;
        pNtProtectVirtualMemory(GetCurrentProcess(), &pBaseAddr, &dwNumberOfBytesToProtect, PAGE_READWRITE, &dwOldAccessProtection);
        g_Infowithlock.dwRefCount = 1;
    }

    LeaveCriticalSection(&g_Infowithlock.CriSec);
    return 0;
}

DWORD UnLockGlobalInfo() {

    EnterCriticalSection(&g_Infowithlock.CriSec);

    if (g_Infowithlock.dwRefCount-- == 1)
    {
        DWORD dwOldAccessProtection = 0;
        PVOID pBaseAddress = g_Infowithlock.info;
        DWORD dwNumberOfBytesToProtect = g_Infowithlock.dwPageSize;
        pNtProtectVirtualMemory(
            GetCurrentProcess(),
            &pBaseAddress,
            &dwNumberOfBytesToProtect,
            PAGE_READONLY,
            &dwOldAccessProtection);
    }
    LeaveCriticalSection(&g_Infowithlock.CriSec);

    return 0;
}



/*
    ret: 是否需要继续检查
*/
BOOL InitializeFuncInfo(UNION_HOOKEDFUNCINFO::PUNKNOWN_INFO a1, int API_index, int API_argAddr) {

    DWORD dw2;
    DWORD dw3;
    BOOL bNextCheck = FALSE;

    switch (API_index)
    {
    case 0:
        a1->dw3 = 0;
        goto LABEL_3;
    case 1:
        a1->dw3 = 1;
    LABEL_3:
        a1->dwType = 4;
        a1->dw1 = 0;
        a1->dw4 = *(DWORD *)API_argAddr;
        a1->dw2 = 0;
        bNextCheck = TRUE;

    case 2:
    case 4:
        a1->dw3 = 0;
        goto LABEL_6;
    case 3:
    case 5:
        a1->dw3 = 1;
    LABEL_6:
        a1->dwType = 4;
        a1->dw1 = 1;
        a1->dw4 = *(DWORD *)API_argAddr;
        a1->dw2 = *(DWORD *)(API_argAddr + 8);
        bNextCheck = TRUE;
    case 8:
    case 10:

        a1->dw4 = 0;
        a1->dwType = 1;
        a1->dw1 = *(DWORD *)API_argAddr;
        dw2 = *(DWORD *)(API_argAddr + 4);
        goto LABEL_11;
    case 9:
    case 11:
        a1->dwType = 1;
        a1->dw4 = *(DWORD *)API_argAddr;
        a1->dw1 = *(DWORD *)(API_argAddr + 4);
        a1->dw2 = *(DWORD *)(API_argAddr + 8);
        dw3 = *(DWORD *)(API_argAddr + 16);
        goto LABEL_9;
    case 12:
        a1->dwType = 1;
        a1->dw4 = *(DWORD *)API_argAddr;
        a1->dw1 = **(DWORD **)(API_argAddr + 4);
        a1->dw2 = **(DWORD **)(API_argAddr + 0xC);
        dw3 = *(DWORD *)(API_argAddr + 20);
        goto LABEL_9;
    case 13:
    case 15:
        a1->dw4 = 0;
        a1->dwType = 2;
        a1->dw1 = *(DWORD *)API_argAddr;
        a1->dw2 = *(DWORD *)(API_argAddr + 4);
        dw3 = *(DWORD *)(API_argAddr + 8);
        goto LABEL_9;
    case 14:
    case 16:
        a1->dwType = 2;
        a1->dw4 = *(DWORD *)API_argAddr;
        a1->dw1 = *(DWORD *)(API_argAddr + 4);
        dw2 = *(DWORD *)(API_argAddr + 8);
        goto LABEL_11;
    case 17:
        a1->dwType = 2;
        a1->dw4 = *(DWORD *)API_argAddr;
        a1->dw1 = **(DWORD **)(API_argAddr + 4);
        dw2 = **(DWORD **)(API_argAddr + 8);
    LABEL_11:
        a1->dw2 = dw2;
        dw3 = *(DWORD *)(API_argAddr + 12);
    LABEL_9:
        a1->dw3 = dw3;
        bNextCheck = TRUE;
    case 18:
    case 19:
        a1->dwType = 3;
        a1->dw1 = *(DWORD *)API_argAddr;
        bNextCheck = TRUE;
    case 28:
    case 29:
    case 30:
        a1->dwType = 6;
        a1->dw1 = *(DWORD *)API_argAddr;
        bNextCheck = TRUE;
    case 31:
        a1->dwType = 6;
        a1->dw1 = *(DWORD *)(API_argAddr + 12);
        break;
    default:
        break;
    }
    a1->dwType = 0;



    //判断是否需要继续检测
    if (a1->dwType > 0 && bNextCheck == TRUE) {
        if (a1->dwType == TYPE_MEMALLOC || a1->dwType == TYPE_MEMPROTECT) {
            //0xF0 = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
            return (((UNION_HOOKEDFUNCINFO::PMEMPROT_INFO)a1)->dwNewProtect & 0xF0) != 0;
        }

        if (a1->dwType == TYPE_HEAPCREATE) {
            //HeapCreate.arg1 == HEAP_CREATE_ENABLE_EXECUTE? 
            return (a1->dw1 >> 18) & 1;
        }
        if (a1->dwType == TYPE_THREADCREATE) {
            return a1->dw1 != (DWORD)GetCurrentProcess();
        }
    }

    return TRUE;
}


void InitializeEMET() {
    int nIndex = 0;
    //init pNtdllKiUserExceptionDispatcher
    g_Info.pNtdllKiUserExceptionDispatcher = GetProcAddress(GetModuleHandle("ntdll"), "KiUserExceptionDispatcher");


    //init HeapSprayAddrTable
    g_Info.HeapSprayAddrTable[nIndex++] = 0x0A040A04;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x0A0A0A0A;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x0B0B0B0B;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x0C0C0C0C;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x0D0D0D0D;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x0E0E0E0E;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x04040404;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x05050505;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x06060606;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x07070707;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x08080808;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x09090909;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x20202020;
    g_Info.HeapSprayAddrTable[nIndex++] = 0x14141414;

    //init EafDllInfo
    //g_Info.EafDllInfo[0].dwPageAddrOfEAT = ;


    g_Info.dwBaseAddrEMET = (DWORD)GetModuleHandle("EMET_Simulator");
    g_Info.dwSizeEMET = GetModuleSize((PVOID)g_Info.dwBaseAddrEMET);


    //init SystemDllInfo
    nIndex = 0;
    g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)"ntdll.dll";
    g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)"kernelbase.dll";
    g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)"kernel32.dll";
    g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)NULL;

    g_Info.SystemDllInfo_EAFPlus = &g_Info.SystemDllInfo[nIndex];
    g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)"mshtml.dll";
    g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)"flash*.ocx";
    g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)"jscript*.dll";
    g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)"vbscript.dll";
    g_Info.SystemDllInfo[nIndex++].dwModuleName = (DWORD)"vgx.dll";
    

    //init pszASRCheckedDllNameAry
    nIndex = 0;
    g_Info.pszASRCheckedDllNameAry[nIndex++] = "npjpi*.dll";
    g_Info.pszASRCheckedDllNameAry[nIndex++] = "jp2iexp.dll";
    g_Info.pszASRCheckedDllNameAry[nIndex++] = "vgx.dll";
    g_Info.pszASRCheckedDllNameAry[nIndex++] = "msxml4*.dll";
    g_Info.pszASRCheckedDllNameAry[nIndex++] = "wshom.ocx";
    g_Info.pszASRCheckedDllNameAry[nIndex++] = "scrrun.dll";
    g_Info.pszASRCheckedDllNameAry[nIndex++] = "vbscript.dll";




}


BOOL CheckExceptAddrAndSEH(PEXCEPTION_RECORD pExceptionRecord) {
    PVOID ExceptionAddress = pExceptionRecord->ExceptionAddress;
    _EXCEPTION_REGISTRATION_RECORD *seh = (_EXCEPTION_REGISTRATION_RECORD *)__readfsdword(0);
    _NT_TIB *tib = (_NT_TIB*)NtCurrentTeb();
    if (seh >= tib->StackLimit || seh < tib->StackBase) {

        //find
        //GdiPlus!GdipCreateSolidFill: 8A 09        mov     cl,byte ptr [ecx]
        //                             FF 45 ??     inc     dword ptr[xxxxxx]
        if (ExceptionAddress && *(DWORD*)ExceptionAddress == 0x45FF098A) {
            PEXCEPTION_ROUTINE pFirstHandler = seh->Handler;
            if (seh->Next >= tib->StackLimit || seh->Next < tib->StackBase) {
                if (pFirstHandler) {
                    if (proxy_GetModuleHandleExW(ExceptionAddress) == proxy_GetModuleHandleExW(pFirstHandler)) {
                        if (memcmp(pFirstHandler, &g_CodeOriginalSEH, 0x12) == 0) {
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return 0;
}


HMODULE proxy_GetModuleHandleExW(PVOID lpAddrInModule) {
    HMODULE hModule = NULL;
    BOOL bRet = GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        (LPCSTR)lpAddrInModule,
        &hModule);

    if (bRet) {
        return hModule;
    }

    return 0;

}