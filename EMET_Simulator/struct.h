#pragma once

typedef struct DLL_BASE_SIZE {
    DWORD dwBase;
    DWORD dwSize;
    DWORD dwProt;
    DWORD dwDllName;
}DLL_BASE_SIZE, *PDLL_BASE_SIZE;

union UNION_HOOKEDFUNCINFO
{
    typedef struct UNKNOWN_INFO {
        DWORD dwType;
        DWORD dw1;
        DWORD dw2;
        DWORD dw3;
        DWORD dw4;
        DWORD dw5;
    }UNKNOWN_INFO, *PUNKNOWN_INFO;


    typedef struct LOADLIB_INFO {
        DWORD dwType;
        DWORD dwIsExVersion;
        DWORD dwFlags;
        DWORD dwIsWideVersion;
        DWORD dwFileNamePtr;
        DWORD dw5;
    }LOADLIB_INFO, ASR_INFO, *PLOADLIB_INFO, *PASR_INFO;


    typedef struct MEMPROT_INFO {
        DWORD dwType;
        DWORD dwAddress;
        DWORD dwSize;
        DWORD dwNewProtect;
        DWORD dwProcess;
    }MEMPROT_INFO, EAFP_INFO, *PMEMPROT_INFO, *PEAFP_INFO;

};





typedef struct FUNCINFO {
    const char *pszFuncPath;
    int nFuncArgc;
    DWORD dwFuncMask;
}FUNCINFO, *PFUNCINFO;


typedef struct EAF_DLLINFO {
    DWORD dwPageAddrOfEAT;
    DWORD dwSize;
    DWORD dwProtect;
    DWORD dwEATAddr;
}EAF_DLLINFO, *PEAF_DLLINFO;


typedef struct MODULEINFO {
    DWORD dwModuleBase;
    DWORD dwModuleSize;
    DWORD dwProtect;
    DWORD dwModuleName;
}MODULEINFO, *PMODULEINFO;

typedef struct HOOKINFO {
    DWORD dwedi;
    DWORD dwesi;
    DWORD dwebp;
    DWORD dwesp;
    DWORD dwebx;
    DWORD dwedx;
    DWORD dwecx;
    DWORD dwEax;
    DWORD dwArgAddr;
    DWORD dwArgc;
    DWORD dwTrueApiAddr;
    DWORD pHookDispatcher;
    DWORD dwIndexApi;
    DWORD dwRetAddr;
    DWORD ApiArg[1];
}HOOKINFO, *PHOOKINFO;



typedef struct GLOBALINFO {
    DWORD dwExceptionReg;
    DWORD SEH_Handler;
    BYTE DEP;
    BYTE SEHOP;
    BYTE MandatoryASLR;
    BYTE NullPage;
    BYTE HeapSpray;
    BYTE EAF;
    BYTE EAF_plus;
    BYTE BottomUpASLR;
    BYTE ASR;
    BYTE AntiDetours;
    BYTE DeepHooks;
    BYTE BannedFunctions;
    BYTE Caller;
    BYTE SimExecFlow;
    BYTE MemProt;
    BYTE LoadLib;
    BYTE StackPivot;
    PVOID pNtdllKiUserExceptionDispatcher;
    DWORD HeapSprayAddrTable[14];
    EAF_DLLINFO EafDllInfo[4];
    DWORD dwBaseAddrEMET;
    DWORD dwSizeEMET;
    PCSTR pszASRCheckedDllNameAry[20];
    PVOID hExceptionHandler;
    HANDLE hVEH;
    MODULEINFO SystemDllInfo[12];
    PMODULEINFO SystemDllInfo_EAFPlus;
}GLOBALINFO, *PGLOBALINFO;

typedef struct GLOBALINFOLOCK {
    CRITICAL_SECTION CriSec;
    PGLOBALINFO info;
    DWORD dwPageSize;
    DWORD dwRefCount;
}GLOBALINFOLOCK, *PGLOBALINFOLOCK;



enum HOOK_FUNC_TYPE {
    TYPE_MEMALLOC = 1,
    TYPE_MEMPROTECT,
    TYPE_HEAPCREATE,
    TYPE_LIBLOAD,
    TYPE_STACKPIVOT,
    TYPE_THREADCREATE
};

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;



typedef struct _REGINGO {
    DWORD dwEsp_Guard_;
    DWORD dwEip_Guard;
    DWORD dwEsp1_Recover;
    DWORD dwEip1_Recover;
    DWORD dwEsp_Guard;
    DWORD dwEip_LastGuard;
    DWORD dwEsp1_LastRecover;
    DWORD dwEip1_LastRecover;
}REGINFO, *PREGINFO;



typedef struct GLOBALHOOKINFO {
    DWORD dwOriginalApiAddr;
    DWORD dwHookAddr;
    DWORD dwTrueApiAddr;
    DWORD dwApiIndex;
    DWORD dwArgCount;
}GLOBALHOOKINFO, *PGLOBALHOOKINFO;