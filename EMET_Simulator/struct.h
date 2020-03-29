#pragma once

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

typedef struct GLOBLEINFO {
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
    PVOID hExceptionHandler;
    DWORD HeapSprayAddrTable[14];
    EAF_DLLINFO EafDllInfo[3];
    DWORD dwBaseAddrEMET;
    DWORD dwSizeEMET;

}GLOBLEINFO, *PGLOBLEINFO;

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


typedef struct STRUCT_MEMPROT {
    DWORD dwType;
    DWORD dwAddress;
    DWORD dwSize;
    DWORD dwNewProtect;
    DWORD dwProcess;
}STRUCT_MEMPROT, *PSTRUCT_MEMPROT;