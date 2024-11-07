#ifndef GLOBAL_HPP
#define GLOBAL_HPP

#include "Header.hpp"

extern std::vector<std::wstring> dlls;
extern fnNtCreateSection g_pNtCreateSection;
extern fnNtResumeProcess g_pNtResumeProcess;
extern fnNtSuspendProcess g_pNtSuspendProcess;
extern fnNtMapViewOfSection g_pNtMapViewOfSection;
extern fnNtQueryVirtualMemory g_pNtQueryVirtualMemory;
extern fnNtQuerySystemInformation g_pNtQuerySystemInformation;
extern fnNtQueryInformationProcess g_pNtQueryInformationProcess;

typedef struct GLOBAL {
    DWORD	dwDump;
    BOOL	bOverWrite;
    LPCWSTR lpPayloadFile;
    PVOID   pRndPtr;
    PVOID   pHandlerList;
    PVOID	pVchStart;
    PVOID	pVehStart;
} GLOBAL;

BOOL Init();

#endif
