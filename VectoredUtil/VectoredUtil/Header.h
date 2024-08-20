#pragma once
#include <Windows.h>
#include <winternl.h>

#define SECTION_RWX (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE)

typedef struct _VEH_HANDLER_ENTRY {
    LIST_ENTRY Entry;
    PVOID SyncRefs;
    PVOID Rnd;
    PVOID VectoredHandler;
} VEH_HANDLER_ENTRY, PVEH_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST {
    PVOID                   MutexException;
    VEH_HANDLER_ENTRY* FirstExceptionHandler;
    VEH_HANDLER_ENTRY* LastExceptionHandler;
    PVOID                   MutexContinue;
    VEH_HANDLER_ENTRY* FirstContinueHandler;
    VEH_HANDLER_ENTRY* LastContinueHandler;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;


typedef enum _MEMORY_INFORMATION_CLASS {
    MemoryBasicInformation,
    MemoryWorkingSetInformation,
    MemoryMappedFilenameInformation,
    MemoryRegionInformation,
    MemoryWorkingSetExInformation,
    MemorySharedCommitInformation,
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped,
    MemoryPhysicalContiguityInformation,
    MemoryBadInformation,
    MemoryBadInformationAllProcesses,
    MaxMemoryInfoClass
} MEMORY_INFORMATION_CLASS;


typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    HANDLE                  Process,
    PROCESSINFOCLASS        ProcessInfoClass,
    PVOID                   ProcessInformation,
    ULONG                   ProcessinfoLength,
    PULONG                  ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtQueryVirtualMemory)(
    HANDLE                  Process,
    PVOID                   BaseAddress,
    MEMORY_INFORMATION_CLASS MemoryInformationClass,
    PVOID                   MemoryInformation,
    SIZE_T                  MemoryInfoLength,
    PSIZE_T                 RetLength
    );

typedef NTSTATUS(NTAPI* fnRtlAdjustPrivilege)(
    DWORD   Privilege,
    BOOL    bEnablePrivilege,
    BOOL    isThreadPrivilege,
    PBOOL   PreviousValue
    );

typedef NTSTATUS(NTAPI* fnNtQuerySysteminformation)(
    SYSTEM_INFORMATION_CLASS    SystemInfoClass,
    PVOID                       SystemInfo,
    ULONG                       SystemInfoLength,
    PULONG                      RetLength
    );

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
    PHANDLE				SectionHandle,
    ACCESS_MASK			DesiredAccess,
    POBJECT_ATTRIBUTES	ObjectAttributes,
    PLARGE_INTEGER		MaximumSize,
    ULONG				SectionPageProtection,
    ULONG				AllocationAttributes,
    HANDLE				FileHandle
    );

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
    HANDLE				SectionHandle,
    HANDLE				ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR			ZeroBits,
    SIZE_T				CommitSize,
    PLARGE_INTEGER		SectionOffset,
    PSIZE_T				ViewSize,
    ULONG       		InheritDisposition,
    ULONG				AllocationType,
    ULONG				Win32Protect
    );

typedef struct GLOBAL {
    PVOID	pNtdll;
    DWORD	dwDump;
    BOOL	bOverWrite;
    LPCWSTR lpPayload;
    PVOID   pHandlerList;
    PVOID	pVchStart;
    PVOID	pVehStart;
    fnNtQueryInformationProcess pNtQueryInformationProcess;
    fnNtQuerySysteminformation pNtQuerySystemInformation;
    fnNtQueryVirtualMemory pNtQueryVirtualMemory;
} GLOBAL;

