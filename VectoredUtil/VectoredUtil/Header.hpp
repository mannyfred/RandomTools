#pragma once
#include <Windows.h>
#include <winternl.h>
#include <unordered_map>
#include <iostream>

#define SECTION_RWX (SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE)
#define PAGE_SIZE 4096
#define KNOWN	L"\\KnownDlls"
#define GET_FILENAMEW_FROM_UNICODE_STRING(PTR) (wcsrchr((PTR)->Buffer, L'\\') ? wcsrchr((PTR)->Buffer, L'\\') + 1 : (PTR)->Buffer)

#define NtCurrentProcess() ((HANDLE)-1)

#define DIRECTORY_QUERY                 (0x0001)
#define DIRECTORY_TRAVERSE              (0x0002)
#define STATUS_FILE_INVALID             (0xC0000098)
#define STATUS_INVALID_ADDRESS          (0xC0000141)
#define STATUS_NO_MORE_ENTRIES          (0x8000001A)

const std::string red = "\033[31m";
const std::string reset = "\033[0m";

const std::unordered_map<DWORD, std::string> Flags = {
    { PAGE_NOACCESS, "PAGE_NOACCESS" },
    { PAGE_READONLY, "PAGE_READONLY" },
    { PAGE_READWRITE, "PAGE_READWRITE" },
    { PAGE_WRITECOPY, "PAGE_WRITECOPY" },
    { PAGE_EXECUTE, "PAGE_EXECUTE" },
    { PAGE_EXECUTE_READ, "PAGE_EXECUTE_READ" },
    { PAGE_EXECUTE_WRITECOPY, "PAGE_EXECUTE_WRITECOPY" },
    { PAGE_EXECUTE_READWRITE, "PAGE_EXECUTE_READWRITE" },
    { PAGE_GUARD, "PAGE_GUARD" },
    { PAGE_NOCACHE, "PAGE_NOCACHE" },
    { PAGE_WRITECOMBINE, "PAGE_WRITECOMBINE" },
    { MEM_COMMIT, "MEM_COMMIT" },
    { MEM_FREE, "MEM_FREE" },
    { MEM_RESERVE, "MEM_RESERVE" },
    { MEM_IMAGE, "MEM_IMAGE" },
    { MEM_MAPPED, "MEM_MAPPED" },
    { MEM_PRIVATE, "MEM_PRIVATE" }
};

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

typedef struct _OBJECT_DIRECTORY_INFORMATION {
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, * POBJECT_DIRECTORY_INFORMATION;

typedef enum _PROCINFOCLASS {
    ProcessBasicInfo = 0,
    ProcessCookie = 36
} PROCINFOCLASS;

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

typedef struct _MEMORY_WORKING_SET_EX_BLOCK {
    union {
        struct {
            ULONG_PTR Valid : 1;
            ULONG_PTR ShareCount : 3;
            ULONG_PTR Win32Protection : 11;
            ULONG_PTR Shared : 1;
            ULONG_PTR Node : 6;
            ULONG_PTR Locked : 1;
            ULONG_PTR LargePage : 1;
            ULONG_PTR Priority : 3;
            ULONG_PTR Reserved : 3;
            ULONG_PTR SharedOriginal : 1;
            ULONG_PTR Bad : 1;
            ULONG_PTR Win32GraphicsProtection : 4;
            ULONG_PTR ReservedUlong : 28;
        };
        struct {
            struct {
                ULONG_PTR Valid : 1;
                ULONG_PTR Reserved0 : 14;
                ULONG_PTR Shared : 1;
                ULONG_PTR Reserved1 : 5;
                ULONG_PTR PageTable : 1;
                ULONG_PTR Location : 2;
                ULONG_PTR Priority : 3;
                ULONG_PTR ModifiedList : 1;
                ULONG_PTR Reserved2 : 2;
                ULONG_PTR SharedOriginal : 1;
                ULONG_PTR Bad : 1;
                ULONG_PTR ReservedUlong : 32;
            };
        } Invalid;
    };
} MEMORY_WORKING_SET_EX_BLOCK, * PMEMORY_WORKING_SET_EX_BLOCK;

typedef struct _MEMORY_WORKING_SET_EX_INFORMATION {
    PVOID VirtualAddress;
    union {
        MEMORY_WORKING_SET_EX_BLOCK VirtualAttributes;
        ULONG_PTR Long;
    } u1;
} MEMORY_WORKING_SET_EX_INFORMATION, * PMEMORY_WORKING_SET_EX_INFORMATION;

typedef enum _SECTION_INHERIT {
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
    _In_ HANDLE ProcessHandle,
    _In_ PROCINFOCLASS ProcessInformationClass,
    _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtQueryVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_opt_ PVOID BaseAddress,
    _In_ MEMORY_INFORMATION_CLASS MemoryInformationClass,
    _Out_writes_bytes_(MemoryInformationLength) PVOID MemoryInformation,
    _In_ SIZE_T MemoryInformationLength,
    _Out_opt_ PSIZE_T ReturnLength
    );

typedef NTSTATUS(NTAPI* fnRtlAdjustPrivilege)(
    _In_ ULONG Privilege,
    _In_ BOOLEAN Enable,
    _In_ BOOLEAN Client,
    _Out_ PBOOLEAN WasEnabled
    );

typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtCreateSection)(
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
    );

typedef NTSTATUS(NTAPI* fnNtMapViewOfSection)(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID* BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG Win32Protect
    );

typedef NTSTATUS(NTAPI* fnNtOpenDirectoryObject)(
    _Out_ PHANDLE DirectoryHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI* fnNtQueryDirectoryObject)(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* fnNtSuspendProcess)(
    _In_ HANDLE ProcessHandle
);

typedef NTSTATUS(NTAPI* fnNtResumeProcess)(
    _In_ HANDLE ProcessHandle
    );