#pragma once
#include "Global.hpp"

fnNtCreateSection g_pNtCreateSection;
fnNtResumeProcess g_pNtResumeProcess;
fnNtSuspendProcess g_pNtSuspendProcess;
fnNtMapViewOfSection g_pNtMapViewOfSection;
fnNtQueryInformationProcess g_pNtQueryInformationProcess;
fnNtQuerySystemInformation g_pNtQuerySystemInformation;
fnNtQueryVirtualMemory g_pNtQueryVirtualMemory;
std::vector<std::wstring> dlls;

BOOL InitFuncs();
BOOL InitKnownDllList();

BOOL Init() {

	if (!InitFuncs())
		return false;

	if (!InitKnownDllList())
		return false;

	return true;
}

BOOL InitFuncs() {

	HMODULE hNtdll = GetModuleHandle(TEXT("NTDLL.DLL"));

	if (!hNtdll)
		return false;

	g_pNtCreateSection = reinterpret_cast<fnNtCreateSection>(GetProcAddress(hNtdll, "NtCreateSection"));
	g_pNtResumeProcess = reinterpret_cast<fnNtResumeProcess>(GetProcAddress(hNtdll, "NtResumeProcess"));
	g_pNtSuspendProcess = reinterpret_cast<fnNtSuspendProcess>(GetProcAddress(hNtdll, "NtSuspendProcess"));
	g_pNtMapViewOfSection = reinterpret_cast<fnNtMapViewOfSection>(GetProcAddress(hNtdll, "NtMapViewOfSection"));
	g_pNtQueryVirtualMemory = reinterpret_cast<fnNtQueryVirtualMemory>(GetProcAddress(hNtdll, "NtQueryVirtualMemory"));
	g_pNtQuerySystemInformation = reinterpret_cast<fnNtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
	g_pNtQueryInformationProcess = reinterpret_cast<fnNtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
	
	if (!g_pNtCreateSection || !g_pNtMapViewOfSection || !g_pNtQueryInformationProcess || !g_pNtQuerySystemInformation || !g_pNtQueryVirtualMemory || !g_pNtSuspendProcess || !g_pNtResumeProcess)
		return false;

	return true;
}

BOOL InitKnownDllList() {

	NTSTATUS	STATUS = 0x00;
	ULONG		ulRetLen = 0;
	ULONG		ulContext = 0;
	HANDLE		hDir = nullptr;
	
	OBJECT_ATTRIBUTES	objAttr = { 0 };
	UNICODE_STRING		usString = { 0 };

	HMODULE		hNtdll = GetModuleHandle(TEXT("NTDLL.DLL"));

	fnNtOpenDirectoryObject pNtOpenDirectoryObject = reinterpret_cast<fnNtOpenDirectoryObject>(GetProcAddress(hNtdll, "NtOpenDirectoryObject"));
	fnNtQueryDirectoryObject pNtQueryDirectoryObject = reinterpret_cast<fnNtQueryDirectoryObject>(GetProcAddress(hNtdll, "NtQueryDirectoryObject"));

	if (!pNtOpenDirectoryObject || !pNtQueryDirectoryObject)
		return false;

	usString.Buffer = (PWSTR)KNOWN;
	usString.Length = wcslen(KNOWN) * sizeof(WCHAR);
	usString.MaximumLength = usString.Length + sizeof(WCHAR);

	InitializeObjectAttributes(&objAttr, &usString, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

	STATUS = pNtOpenDirectoryObject(&hDir, DIRECTORY_QUERY | DIRECTORY_TRAVERSE, &objAttr);

	if (!NT_SUCCESS(STATUS) || hDir == nullptr)
		return false;

	BYTE buffer[1024];
	OBJECT_DIRECTORY_INFORMATION* pInfo = (OBJECT_DIRECTORY_INFORMATION*)buffer;

	while (true) {

		STATUS = pNtQueryDirectoryObject(hDir, pInfo, sizeof(buffer), true, false, &ulContext, &ulRetLen);

		if (STATUS == STATUS_NO_MORE_ENTRIES) {
			break;
		}

		if (!NT_SUCCESS(STATUS)) {
			std::printf("[!] Failed to query KnownDlls: 0x%0.8X\n", STATUS);
			break;
		}

		for (OBJECT_DIRECTORY_INFORMATION* pInfoEntry = pInfo; pInfoEntry->Name.Length != 0; pInfoEntry++) {
			dlls.push_back(pInfoEntry->Name.Buffer);
		}
	}

	std::wstring junk = L"KnownDllPath";
	auto it = std::remove(dlls.begin(), dlls.end(), junk);
	if (it != dlls.end()) {
		dlls.erase(it, dlls.end());
	}

	CloseHandle(hDir);
	
	return true;
}