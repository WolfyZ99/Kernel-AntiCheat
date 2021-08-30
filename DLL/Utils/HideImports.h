#pragma once

NTSYSAPI ULONG NTAPI RtlRandomEx(PULONG Seed);
NTSYSAPI VOID NTAPI RtlExitUserProcess(NTSTATUS);
NTSYSAPI NTSTATUS NTAPI NtLoadDriver(PUNICODE_STRING);
NTSYSAPI NTSTATUS NTAPI NtUnloadDriver(PUNICODE_STRING);
extern "C" NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);
NTSYSAPI NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);
NTSYSAPI NTSTATUS NTAPI LdrLoadDll(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
NTSYSAPI NTSTATUS NTAPI RtlGetVersion(LPOSVERSIONINFOEXW);
NTSYSAPI PVOID NTAPI RtlImageDirectoryEntryToData(_In_ PVOID ImageBase, _In_ BOOLEAN MappedAsImage, _In_ USHORT DirectoryEntry, _Out_ PULONG Size);

uintptr_t GetNtDll()
{
	//get ntdll base
#if defined _M_IX86
	PPEB_LDR_DATA Ldr = ((PTEB)__readfsdword(FIELD_OFFSET(NT_TIB, Self)))->ProcessEnvironmentBlock->Ldr;
#elif defined _M_X64
	PPEB_LDR_DATA Ldr = ((PTEB)__readgsqword(FIELD_OFFSET(NT_TIB, Self)))->ProcessEnvironmentBlock->Ldr;
#endif

	//process modules
	for (PLIST_ENTRY CurEnt = Ldr->InMemoryOrderModuleList.Flink; CurEnt != &Ldr->InMemoryOrderModuleList; CurEnt = CurEnt->Flink) {
		PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(CurEnt, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
		if ((pEntry->BaseDllName.Length == 18) && (*(uint64_t*)pEntry->BaseDllName.Buffer == 0x6C00640074006E))
			return (uintptr_t)pEntry->DllBase;
	} return 0;
}
uintptr_t GetNtDll64_Export(const char* Name)
{
	//parse info
	static uintptr_t hNtDll = 0;
	static PIMAGE_EXPORT_DIRECTORY ExportDir = nullptr;
	if (!hNtDll) {
		hNtDll = GetNtDll();
		PIMAGE_NT_HEADERS NT_Head = (PIMAGE_NT_HEADERS)(hNtDll + ((PIMAGE_DOS_HEADER)hNtDll)->e_lfanew);
		ExportDir = (PIMAGE_EXPORT_DIRECTORY)(hNtDll + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);
	}

	//process list
	for (uint32_t i = 0; i < ExportDir->NumberOfNames; i++)
	{
		//get ordinal & name
		uint16_t Ordinal = ((uint16_t*)(hNtDll + ExportDir->AddressOfNameOrdinals))[i];
		const char* ExpName = (const char*)hNtDll + ((uint32_t*)(hNtDll + ExportDir->AddressOfNames))[i];

		//check name
		for (int i = 0; ExpName[i] == Name[i]; i++) if (!ExpName[i])
			return hNtDll + ((uint32_t*)(hNtDll + ExportDir->AddressOfFunctions))[Ordinal];
	} return 0;
}

//LoadLibrary & GetProcAddr
uintptr_t LoadLibUnc(UNICODE_STRING Mod)
{
	typedef NTSTATUS(__stdcall* _LdrLoadDll)(PWCHAR, PULONG, PUNICODE_STRING, HMODULE*);
	static _LdrLoadDll LdrLoadDllFn = nullptr; HMODULE hMod;
	if (!LdrLoadDllFn) LdrLoadDllFn = (_LdrLoadDll)GetNtDll64_Export(xorstr_("LdrLoadDll"));
	LdrLoadDllFn(nullptr, nullptr, &Mod, &hMod); return (uintptr_t)hMod;
}
uintptr_t GetProcAddrAnsi(uintptr_t Mod, ANSI_STRING Func)
{
	typedef NTSTATUS(__stdcall* _LdrGetProcAddr)(HMODULE, PANSI_STRING, WORD, PVOID*);
	static _LdrGetProcAddr LdrGetProcAddr = nullptr; void* FuncAddr;
	if (!LdrGetProcAddr) LdrGetProcAddr = (_LdrGetProcAddr)GetNtDll64_Export(xorstr_("LdrGetProcedureAddress"));
	LdrGetProcAddr((HMODULE)Mod, &Func, 0, &FuncAddr); return (uintptr_t)FuncAddr;
}

//Secure Call Func
#define UNC_STR(a) { sizeof(a) - 2, sizeof(a), (PWSTR)xorstr_(a) }
#define ANS_STR(a) { sizeof(a) - 1, sizeof(a), (PCHAR)xorstr_(a) }

#define GetModHandle(Mod) LoadLibUnc({ sizeof(L#Mod) - 2, sizeof(L#Mod), (PWSTR)xorstr_(L#Mod) });
#define GetProc(Mod, Name) GetProcAddrAnsi(Mod, { sizeof(#Name) - 1, sizeof(#Name), (PCHAR)xorstr_(#Name) });

#define FC(Mod, Name, ...) [&](){ \
	static uintptr_t ModBase = 0; \
	if(!ModBase) \
		ModBase = LoadLibUnc({ sizeof(L#Mod) - 2, sizeof(L#Mod), (PWSTR)xorstr_(L#Mod) }); \
	static uintptr_t Func = 0; \
	if (!Func) \
		Func = GetProcAddrAnsi(ModBase, { sizeof(#Name) - 1, sizeof(#Name), (PCHAR)xorstr_(#Name) }); \
	using _OVar = decltype(&Name); \
	return _OVar(Func)(__VA_ARGS__); \
}()

#define FC_err(Mod, Name, Tmplt, ...) [&](){ \
	static uintptr_t ModBase = 0; \
	if(!ModBase) \
		ModBase = LoadLibUnc({ sizeof(L#Mod) - 2, sizeof(L#Mod), (PWSTR)xorstr_(L#Mod) }); \
	static uintptr_t Func = 0; \
	if (!Func) \
		Func = GetProcAddrAnsi(ModBase, { sizeof(#Name) - 1, sizeof(#Name), (PCHAR)xorstr_(#Name) }); \
	using _OVar = decltype(&Tmplt); \
	return _OVar(Func)(__VA_ARGS__); \
}()

char* __CRTDECL strstrFn(char* const _String, char const* const _SubString);
wchar_t* __cdecl wcsstrFn(const wchar_t* Str, const wchar_t* SubStr);
errno_t __cdecl wcscpy_sFn(wchar_t* Dst, rsize_t SizeInWords, const wchar_t* Src);

NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(
	HANDLE    ProcessHandle,
	PVOID* BaseAddress,
	ULONG_PTR ZeroBits,
	PSIZE_T   RegionSize,
	ULONG     AllocationType,
	ULONG     Protect
);

NTSYSAPI
NTSTATUS
NTAPI
NtSetTimerResolution(



	IN ULONG                DesiredResolution,
	IN BOOLEAN              SetResolution,
	OUT PULONG              CurrentResolution);

//ntdll funcs
#define NtClose(a) FC(ntdll, NtClose, a)
#define strlen(a) FC(ntdll, strlen, a)
#define strstr(...) FC_err(ntdll, strstr, strstrFn, __VA_ARGS__)
#define memset(a, b) FC(ntdll, memset, a, 0, b)
#define memcpy(...) FC(ntdll, memcpy, __VA_ARGS__)
#define wcscat(...) FC(ntdll, wcscat, __VA_ARGS__)
#define wcscpy(a, b) FC(ntdll, wcscpy, a, b)
#define NtDeviceIoControlFile(...) FC(ntdll, NtDeviceIoControlFile, __VA_ARGS__)
#define wcscpy_s(...) FC_err(ntdll, wcscpy_s, wcscpy_sFn, __VA_ARGS__)
#define wcslen(...) FC(ntdll, wcslen, __VA_ARGS__)
#define RtlGetVersion(a) FC(ntdll, RtlGetVersion, a)
#define ExitProcess() FC(ntdll, RtlExitUserProcess, 0)
#define NtOpenFile(...) FC(ntdll, NtOpenFile, __VA_ARGS__)
#define NtQuerySystemInformation(...) FC(ntdll, NtQuerySystemInformation, __VA_ARGS__)
#define NtSetTimerResolution(...) FC(ntdll, NtSetTimerResolution, __VA_ARGS__)
#define RtlImageDirectoryEntryToData(...) FC(ntdll, RtlImageDirectoryEntryToData, __VA_ARGS__)

//Shell32 funcs
#define CommandLineToArgvW(a, b) FC(shell32, CommandLineToArgvW, a, b)

//Kernel32 funcs
#define Sleep(a) FC(kernel32, Sleep, a)
#define LocalFree(a) FC(kernel32, LocalFree, a)
#define GetModuleFileNameW(...) FC(kernel32, GetModuleFileNameW, __VA_ARGS__)
#define GetModuleHandleW(...) FC(kernel32, GetModuleHandleW, __VA_ARGS__)
#define VirtualQuery(...) FC(kernel32, VirtualQuery, __VA_ARGS__)
#define FreeLibrary(a) FC(kernel32, FreeLibrary, a)
#define GetCommandLineW() FC(kernel32, GetCommandLineW)
#define LoadLibraryA(a) FC(kernel32, LoadLibraryA, a)
#define GetConsoleWindow() FC(kernel32, GetConsoleWindow)
#define ReadFile(...) FC(kernel32, ReadFile, __VA_ARGS__)
#define WriteFile(...) FC(kernel32, WriteFile, __VA_ARGS__)
#define free(a) FC(kernel32, VirtualFree, a, 0, MEM_RELEASE)
#define SetConsoleTitleW(a) FC(kernel32, SetConsoleTitleW, a)
#define MoveFileExW(...) FC(kernel32, MoveFileExW, __VA_ARGS__)
#define CreateFileW(...) FC(kernel32, CreateFileW, __VA_ARGS__)
#define CloseHandle(...) FC(kernel32, CloseHandle, __VA_ARGS__)
#define DeleteFileW(...) FC(kernel32, DeleteFileW, __VA_ARGS__)
#define GetFileSize(...) FC(kernel32, GetFileSize, __VA_ARGS__)
#define GetCurrentProcessId() FC(kernel32, GetCurrentProcessId)
#define GetTempPathW(...) FC(kernel32, GetTempPathW, __VA_ARGS__)
#define MapViewOfFile(...) FC(kernel32, MapViewOfFile, __VA_ARGS__)
#define WriteConsoleA(...) FC(kernel32, WriteConsoleA, __VA_ARGS__)
#define GetConsoleOutHandle() FC(kernel32, GetStdHandle, STD_OUTPUT_HANDLE);
#define DeviceIoControl(...) FC(kernel32, DeviceIoControl, __VA_ARGS__)
#define UnmapViewOfFile(...) FC(kernel32, UnmapViewOfFile, __VA_ARGS__)
//#define LoadLibraryExA(a, b) FC(kernel32, LoadLibraryExA, a, nullptr, b)
#define CreateFileMappingA(...) FC(kernel32, CreateFileMappingA, __VA_ARGS__)
#define GetProcAddress(...) (uintptr_t)FC(kernel32, GetProcAddress, __VA_ARGS__)
#define SetConsoleTextAttribute(...) FC(kernel32, SetConsoleTextAttribute, __VA_ARGS__)
#define GetConsoleScreenBufferInfo(...) FC(kernel32, GetConsoleScreenBufferInfo, __VA_ARGS__)
#define malloc(a) FC(kernel32, VirtualAlloc, nullptr, a, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
#define Wow64DisableWow64FsRedirection(...) FC(kernel32, Wow64DisableWow64FsRedirection, __VA_ARGS__)
#define Wow64RevertWow64FsRedirection(...) FC(kernel32, Wow64RevertWow64FsRedirection, __VA_ARGS__)
#define GetFileSize(...) FC(kernel32, GetFileSize, __VA_ARGS__)
#define IsBadReadPtr(...) FC(kernel32, IsBadReadPtr, __VA_ARGS__)
#define CreateProcessW(...) FC(kernel32, CreateProcessW, __VA_ARGS__)
#define CreateThread(...) FC(kernel32, CreateThread, __VA_ARGS__)
#define GetProcessId(...) FC(kernel32, GetProcessId, __VA_ARGS__)

//Advapi32 funcs
#define RegOpenKeyA(...) FC(advapi32, RegOpenKeyA, __VA_ARGS__)
#define RegCloseKey(...) FC(advapi32, RegCloseKey, __VA_ARGS__)
#define RegCreateKeyW(...) FC(advapi32, RegCreateKeyW, __VA_ARGS__)
#define RegDeleteKeyW(...) FC(advapi32, RegDeleteKeyW, __VA_ARGS__)
#define RegSetValueExA(...) FC(advapi32, RegSetValueExA, __VA_ARGS__)
#define RegSetValueExW(...) FC(advapi32, RegSetValueExW, __VA_ARGS__)
#define OpenProcessToken(...) FC(advapi32, OpenProcessToken, __VA_ARGS__)
#define LookupPrivilegeValueA(...) FC(advapi32, LookupPrivilegeValueA, __VA_ARGS__)
#define AdjustTokenPrivileges(...) FC(advapi32, AdjustTokenPrivileges, __VA_ARGS__)
#define CryptCreateHash(...) FC(advapi32, CryptCreateHash, __VA_ARGS__)
#define CryptHashData(...) FC(advapi32, CryptHashData, __VA_ARGS__)
#define CryptGetHashParam(...) FC(advapi32, CryptGetHashParam, __VA_ARGS__)
#define CryptDestroyHash(...) FC(advapi32, CryptDestroyHash, __VA_ARGS__)
#define CryptReleaseContext(...) FC(advapi32, CryptReleaseContext, __VA_ARGS__)

//Crypt32 funcs
#define CertFindCertificateInStore(...) FC(crypt32, CertFindCertificateInStore, __VA_ARGS__)
#define CryptMsgGetParam(...) FC(crypt32, CryptMsgGetParam, __VA_ARGS__)
#define CryptQueryObject(...) FC(crypt32, CryptQueryObject, __VA_ARGS__)
#define CertGetNameStringW(...) FC(crypt32, CertGetNameStringW, __VA_ARGS__)
#define CertFreeCertificateContext(...) FC(crypt32, CertFreeCertificateContext, __VA_ARGS__)
#define CertCloseStore(...) FC(crypt32, CertCloseStore, __VA_ARGS__)
#define CryptMsgClose(...) FC(crypt32, CryptMsgClose, __VA_ARGS__)

//User32 funcs
#define FindWindowW(...) FC(user32, FindWindowW, __VA_ARGS__)
#define EnableWindow(...) FC(user32, EnableWindow, __VA_ARGS__)
#define SetWindowsHookExW(...) FC(user32, SetWindowsHookExW, __VA_ARGS__)
#define UnhookWindowsHookEx(...) FC(user32, UnhookWindowsHookEx, __VA_ARGS__)
#define PostThreadMessageW(...) FC(user32, PostThreadMessageW, __VA_ARGS__)
#define GetWindowThreadProcessId(...) FC(user32, GetWindowThreadProcessId, __VA_ARGS__)

//FltLib funcs
#define FltSendMessage(...) FC(FltLib, FilterSendMessage, __VA_ARGS__)
#define FltGetMessage(...) FC(FltLib, FilterGetMessage, __VA_ARGS__)
#define FltConnectCommunicationPort(...) FC(FltLib, FilterConnectCommunicationPort, __VA_ARGS__)
#define FltReplyMessage(...) FC(FltLib, FilterReplyMessage, __VA_ARGS__)

//wintrust funcs
#define CryptCATAdminAcquireContext(...) FC(wintrust, CryptCATAdminAcquireContext, __VA_ARGS__)
#define CryptCATAdminCalcHashFromFileHandle(...) FC(wintrust, CryptCATAdminCalcHashFromFileHandle, __VA_ARGS__)
#define CryptCATAdminEnumCatalogFromHash(...) FC(wintrust, CryptCATAdminEnumCatalogFromHash, __VA_ARGS__)
#define CryptCATCatalogInfoFromContext(...) FC(wintrust, CryptCATCatalogInfoFromContext, __VA_ARGS__)
#define WinVerifyTrust(...) FC(wintrust, WinVerifyTrust, __VA_ARGS__)
#define CryptCATAdminReleaseCatalogContext(...) FC(wintrust, CryptCATAdminReleaseCatalogContext, __VA_ARGS__)
#define CryptCATAdminReleaseContext(...) FC(wintrust, CryptCATAdminReleaseContext, __VA_ARGS__)

uint32_t getRand()
{
	uint32_t seed = (uint32_t)__rdtsc();
	return FC(ntdll, RtlRandomEx, (PULONG)&seed);
}

//inline funcs
#define SizeAlign(a) ((a + 4095) & 0xFFFFF000)

void toWchar(wchar_t* Dst, const char* Str)
{
	for (;; Str++, Dst++)
	{
		char Tmp = *Str;
		*Dst = Tmp;
		if (!Tmp)
			break;
	}
}

void toChar(char* Dst, const wchar_t* Str)
{
	for (;; Str++, Dst++)
	{
		wchar_t Tmp = *Str;
		*Dst = (char)Tmp;
		if (!Tmp)
			break;
	}
}