#pragma once

namespace Hooks
{
	using def_LoadLibraryA = decltype(&LoadLibraryA);
    using def_LoadLibraryW = decltype(&LoadLibraryW);
    using def_LoadLibraryExA = decltype(&LoadLibraryExA);
    using def_LoadLibraryExW = decltype(&LoadLibraryExW);

	def_LoadLibraryA fn_LoadLibraryA = nullptr, o_LoadLibraryA = nullptr;
    def_LoadLibraryW fn_LoadLibraryW = nullptr, o_LoadLibraryW = nullptr;
    def_LoadLibraryExA fn_LoadLibraryExA = nullptr, o_LoadLibraryExA = nullptr;
    def_LoadLibraryExW fn_LoadLibraryExW = nullptr, o_LoadLibraryExW = nullptr;

    HMODULE hk_LoadLibraryA(LPCSTR lpLibFileName)
    {
        std::string sFileName = lpLibFileName;
        std::wstring wFileName = std::wstring(sFileName.begin(), sFileName.end());

        if (Utils::IsFileAllowed((wchar_t*)wFileName.c_str()))
        {
            printf("DLL %ws is allowed!\n", wFileName.c_str());
            return o_LoadLibraryA(lpLibFileName);
        }

        printf("DLL %ws is blocked!\n", wFileName.c_str());
		return (HMODULE)0;
	}

    HMODULE hk_LoadLibraryW(LPCWSTR lpLibFileName)
    {
        if (Utils::IsFileAllowed((wchar_t*)lpLibFileName))
        {
            printf("DLL %ws is allowed!\n", lpLibFileName);
            return o_LoadLibraryW(lpLibFileName);
        }

        printf("DLL %ws is blocked!\n", lpLibFileName);
        return (HMODULE)0;
    }

    HMODULE hk_LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        std::string sFileName = lpLibFileName;
        std::wstring wFileName = std::wstring(sFileName.begin(), sFileName.end());

        if (Utils::IsFileAllowed((wchar_t*)wFileName.c_str()))
        {
            printf("DLL %ws is allowed!\n", wFileName.c_str());
            return fn_LoadLibraryExA(lpLibFileName, hFile, dwFlags);
        }

        printf("DLL %ws is blocked!\n", wFileName.c_str());
        return (HMODULE)0;
    }

    HMODULE hk_LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
    {
        if (Utils::IsFileAllowed((wchar_t*)lpLibFileName))
        {
            printf("DLL %ws is allowed!\n", lpLibFileName);
            return o_LoadLibraryExW(lpLibFileName, hFile, dwFlags);
        }

        printf("DLL %ws is blocked!\n", lpLibFileName);
        return (HMODULE)0;
    }

	bool InitializeHooks()
	{
        uint64_t Kernel32 = GetModHandle(kernel32);

        fn_LoadLibraryA = (def_LoadLibraryA)GetProc(Kernel32, LoadLibraryA);
        fn_LoadLibraryW = (def_LoadLibraryW)GetProc(Kernel32, LoadLibraryW);
        fn_LoadLibraryExA = (def_LoadLibraryExA)GetProc(Kernel32, LoadLibraryExA);
        fn_LoadLibraryExW = (def_LoadLibraryExW)GetProc(Kernel32, LoadLibraryExW);

        printf("LoadLibraryA: 0x%llX\n", fn_LoadLibraryA);
        printf("LoadLibraryW: 0x%llX\n", fn_LoadLibraryW);
        printf("LoadLibraryExA: 0x%llX\n", fn_LoadLibraryExA);
        printf("LoadLibraryExW: 0x%llX\n", fn_LoadLibraryExW); 
  
        MH_CreateHook(fn_LoadLibraryA, hk_LoadLibraryA, reinterpret_cast<LPVOID*>(&o_LoadLibraryA));
        MH_EnableHook(fn_LoadLibraryA);

        MH_CreateHook(fn_LoadLibraryW, hk_LoadLibraryW, reinterpret_cast<LPVOID*>(&o_LoadLibraryW));
        MH_EnableHook(fn_LoadLibraryW);

        MH_CreateHook(fn_LoadLibraryExA, hk_LoadLibraryExA, reinterpret_cast<LPVOID*>(&o_LoadLibraryExA));
        MH_EnableHook(fn_LoadLibraryExA);

        MH_CreateHook(fn_LoadLibraryExW, hk_LoadLibraryExW, reinterpret_cast<LPVOID*>(&o_LoadLibraryExW));
        MH_EnableHook(fn_LoadLibraryExW);

		return true;
	}
}


/*    void* DetourFunction64(void* pSource, void* pDestination, int dwLen)
    {
        DWORD MinLen = 14;

        if (dwLen < MinLen) return NULL;

        BYTE stub[] =
        {
            0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, // jmp qword ptr [$+6]
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 // ptr
        };

        void* pTrampoline = VirtualAlloc(0, dwLen + sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        DWORD dwOld = 0;
        VirtualProtect(pSource, dwLen, PAGE_EXECUTE_READWRITE, &dwOld);

        DWORD64 retto = (DWORD64)pSource + dwLen;

        memcpy(stub + 6, &retto, 8);
        memcpy((void*)((DWORD_PTR)pTrampoline), pSource, dwLen);
        memcpy((void*)((DWORD_PTR)pTrampoline + dwLen), stub, sizeof(stub));

        memcpy(stub + 6, &pDestination, 8);
        memcpy(pSource, stub, sizeof(stub));

        for (int i = MinLen; i < dwLen; i++)
        {
            *(BYTE*)((DWORD_PTR)pSource + i) = 0x90;
        }

        VirtualProtect(pSource, dwLen, dwOld, &dwOld);
        return (void*)((DWORD_PTR)pTrampoline);
    } */