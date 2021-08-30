
#include "Globals.h"

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    FILE* pFile = nullptr;
    AllocConsole();
    freopen_s(&pFile, "CONOUT$", "w", stdout);

    std::cout << E("Hello from client!\n");

    Loader::LoadDriver(E("C:\\Windows\\System32\\drivers\\WolfyZ_NtDrv.sys"), E("WolfyZ_NtDrv.sys"));

    OverlayWindow = GetConsoleWindow();

    STARTUPINFOW SA = { 0 };
    PROCESS_INFORMATION PI = { 0 };

    if (!CreateProcessW(E(L"ProtectionTest.exe"), NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &SA, &PI))
    {
        printf(E("Failed to start protected process: %d\n"), GetLastError());
        Sleep(4000);
        return false;
    }

    GamePID = GetProcessId(PI.hProcess); 

    std::cout << E("Status: ") << Driver::GetStatus() << std::endl;
  
    Driver::SendNtOffsets();
    CreateThread(0, 0, (LPTHREAD_START_ROUTINE)Server::SendThread, 0, 0, 0);

    while (!GetAsyncKeyState(VK_END))
        Sleep(30);

    Loader::UnloadDriver(E("WolfyZ_NtDrv.sys"));

    Sleep(5000);
    return 1;
}
