
#include "Globals.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            std::cout << E("Hello from dll\n");
            MH_Initialize();

            DisableThreadLibraryCalls(hModule);

            Hooks::InitializeHooks();

        } break;

//    case DLL_THREAD_ATTACH:
 //   case DLL_THREAD_DETACH:

        case DLL_PROCESS_DETACH:
        {
            
        } break;

        default:
            break;
    }
    return TRUE;
}

