#include <MinHook.h>
#include <chrono>
#include <sstream>
#include <string>

typedef FARPROC(WINAPI *TrueGetProcAddress)(HMODULE, LPCSTR);
TrueGetProcAddress originalGetProcAddress = nullptr;

extern "C" unsigned int AG_Init_Hook(unsigned short nCode, void *vp);
using AG_Init_Type = decltype(&AG_Init_Hook);
AG_Init_Type gAGInit = nullptr;
AG_Init_Type gOriginAGInit = nullptr;

extern "C" unsigned int AG_Init_Hook(unsigned short nCode, void *vp)
{
    if (nCode == 0x314)
    {
        auto start = std::chrono::high_resolution_clock::now();
        int ret = gOriginAGInit(nCode, vp);
        auto end = std::chrono::high_resolution_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        std::ostringstream oss;
        oss << "Flash executed in " << duration.count() << " milliseconds";
        MessageBoxA(NULL, oss.str().c_str(), "Flash Done", 0);
        return ret;
    }

    return gOriginAGInit(nCode, vp);
}

FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    if ((ULONG_PTR)lpProcName > USHRT_MAX && strcmp(lpProcName, "AG_Init") == 0)
    {
        auto addr = originalGetProcAddress(hModule, lpProcName);
        if (addr == nullptr)
        {
            MessageBoxA(NULL, "Failed to init", NULL, 0);
            return addr;
        }

        if (gAGInit)
        {
            MH_DisableHook(gAGInit);
            MH_RemoveHook(gAGInit);
        }
        gAGInit = reinterpret_cast<AG_Init_Type>(addr);

        if (MH_CreateHook(addr, &AG_Init_Hook, reinterpret_cast<void **>(&gOriginAGInit)) == MH_OK &&
            MH_EnableHook(addr) == MH_OK)
        {
        }
        else
        {
            MessageBoxA(NULL, "Failed to hook!", NULL, 0);
        }

        return addr;
    }

    return originalGetProcAddress(hModule, lpProcName);
}

void InstallHooks()
{
    MH_Initialize();
    MH_CreateHook(&GetProcAddress, &HookedGetProcAddress, reinterpret_cast<void **>(&originalGetProcAddress));
    MH_EnableHook(&GetProcAddress);
}

void UninstallHooks()
{
    MH_DisableHook(&GetProcAddress);
    MH_RemoveHook(&GetProcAddress);
    if (gAGInit)
    {
        MH_DisableHook(gAGInit);
        MH_RemoveHook(gAGInit);
    }
    MH_Uninitialize();
}

DWORD WINAPI InitHook(LPVOID lpParam)
{
    InstallHooks();
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(nullptr, 0, InitHook, nullptr, 0, nullptr);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        UninstallHooks();
        break;
    }
    return TRUE;
}

// make windows dll importer happy
extern "C" __declspec(dllexport) int dummy_export()
{
    return 0;
}
