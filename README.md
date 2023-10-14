# veh_hooking
x64/x86 Function Hooking through VectoredExceptionHandler (PAGE_GUARD method)

Anti-cheat safe with little to no impact on performance

# How To Use
- Call veh::Setup()
- Hook functions through veh::Hook()
- In the end unhook functions with veh::Unhook / veh::UnhookAll and call veh::Destroy()

To call the original function use veh::CallOriginal<ReturnType>(original, args)

# Example

```cpp
bool hooks::CreateMove_hk(void* csgo_input, uint32_t a2, uint8_t a3)
{
    bool result = veh::CallOriginal<bool>(CreateMove, csgo_input, a2, a3);

    std::cout << "createmove called" << std::endl;

    return result;
}

int MainThread(HMODULE hModule)
{
    AllocConsole();
    FILE* file;
    freopen_s(&file, "CONOUT$", "w", stdout);

    veh::Setup();
    veh::Hook(hooks::CreateMove, hooks::CreateMove_hk);

    while (!GetAsyncKeyState(VK_END))
        Sleep(100);

    veh::UnhookAll();
    veh::Destroy();

    fclose(stdout);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}
```
