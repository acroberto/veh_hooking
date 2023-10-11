# veh_hooking
x64 Function Hooking through VectoredExceptionHandler (PAGE_GUARD method)

Slow but anti-cheat safe

# How To Use
- Call veh::Setup()
- Hook functions through veh::Hook()
- In the end unhook functions with veh::Unhook / veh::UnhookAll and call veh::Destroy()

To call the original function use veh::CallOriginal<ReturnType>(original, args)

# Example

```cpp
bool hk(void* csgo_input, uint32_t a2, uint8_t a3)
{
    typedef bool(*create_move_t)(void*, uint32_t, uint8_t);
    static create_move_t create_move = FindPattern<create_move_t>("client.dll", "48 8B C4 48 89 48 08 55 53 41 56 41 57");
    
    bool result = veh::CallOriginal<bool>(create_move, csgo_input, a2, a3);

    std::cout << "hooked" << std::endl;

    return result;
}

int entry(HMODULE hModule)
{
    AllocConsole();
    FILE* file;
    freopen_s(&file, "CONOUT$", "w", stdout);

    void* create_move = FindPattern<void*>("client.dll", "48 8B C4 48 89 48 08 55 53 41 56 41 57");

    veh::Setup();
    veh::Hook(create_move, hk);

    Sleep(10000);

    veh::UnhookAll();
    veh::Destroy();

    fclose(stdout);
    FreeConsole();
    FreeLibraryAndExitThread(hModule, 0);
    return 0;
}
```
