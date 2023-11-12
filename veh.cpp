#include "veh.h"

void veh::Setup()
{
    GetSystemInfo(&system_info);
    handle = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
}

bool veh::Hook(void* source, void* destination)
{
    if (!handle)
        return false;

    MEMORY_BASIC_INFORMATION source_info;
    if (!VirtualQuery(source, &source_info, sizeof(MEMORY_BASIC_INFORMATION)))
        return false;

    MEMORY_BASIC_INFORMATION destination_info;
    if (!VirtualQuery(destination, &destination_info, sizeof(MEMORY_BASIC_INFORMATION)))
        return false;

    if (source_info.AllocationBase == destination_info.AllocationBase)
        return false;

    hooks.push_back({ source, destination });
    DWORD tmp;
    VirtualProtect(source, system_info.dwPageSize, PAGE_EXECUTE_READ | PAGE_GUARD, &tmp);
    return true;
}

void veh::Destroy()
{
    std::vector<HookInfo_t> _hooks(hooks);
    hooks.clear();

    for (HookInfo_t& hook_info : _hooks)
    {
        DWORD tmp;
        VirtualProtect(hook_info.source, system_info.dwPageSize, PAGE_EXECUTE_READ, &tmp);
    }

    RemoveVectoredExceptionHandler(handle);
    handle = nullptr;
}

LONG veh::VectoredExceptionHandler(EXCEPTION_POINTERS* exception_info)
{
    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
    {
        for (HookInfo_t& hook_info : hooks)
        {
            if (exception_info->ExceptionRecord->ExceptionAddress == hook_info.source)
            {
#ifdef _WIN64
                exception_info->ContextRecord->Rip = (DWORD64)hook_info.destination;
#else
                exception_info->ContextRecord->Eip = (DWORD)hook_info.destination;
#endif
            }
        }

        exception_info->ContextRecord->EFlags |= PAGE_GUARD;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        for (HookInfo_t& hook_info : hooks)
        {
            DWORD tmp;
            VirtualProtect(hook_info.source, system_info.dwPageSize, PAGE_EXECUTE_READ | PAGE_GUARD, &tmp);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
