#pragma once
#include <Windows.h>
#include <vector>

LONG Handler(EXCEPTION_POINTERS* exception_info);

namespace veh
{
    bool Setup();
    bool Hook(uintptr_t original, uintptr_t hook);
    bool Unhook(uintptr_t original);
    bool UnhookAll();
    bool AreInSamePage(uintptr_t first, uintptr_t second);

    inline PVOID handler;
    inline std::vector<std::pair<uintptr_t, uintptr_t>> hooks;
}

bool veh::Setup()
{
    handler = AddVectoredExceptionHandler(1, Handler);

    return handler;
}

bool veh::Hook(uintptr_t original, uintptr_t hook)
{
    if (!handler)
        return false;

    if (AreInSamePage(original, hook))
        return false;

    DWORD tmp;
    if (VirtualProtect((LPVOID)original, 0x1000, PAGE_EXECUTE_READ | PAGE_GUARD, &tmp))
    {
        hooks.push_back(std::make_pair(original, hook));
        return true;
    }

	return false;
}

bool veh::Unhook(uintptr_t original)
{
    DWORD tmp;
    if (VirtualProtect((LPVOID)original, 0x1000, PAGE_EXECUTE_READ, &tmp))
    {
        for (std::pair<uintptr_t, uintptr_t>& hook : hooks)
        {
            if (hook.first == original)
            {
                hooks.erase(std::remove(hooks.begin(), hooks.end(), hook), hooks.end());
                return true;
            }
        }
    }

    return false;
}

bool veh::UnhookAll()
{
    bool result = true;

    for (std::pair<uintptr_t, uintptr_t>& hook : hooks)
    {
        if (!Unhook(hook.first))
        {
            result = false;
        }
    }

    return result;
}

bool veh::AreInSamePage(uintptr_t first, uintptr_t second)
{
    MEMORY_BASIC_INFORMATION info1;
    if (!VirtualQuery((LPCVOID)first, &info1, sizeof(MEMORY_BASIC_INFORMATION)))
        return true;

    MEMORY_BASIC_INFORMATION info2;
    if (!VirtualQuery((LPCVOID)second, &info2, sizeof(MEMORY_BASIC_INFORMATION)))
        return true;

    return (info1.BaseAddress == info2.BaseAddress);
}

LONG Handler(EXCEPTION_POINTERS* exception_info)
{
    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
    {
        for (std::pair<uintptr_t, uintptr_t>& hook : veh::hooks)
        {
            if (exception_info->ContextRecord->Rip == hook.first)
            {
                exception_info->ContextRecord->Rip = hook.second;
            }
        }

        exception_info->ContextRecord->EFlags |= PAGE_GUARD;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        for (std::pair<uintptr_t, uintptr_t>& hook : veh::hooks)
        {
            DWORD tmp;
            VirtualProtect((LPVOID)hook.first, 0x1000, PAGE_EXECUTE_READ | PAGE_GUARD, &tmp);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
