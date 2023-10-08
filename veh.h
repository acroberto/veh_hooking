#pragma once
#include <Windows.h>
#include <vector>

LONG VectoredExceptionHandler(EXCEPTION_POINTERS* exception_info);

struct HookInfo_t
{
    void* source;
    void* destination;
    DWORD old_protection;
};

namespace veh
{
    bool Setup();
    bool Hook(void* source, void* destination);
    bool Unhook(void* source);
    bool UnhookAll();
    bool AreInSamePage(void* first, void* second);

    inline SYSTEM_INFO system_info;
    inline PVOID handler;
    inline std::vector<HookInfo_t> hooks;
}

bool veh::Setup()
{
    GetSystemInfo(&system_info);
    handler = AddVectoredExceptionHandler(1, VectoredExceptionHandler);

    return handler;
}

bool veh::Hook(void* source, void* destination)
{
    if (!handler)
        return false;

    if (AreInSamePage(source, destination))
        return false;

    MEMORY_BASIC_INFORMATION info;
    if (!VirtualQuery(source, &info, sizeof(MEMORY_BASIC_INFORMATION)))
        return false;
    
    DWORD old_protection;
    if (VirtualProtect(source, system_info.dwPageSize, info.Protect | PAGE_GUARD, &old_protection))
    {
        HookInfo_t new_hook
        {
            source,
            destination,
            old_protection
        };

        hooks.push_back(new_hook);
        return true;
    }

	return false;
}

bool veh::Unhook(void* source)
{
    for (HookInfo_t& hook_info : hooks)
    {
        if (hook_info.source == source)
        {
            DWORD tmp;
            if (!VirtualProtect(source, system_info.dwPageSize, hook_info.old_protection, &tmp))
                return false;

            hooks.erase(std::remove_if(hooks.begin(), hooks.end(), [&hook_info](const HookInfo_t& element)
                {
                    return element.source == hook_info.source;
                }));

            return true;
        }
    }

    return false;
}

bool veh::UnhookAll()
{
    bool result = true;

    for (HookInfo_t& hook_info : hooks)
    {
        if (!Unhook(hook_info.source))
        {
            result = false;
        }
    }

    return result;
}

bool veh::AreInSamePage(void* first, void* second)
{
    MEMORY_BASIC_INFORMATION info1;
    if (!VirtualQuery(first, &info1, sizeof(MEMORY_BASIC_INFORMATION)))
        return true;

    MEMORY_BASIC_INFORMATION info2;
    if (!VirtualQuery(second, &info2, sizeof(MEMORY_BASIC_INFORMATION)))
        return true;

    return (info1.BaseAddress == info2.BaseAddress);
}

LONG VectoredExceptionHandler(EXCEPTION_POINTERS* exception_info)
{
    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
    {
        for (HookInfo_t& hook_info : veh::hooks)
        {
            if (exception_info->ContextRecord->Rip == (DWORD64)hook_info.source)
            {
                exception_info->ContextRecord->Rip = (DWORD64)hook_info.destination;
            }
        }

        exception_info->ContextRecord->EFlags |= PAGE_GUARD;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        for (HookInfo_t& hook : veh::hooks)
        {
            DWORD tmp;
            VirtualProtect(hook.source, veh::system_info.dwPageSize, hook.old_protection | PAGE_GUARD, &tmp);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}
