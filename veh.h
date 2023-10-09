#pragma once
#include <Windows.h>
#include <vector>

struct HookInfo_t
{
    void* source;
    void* destination;
};

namespace veh
{
    bool Setup();
    bool Hook(void* source, void* destination);
    bool Unhook(void* source);
    bool UnhookAll();
    bool AreInSamePage(void* first, void* second);
    LONG VectoredExceptionHandler(EXCEPTION_POINTERS* exception_info);

    template <typename ReturnType, typename Prototype, typename... Args>
    ReturnType CallOriginal(Prototype source, Args... args);

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

    DWORD tmp;
    if (!VirtualProtect(source, system_info.dwPageSize, PAGE_EXECUTE_READ | PAGE_GUARD, &tmp))
        return false;

    HookInfo_t new_hook
    {
        source,
        destination
    };

    hooks.push_back(new_hook);
    return true;
}

bool veh::Unhook(void* source)
{
    bool lonely_hook = true;

    for (HookInfo_t& hook_info : veh::hooks)
    {
        if (hook_info.source == source)
        {
            for (HookInfo_t& _hook_info : hooks)
            {
                if (hook_info.source != _hook_info.source && AreInSamePage(hook_info.source, _hook_info.source))
                {
                    lonely_hook = false;
                    break;
                }
            }
        }

        break;
    }

    if (lonely_hook)
    {
        DWORD tmp;
        if (!VirtualProtect(source, system_info.dwPageSize, PAGE_EXECUTE_READ, &tmp))
            return false;
    }

    hooks.erase(std::remove_if(hooks.begin(), hooks.end(), [&](const HookInfo_t& hook_info)
        {
            return hook_info.source == source;
        }));

    return true;
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
    MEMORY_BASIC_INFORMATION source_info;
    if (!VirtualQuery(first, &source_info, sizeof(MEMORY_BASIC_INFORMATION)))
        return true;

    MEMORY_BASIC_INFORMATION destination_info;
    if (!VirtualQuery(second, &destination_info, sizeof(MEMORY_BASIC_INFORMATION)))
        return true;

    return (source_info.BaseAddress == destination_info.BaseAddress);
}

LONG veh::VectoredExceptionHandler(EXCEPTION_POINTERS* exception_info)
{
    if (exception_info->ExceptionRecord->ExceptionCode == EXCEPTION_GUARD_PAGE)
    {
        for (HookInfo_t& hook_info : hooks)
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
        for (HookInfo_t& hook : hooks)
        {
            DWORD tmp;
            VirtualProtect(hook.source, system_info.dwPageSize, PAGE_EXECUTE_READ | PAGE_GUARD, &tmp);
        }

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    return EXCEPTION_CONTINUE_SEARCH;
}

template <typename ReturnType, typename Prototype, typename... Args>
ReturnType veh::CallOriginal(Prototype source, Args... args)
{
    ReturnType result{};

    for (HookInfo_t& hook_info : hooks)
    {
        if (hook_info.source == source)
        {
            Unhook(source);
            result = source(args...);
            Hook(source, hook_info.destination);
        }
    }

    return result;
}
