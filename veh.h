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
    void Destroy();
    bool AreInSamePage(void* first, void* second);
    LONG VectoredExceptionHandler(EXCEPTION_POINTERS* exception_info);

    template <typename ReturnType, typename Prototype, typename... Args>
    ReturnType CallOriginal(Prototype source, Args... args);

    inline SYSTEM_INFO system_info;
    inline PVOID handler;
    inline std::vector<HookInfo_t> hooks;
}

template <typename ReturnType, typename Prototype, typename... Args>
ReturnType veh::CallOriginal(Prototype source, Args... args)
{
    for (HookInfo_t hook_info : hooks)
    {
        if (hook_info.source == source)
        {
            Unhook(source);
            ReturnType result = source(args...);
            Hook(source, hook_info.destination);
            return result;
        }
    }

    return source(args...);
}
