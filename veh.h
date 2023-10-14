#pragma once
#include <Windows.h>
#include <vector>

struct HookInfo_t
{
    void* source;
    void* destination;

    bool operator==(HookInfo_t& other) { return (source == other.source && destination == other.destination); }
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
    inline PVOID handle;
    inline std::vector<HookInfo_t> hooks;
}

template <typename ReturnType, typename Prototype, typename... Args>
ReturnType veh::CallOriginal(Prototype source, Args... args)
{
    DWORD old_protection;
    VirtualProtect(source, system_info.dwPageSize, PAGE_EXECUTE_READ, &old_protection);
    ReturnType result = source(args...);
    VirtualProtect(source, system_info.dwPageSize, old_protection, &old_protection);
    return result;
}
