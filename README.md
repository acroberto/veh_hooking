# veh_hooking
x64 Function Hooking through VectoredExceptionHandler (PAGE_GUARD method)

Slow but anti-cheat safe

# How To Use
- Call veh::Setup()
- Hook functions through veh::Hook()
- When done unhook functions (veh::Unhook / veh::UnhookAll) and call veh::Destroy()

To call the original function use veh::CallOriginal<ReturnType>(original, args)
