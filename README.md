# veh_hooking
x64 Function Hooking through VectoredExceptionHandler (PAGE_GUARD method)

Slow but anti-cheat safe

# How To Use
- Call veh::Setup()
- Hook functions through veh::Hook()

To call the original function from inside the hooked function, you must first unhook and then hook again afterwards
