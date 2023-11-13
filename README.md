# veh_hooking
x64/x86 Function Hooking through VectoredExceptionHandler (PAGE_GUARD method)

Anti-cheat safe in most games with little performance loss in some situations

# How To Use
- Call veh::Setup()
- Hook functions through veh::Hook(old, new)
- Unhook functions with veh::Destroy() (you will need to call veh::Setup() again if you wanna hook functions again)

To call the original function from inside the hook function use veh::CallOriginal<ReturnType>(original, args)

# Example
```cpp

void hooks::Setup()
{
    veh::Setup();
    veh::Hook(Present, Present_hk);
    veh::Hook(CreateMove, CreateMove_hk);
}

void hooks::Destroy()
{
    veh::Destroy();

    if (ImGui::GetCurrentContext())
    {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
    }
}

bool hooks::CreateMove_hk(CCSGOInput* csgo_input, uint32_t slot, uint64_t a3, uint8_t a4)
{
    bool result = veh::CallOriginal<bool>(CreateMove, csgo_input, slot, a3, a4);

    if (!globals::Update() || !globals::local_pawn->m_pGameSceneNode())
        return result;

    CUserCmd* user_cmd = csgo_input->GetUserCmd(slot);
    globals::view_angles = user_cmd->base_user_cmd->msg_qangle->angles;
    globals::shoot_position = globals::local_pawn->m_pGameSceneNode()->m_vecAbsOrigin() + globals::local_pawn->m_vecViewOffset();

    aim_assist::Tick(user_cmd, csgo_input, slot);
    triggerbot::Tick(user_cmd);
    misc::AutoFire(user_cmd);

    return result;
}
```
