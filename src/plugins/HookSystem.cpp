#include "HookSystem.hpp"
#include "../debug/Log.hpp"

#include <sys/mman.h>
#include <unistd.h>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>

CFunctionHook::CFunctionHook(HANDLE owner, void* source, void* destination) {
    m_pSource      = source;
    m_pDestination = destination;
    m_pOwner       = owner;
}

CFunctionHook::~CFunctionHook() {
    if (m_bActive)
        unhook();
}

bool CFunctionHook::hook() {

    // check for unsupported platforms
#if !defined(__x86_64__) || HYPRLAND_PATCH_SIZE < 0
    return false;
#endif

    // movabs $0,%rax | jmpq *%rax
    // offset for addr: 2
    static constexpr uint8_t ABSOLUTE_JMP_ADDRESS[]      = {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0};
    static constexpr size_t  ABSOLUTE_JMP_ADDRESS_OFFSET = 2;

    m_iHookLen = sizeof(ABSOLUTE_JMP_ADDRESS);

    if (HYPRLAND_PATCH_SIZE != m_iHookLen) {
        Debug::log(ERR, "Function patch size mismatch. Expected {} but got {}", m_iHookLen, HYPRLAND_PATCH_SIZE);
        return false;
    }

    // make jump to hk
    const auto     PAGESIZE_VAR = sysconf(_SC_PAGE_SIZE);
    const uint8_t* PROTSTART    = (uint8_t*)m_pSource - ((uint64_t)m_pSource % PAGESIZE_VAR);
    const size_t   PROTLEN      = std::ceil((float)(m_iHookLen + ((uint64_t)m_pSource - (uint64_t)PROTSTART)) / (float)PAGESIZE_VAR) * PAGESIZE_VAR;
    mprotect((uint8_t*)PROTSTART, PROTLEN, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy((uint8_t*)m_pSource, ABSOLUTE_JMP_ADDRESS, sizeof(ABSOLUTE_JMP_ADDRESS));

    // fixup jump addr
    *(uint64_t*)((uint8_t*)m_pSource + ABSOLUTE_JMP_ADDRESS_OFFSET) = (uint64_t)(m_pDestination);

    // revert mprot
    mprotect((uint8_t*)PROTSTART, PROTLEN, PROT_READ | PROT_EXEC);

    // set original addr to the source + sizeof(ABSOLUTE_JMP_ADDRESS) to skip the inserted jump
    m_pOriginal = (void *)((uint64_t)(m_pSource) + sizeof(ABSOLUTE_JMP_ADDRESS));

    m_bActive    = true;

    return true;
}

bool CFunctionHook::unhook() {
    // check for unsupported platforms
#if !defined(__x86_64__)
    return false;
#endif

    if (!m_bActive)
        return false;

    // allow write to src
    const auto     PAGESIZE_VAR = sysconf(_SC_PAGE_SIZE);
    const uint8_t* PROTSTART    = (uint8_t*)m_pSource - ((uint64_t)m_pSource % PAGESIZE_VAR);
    const size_t   PROTLEN      = std::ceil((float)(m_iHookLen + ((uint64_t)m_pSource - (uint64_t)PROTSTART)) / (float)PAGESIZE_VAR) * PAGESIZE_VAR;
    mprotect((uint8_t*)PROTSTART, PROTLEN, PROT_READ | PROT_WRITE | PROT_EXEC);

    // write back original bytes
    static constexpr uint8_t NOP = 0x90;
    memset(m_pSource, NOP, m_iHookLen);

    // revert mprot
    mprotect((uint8_t*)PROTSTART, PROTLEN, PROT_READ | PROT_EXEC);

    // reset vars
    m_bActive         = false;
    m_iHookLen        = 0;

    return true;
}

CFunctionHook* CHookSystem::initHook(HANDLE owner, void* source, void* destination) {
    return m_vHooks.emplace_back(std::make_unique<CFunctionHook>(owner, source, destination)).get();
}

bool CHookSystem::removeHook(CFunctionHook* hook) {
    std::erase_if(m_vHooks, [&](const auto& other) { return other.get() == hook; });
    return true; // todo: make false if not found
}

void CHookSystem::removeAllHooksFrom(HANDLE handle) {
    std::erase_if(m_vHooks, [&](const auto& other) { return other->m_pOwner == handle; });
}
