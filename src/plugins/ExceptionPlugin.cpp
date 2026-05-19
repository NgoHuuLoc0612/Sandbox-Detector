#include "utils/SehCompat.hpp"
#include "plugins/ExceptionPlugin.hpp"
#include "utils/WinApiUtils.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#  define NOMINMAX
#endif
#include <windows.h>
#include <winternl.h>

#include <sstream>
#include <chrono>
#include <atomic>
#include <string>

// ─── Exception codes ────────────────────────────────────────
#ifndef STATUS_GUARD_PAGE_VIOLATION
#  define STATUS_GUARD_PAGE_VIOLATION  ((NTSTATUS)0x80000001L)
#endif
#ifndef STATUS_INVALID_HANDLE
#  define STATUS_INVALID_HANDLE        ((NTSTATUS)0xC0000008L)
#endif

namespace SandboxDetector {
namespace Plugins {

// ============================================================
//  Thread-local / atomic counters for VEH checks
// ============================================================

static std::atomic<uint32_t> g_vehCallCount{0};
static std::atomic<bool>     g_vehUnexpectedOrder{false};

// ============================================================
//  Construction / lifecycle
// ============================================================

ExceptionPlugin::ExceptionPlugin() {
    m_meta.id           = "com.sandboxdetector.exception";
    m_meta.name         = "Exception Handling Behavior Plugin";
    m_meta.version      = "1.0.0";
    m_meta.author       = "SandboxDetector";
    m_meta.description  = "Detects sandbox/VM via exception handling anomalies: "
                          "VEH invocation order, INT 2D/3, trap flag, CloseHandle "
                          "invalid handle trick, UnhandledExceptionFilter hook, "
                          "KiUserExceptionDispatcher patches, and RaiseException behavior.";
    m_meta.categories   = DetectionCategory::Exception;
    m_meta.priority     = 9;
    m_meta.requiresAdmin = false;
    m_meta.isDestructive = false;
}

ExceptionPlugin::~ExceptionPlugin() { shutdown(); }

const PluginMetadata& ExceptionPlugin::getMetadata() const noexcept { return m_meta; }
bool ExceptionPlugin::isSupported() const noexcept { return true; }

bool ExceptionPlugin::initialize(const PluginConfig& config) {
    m_config = config;
    return true;
}

void ExceptionPlugin::shutdown() noexcept {}

// ============================================================
//  run()
// ============================================================

PluginResult ExceptionPlugin::run() {
    PluginResult result;
    result.pluginId      = m_meta.id;
    result.pluginVersion = m_meta.version;
    result.executed      = true;

    auto t0 = std::chrono::steady_clock::now();

    auto push = [&](DetectionIndicator ind) {
        if (ind.confidence != SandboxConfidence::None)
            result.indicators.push_back(std::move(ind));
    };

    push(checkVehOrder());
    push(checkInt2d());
    push(checkTrapFlag());
    push(checkCloseHandleException());
    push(checkUnhandledExceptionFilter());
    push(checkKiUserExceptionDispatcherHook());
    push(checkRaiseExceptionInterception());
    push(checkInt3Delivery());

    auto t1 = std::chrono::steady_clock::now();
    result.executionTime = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0);

    result.sandboxDetected = !result.indicators.empty();
    result.overallConfidence = result.computeAggregateConfidence();

    return result;
}

// ============================================================
//  Check: VEH Invocation Order
// ============================================================

// VEH handler that increments a counter
static LONG CALLBACK vehCountHandler(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        g_vehCallCount.fetch_add(1, std::memory_order_relaxed);
        // Resume execution past the INT3
#ifdef _WIN64
        ep->ContextRecord->Rip++;
#else
        ep->ContextRecord->Eip++;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

DetectionIndicator ExceptionPlugin::checkVehOrder() {
    DetectionIndicator ind;
    ind.name     = "VEH Invocation Order";
    ind.category = DetectionCategory::Exception;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    g_vehCallCount.store(0, std::memory_order_relaxed);

    // Register two VEH handlers; both should see our INT3
    PVOID h1 = AddVectoredExceptionHandler(1, vehCountHandler);
    PVOID h2 = AddVectoredExceptionHandler(1, vehCountHandler);

    if (!h1 || !h2) {
        if (h1) RemoveVectoredExceptionHandler(h1);
        if (h2) RemoveVectoredExceptionHandler(h2);
        return ind;
    }

    // Raise an INT3
#ifdef _MSC_VER

    __try {
        __debugbreak();
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // SEH caught it before VEH — sandbox is eating exceptions
        ind.detail     = "EXCEPTION_BREAKPOINT from __debugbreak() was caught by SEH before VEH. "
                         "Sandbox is intercepting exception dispatch.";
        ind.confidence = SandboxConfidence::High;
        ind.rawValue   = 0;
    }
#else

    // SEH not available on non-MSVC compiler
#endif

    RemoveVectoredExceptionHandler(h1);
    RemoveVectoredExceptionHandler(h2);

    // If VEH was called, g_vehCallCount should be 2 (both handlers)
    uint32_t cnt = g_vehCallCount.load(std::memory_order_relaxed);
    ind.rawValue = cnt;

    if (ind.confidence == SandboxConfidence::None) {
        if (cnt == 0) {
            ind.detail     = "VEH handler was never called for INT3 exception. "
                             "Exception delivery suppressed by sandbox.";
            ind.confidence = SandboxConfidence::High;
        } else if (cnt == 1) {
            ind.detail     = "Only 1 of 2 VEH handlers was called for INT3. "
                             "Exception chain may be short-circuited.";
            ind.confidence = SandboxConfidence::Medium;
        }
    }
    return ind;
}

// ============================================================
//  Check: INT 2D
// ============================================================

DetectionIndicator ExceptionPlugin::checkInt2d() {
    DetectionIndicator ind;
    ind.name     = "INT 2D Debugger Trap";
    ind.category = DetectionCategory::Exception;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // INT 2D is used by Windows kernel for debug assertions.
    // When executed in user mode under a debugger, it raises EXCEPTION_BREAKPOINT.
    // Sandboxes often handle this and cause skipped bytes / altered EIP.
    bool exceptionRaised = false;
    uint32_t skipCount = 0;

#ifdef _MSC_VER

    __try {
#ifdef _WIN64
        __asm__ volatile (
            "xor %%eax, %%eax\n\t"
            "int $0x2d\n\t"
            "nop\n\t"
            ::: "eax"
        );
#else
        __asm {
            xor eax, eax
            int 0x2d
            nop
        }
#endif
    } __except (GetExceptionCode() == EXCEPTION_BREAKPOINT
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH) {
        exceptionRaised = true;
    }

    // Under a debugger, INT 2D increments EIP by 1 (skipping the NOP).
    // We can detect this by placing a sentinel byte after the NOP.
    // This is a heuristic; just report the exception raise itself.
    (void)skipCount;

    if (!exceptionRaised) {
        // On bare metal without debugger, INT 2D raises EXCEPTION_BREAKPOINT
        // If no exception was raised, the sandbox swallowed it.
        ind.detail     = "INT 2D did not raise EXCEPTION_BREAKPOINT. "
                         "Sandbox suppressed kernel debug interrupt delivery.";
        ind.confidence = SandboxConfidence::Medium;
        ind.rawValue   = 0;
    } else {
        ind.rawValue = 1;
        // Exception was raised — this is normal; check if EIP was advanced by exactly 1 or 0
        // (Distinguishing debugger vs normal requires additional asm — noted for future enhancement)
    }
#else
    // SEH / INT 2D check not available on non-MSVC compiler
#endif
    return ind;
}

// ============================================================
//  Check: Trap Flag (Single Step)
// ============================================================

static bool g_trapFlagFired = false;

static LONG CALLBACK trapFlagVehHandler(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        g_trapFlagFired = true;
        // Clear TF so we don't loop
        ep->ContextRecord->EFlags &= ~0x100UL;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

DetectionIndicator ExceptionPlugin::checkTrapFlag() {
    DetectionIndicator ind;
    ind.name     = "Trap Flag (EXCEPTION_SINGLE_STEP)";
    ind.category = DetectionCategory::Exception;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    g_trapFlagFired = false;

    PVOID hVeh = AddVectoredExceptionHandler(1, trapFlagVehHandler);
    if (!hVeh) return ind;

#ifdef _MSC_VER
    __try {
        // Set the trap flag in EFLAGS via pushf/or/popf
#ifdef _WIN64
        __asm__ volatile (
            "pushfq\n\t"
            "orq $0x100, (%%rsp)\n\t"
            "popfq\n\t"
            "nop\n\t"
            :::
        );
#else
        __asm {
            pushfd
            or dword ptr [esp], 0x100
            popfd
            nop
        }
#endif
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
#else
    // SEH not available on non-MSVC compiler; skip trap-flag check
#endif

    RemoveVectoredExceptionHandler(hVeh);

    ind.rawValue = g_trapFlagFired ? 1 : 0;
    if (!g_trapFlagFired) {
        ind.detail     = "Setting TF in EFLAGS did not produce EXCEPTION_SINGLE_STEP. "
                         "Sandbox is suppressing single-step exception delivery.";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

// ============================================================
//  Check: CloseHandle Exception Trick
// ============================================================

DetectionIndicator ExceptionPlugin::checkCloseHandleException() {
    DetectionIndicator ind;
    ind.name     = "CloseHandle Invalid Handle Exception";
    ind.category = DetectionCategory::Exception;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // Under a debugger: CloseHandle(0xDEADBEEF) raises EXCEPTION_INVALID_HANDLE
    // Under sandbox hooks that intercept CloseHandle: the exception may not be raised
    bool exceptionRaised = false;

#ifdef _MSC_VER

    __try {
        CloseHandle(reinterpret_cast<HANDLE>(static_cast<uintptr_t>(0xDEADBEEF)));
    } __except (GetExceptionCode() == STATUS_INVALID_HANDLE
                ? EXCEPTION_EXECUTE_HANDLER
                : EXCEPTION_CONTINUE_SEARCH) {
        exceptionRaised = true;
    }

    ind.rawValue = exceptionRaised ? 1 : 0;
    // Note: this exception is only raised when a kernel debugger is attached OR
    // when GFLAGS has the exception-on-bad-handle flag set.
    // So absence is NORMAL; presence indicates a debugger or special config.
    // We use absence as an indicator only when combined with other signals.
    // Presence = debugger.
    if (exceptionRaised) {
        ind.detail     = "CloseHandle(INVALID_HANDLE) raised STATUS_INVALID_HANDLE. "
                         "Kernel debugger attached or GFLAGS exception-on-bad-handle enabled.";
        ind.confidence = SandboxConfidence::High;
    }
#else
    // SEH not available on non-MSVC compiler; skip CloseHandle exception check
#endif
    return ind;
}

// ============================================================
//  Check: UnhandledExceptionFilter Hook
// ============================================================

static LONG WINAPI ourUef(EXCEPTION_POINTERS*) {
    return EXCEPTION_EXECUTE_HANDLER;
}

DetectionIndicator ExceptionPlugin::checkUnhandledExceptionFilter() {
    DetectionIndicator ind;
    ind.name     = "UnhandledExceptionFilter Hook";
    ind.category = DetectionCategory::Exception;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    // Set our UEF, then check if SetUnhandledExceptionFilter returns what we set previously.
    // Sandboxes often hook this to capture crashes and may return their own hook.
    LPTOP_LEVEL_EXCEPTION_FILTER prev = SetUnhandledExceptionFilter(ourUef);
    LPTOP_LEVEL_EXCEPTION_FILTER prev2 = SetUnhandledExceptionFilter(prev); // restore

    // Check if GetProcAddress for UnhandledExceptionFilter is hooked
    HMODULE hK32 = GetModuleHandleW(L"kernel32.dll");
    if (hK32) {
        FARPROC fn = GetProcAddress(hK32, "SetUnhandledExceptionFilter");
        if (fn) {
            const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);
            // Check for jmp at start (inline hook)
            if (p[0] == 0xE9 || p[0] == 0xEB) {
                ind.detail     = "SetUnhandledExceptionFilter is inline-hooked (starts with JMP). "
                                 "Sandbox is intercepting crash handlers.";
                ind.confidence = SandboxConfidence::High;
                ind.rawValue   = 1;
            }
        }
    }

    // If sandbox replaced our UEF with its own, prev2 won't be ourUef
    if (prev2 != ourUef && ind.confidence == SandboxConfidence::None) {
        ind.detail     = "SetUnhandledExceptionFilter returned unexpected filter pointer. "
                         "Sandbox may have replaced the UEF.";
        ind.confidence = SandboxConfidence::Medium;
        ind.rawValue   = 2;
    }
    return ind;
}

// ============================================================
//  Check: KiUserExceptionDispatcher Hook
// ============================================================

DetectionIndicator ExceptionPlugin::checkKiUserExceptionDispatcherHook() {
    DetectionIndicator ind;
    ind.name     = "KiUserExceptionDispatcher Hook";
    ind.category = DetectionCategory::Exception;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return ind;

    FARPROC fn = GetProcAddress(hNtdll, "KiUserExceptionDispatcher");
    if (!fn) return ind;

    const uint8_t* p = reinterpret_cast<const uint8_t*>(fn);

    // On unmodified ntdll, KiUserExceptionDispatcher starts with:
    // (x64): 48 8B 4C 24 ...  (mov rcx, [rsp+...])
    // (x86): 8B 4C 24 04 ...  (mov ecx, [esp+4])
    // A sandbox hook replaces the first bytes with a JMP or CALL

    bool hooked = false;
    std::string hookType;

    if (p[0] == 0xE9) {
        hooked = true; hookType = "JMP rel32";
    } else if (p[0] == 0xEB) {
        hooked = true; hookType = "JMP short";
    } else if (p[0] == 0xFF && p[1] == 0x25) {
        hooked = true; hookType = "JMP [rip+...]";
    } else if (p[0] == 0xCC) {
        hooked = true; hookType = "INT3 breakpoint";
    } else if (p[0] == 0x48 && p[1] == 0xB8) {
        // mov rax, imm64
        if (p[10] == 0xFF && p[11] == 0xE0) {
            hooked = true; hookType = "MOV RAX, imm64 / JMP RAX";
        }
    }

    ind.rawValue = hooked ? 1 : 0;
    if (hooked) {
        ind.detail     = "KiUserExceptionDispatcher is hooked (" + hookType + "). "
                         "Sandbox is intercepting all exception dispatch.";
        ind.confidence = SandboxConfidence::Certain;
    }
    return ind;
}

// ============================================================
//  Check: RaiseException Interception
// ============================================================

static std::atomic<bool> g_raiseExceptionCaught{false};

static LONG CALLBACK raiseVehHandler(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == 0xE0AABBCC) {
        g_raiseExceptionCaught.store(true, std::memory_order_relaxed);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

DetectionIndicator ExceptionPlugin::checkRaiseExceptionInterception() {
    DetectionIndicator ind;
    ind.name     = "RaiseException Interception";
    ind.category = DetectionCategory::Exception;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    g_raiseExceptionCaught.store(false, std::memory_order_relaxed);

    PVOID hVeh = AddVectoredExceptionHandler(1, raiseVehHandler);
    if (!hVeh) return ind;

#ifdef _MSC_VER
    __try {
        RaiseException(0xE0AABBCC, 0, 0, nullptr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // Normal: SEH catches it after VEH sees it
    }
#else
    // SEH not available on non-MSVC compiler; skip RaiseException interception check
#endif

    RemoveVectoredExceptionHandler(hVeh);

    bool vehSawIt = g_raiseExceptionCaught.load(std::memory_order_relaxed);
    ind.rawValue = vehSawIt ? 1 : 0;

    if (!vehSawIt) {
        ind.detail     = "RaiseException(0xE0AABBCC) was NOT seen by VEH before SEH. "
                         "Sandbox intercepted and short-circuited exception dispatch.";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

// ============================================================
//  Check: INT3 Delivery
// ============================================================

static std::atomic<bool> g_int3Delivered{false};

static LONG CALLBACK int3VehHandler(EXCEPTION_POINTERS* ep) {
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
        g_int3Delivered.store(true, std::memory_order_relaxed);
#ifdef _WIN64
        ep->ContextRecord->Rip++;
#else
        ep->ContextRecord->Eip++;
#endif
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

DetectionIndicator ExceptionPlugin::checkInt3Delivery() {
    DetectionIndicator ind;
    ind.name     = "INT3 Exception Delivery";
    ind.category = DetectionCategory::Exception;
    ind.confidence = SandboxConfidence::None;
    ind.rawValue   = 0;

    g_int3Delivered.store(false, std::memory_order_relaxed);

    PVOID hVeh = AddVectoredExceptionHandler(1, int3VehHandler);
    if (!hVeh) return ind;

#ifdef _MSC_VER

    __try {
        // Emit a raw INT3 byte
#ifdef _WIN64
        __asm__ volatile("int3" :::);
#else
        __asm { int 3 }
#endif
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // SEH caught without VEH seeing it
    }
#else

    // SEH not available on non-MSVC compiler
#endif

    RemoveVectoredExceptionHandler(hVeh);

    bool delivered = g_int3Delivered.load(std::memory_order_relaxed);
    ind.rawValue = delivered ? 1 : 0;

    if (!delivered) {
        ind.detail     = "INT3 exception was not delivered to VEH handler. "
                         "Sandbox is intercepting breakpoint exceptions.";
        ind.confidence = SandboxConfidence::High;
    }
    return ind;
}

} // namespace Plugins
} // namespace SandboxDetector
