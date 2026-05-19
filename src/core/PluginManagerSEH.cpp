#include "utils/SehCompat.hpp"
// PluginManagerSEH.cpp
// Compiled without /EHa (/EHs-c-) so __try/__except works correctly.
// IMPORTANT: No C++ objects with destructors can be declared or assigned
// inside the __try block — only POD types and raw pointers are safe.

#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include "core/IPlugin.hpp"

namespace SandboxDetector {

struct SehRunResult {
    bool  succeeded;
    DWORD exceptionCode;
};

// Thin trampoline: calls plugin->run() via a raw function pointer to keep
// the __try frame free of C++ object construction/destruction.
static void callRun(IPlugin* plugin, PluginResult* out) noexcept(false)
{
    *out = plugin->run();
    out->executed = true;
}

SehRunResult runPluginWithSEH(IPlugin* plugin, PluginResult* outResult)
{
    SehRunResult r;
    r.succeeded     = false;
    r.exceptionCode = 0;

    // Use a function pointer so the compiler sees no C++ object lifetime
    // in this frame, satisfying /EHs-c- and avoiding C2712.
    void (*pfn)(IPlugin*, PluginResult*) = &callRun;

#ifdef _MSC_VER
    __try {
        pfn(plugin, outResult);
        r.succeeded = true;
    }
    __except (r.exceptionCode = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {
        outResult->executed = false;
    }
#else
    // On non-MSVC (MinGW/GCC), SEH is unavailable.
    // Run plugin directly; C++ exceptions propagate normally.
    try {
        pfn(plugin, outResult);
        r.succeeded = true;
    } catch (...) {
        outResult->executed = false;
        r.exceptionCode = 0xFFFFFFFF; // sentinel: unknown exception
    }
#endif

    return r;
}

} // namespace SandboxDetector
