#pragma once
// SehCompat.hpp
// Portability shim: map MSVC Structured Exception Handling macros to
// GCC/Clang equivalents using __try/__except GNU extensions or no-ops.
//
// On MSVC: the real keywords work natively.
// On GCC/MinGW (Windows target): __try/__except are not supported;
//   we provide graceful no-op fallbacks so the code still compiles.
//   The checks that rely on SEH will simply report SandboxConfidence::None.

#ifndef _MSC_VER

// GCC/Clang: No native SEH. Provide no-op macros so the code compiles.
// The __try block executes normally; exceptions become crashes (expected on
// real Windows with signal handlers, but SEH-based detection is disabled).
#ifndef __try
#  define __try        if (true)
#endif
#ifndef __except
#  define __except(x)  else if (false)
#endif
#ifndef __finally
#  define __finally    if (true)
#endif

#ifndef GetExceptionCode
#  define GetExceptionCode() (0UL)
#endif

#endif // !_MSC_VER
