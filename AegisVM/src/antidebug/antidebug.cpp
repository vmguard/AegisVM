#include "antidebug.h"
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <intrin.h>
#include <algorithm>
#include <chrono>
#include <cstdlib>

#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "psapi.lib")

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace AegisVM {

    bool AntiDebug::debuggerDetected() const {
        return debuggerDetectedFlag != 0;
    }

    // Dynamicallly resolve ntapis, make hooking more annoying

    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
        HANDLE ProcessHandle, PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation, ULONG ProcessInformationLength, PULONG ReturnLength);

    typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);

    typedef NTSTATUS(NTAPI* pNtQueryObject)(
        HANDLE Handle, OBJECT_INFORMATION_CLASS ObjectInformationClass,
        PVOID ObjectInformation, ULONG ObjectInformationLength, PULONG ReturnLength);

    typedef NTSTATUS(NTAPI* pNtSetInformationThread)(
        HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation, ULONG ThreadInformationLength);

    typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(
        HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass,
        PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

    typedef NTSTATUS(NTAPI* pNtSetDebugFilterState)(ULONG ComponentId, ULONG Level, BOOLEAN State);
    typedef NTSTATUS(NTAPI* pNtYieldExecution)(VOID);


    void* AntiDebug::getNtQueryInformationProcess() {
        static auto proc = (pNtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
        return proc;
    }

    void* AntiDebug::getNtQuerySystemInformation() {
        static auto proc = (pNtQuerySystemInformation)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        return proc;
    }

    void* AntiDebug::getNtQueryObject() {
        static auto proc = (pNtQueryObject)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryObject");
        return proc;
    }

    void* AntiDebug::getNtSetInformationThread() {
        static auto proc = (pNtSetInformationThread)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtSetInformationThread");
        return proc;
    }

    void* AntiDebug::getNtQueryInformationThread() {
        static auto proc = (pNtQueryInformationThread)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");
        return proc;
    }

    void* AntiDebug::getNtSetDebugFilterState() {
        static auto proc = (pNtSetDebugFilterState)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtSetDebugFilterState");
        return proc;
    }

    void* AntiDebug::getNtYieldExecution() {
        static auto proc = (pNtYieldExecution)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtYieldExecution");
        return proc;
    }


    bool AntiDebug::initialize() {
        if (initialized) return true;

        setupExceptionHandling();
        enableThreadHideFromDebugger();
        if (checkIsDebuggerPresent() || checkRemoteDebuggerPresent()) {
            InterlockedExchange(&debuggerDetectedFlag, 1);
        }

        initialized = true;
        return true;
    }

    void AntiDebug::shutdown() {
        if (initialized) {
            disableThreadHideFromDebugger();
            initialized = false;
            threadHidden = false;
        }
    }


    bool AntiDebug::isDebuggerPresent() {
        if (checkIsDebuggerPresent() ||
            checkRemoteDebuggerPresent() ||
            checkDebugPort() ||
            checkDebugObjectHandle() ||
            checkProcessDebugFlags() ||
            checkSoftwareBreakpoints() ||
            checkHardwareBreakpoints()) {
            InterlockedExchange(&debuggerDetectedFlag, 1);
            return true;
        }

        if (checkSystemKernelDebugger()) {
            InterlockedExchange(&debuggerDetectedFlag, 1);
            return true;
        }

        // decided to require multiple independent hits to reduce false positives
        uint32_t hits = 0;

        if (checkNtGlobalFlag())          ++hits;
        if (checkHeapFlags())             ++hits;
        if (checkTimingAttacks())         ++hits;
        if (checkApiHooks())              ++hits;
        if (checkInlineHooking())         ++hits;
        if (checkIATHooking())            ++hits;
        if (checkModuleHooking())         ++hits;
        if (checkMemoryBreakpoints())     ++hits;
        if (checkMemoryProtection())      ++hits;
        if (checkBreakOnTermination())    ++hits;
        if (checkNtSetDebugFilterState()) ++hits;
        if (checkThreadHideFromDebugger())++hits;
        if (checkDrivers())               ++hits;

        bool detected = hits >= 2;
        if (detected) InterlockedExchange(&debuggerDetectedFlag, 1);
        return detected;
    }


    void AntiDebug::takeAction() {
        InterlockedExchange(&debuggerDetectedFlag, 1);
    }

    void AntiDebug::removeDebugger() {
        InterlockedExchange(&debuggerDetectedFlag, 1);
    }

    void AntiDebug::crashProcess() {
        __try {
            volatile int* p = nullptr;
            *p = 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
    }

    void AntiDebug::exitProcess() {
        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
        while (true) {
            __fastfail(FAST_FAIL_FATAL_APP_EXIT);
        }
    }


    bool AntiDebug::checkIsDebuggerPresent() {
        return IsDebuggerPresent() != FALSE;
    }

    bool AntiDebug::checkRemoteDebuggerPresent() {
        BOOL remote = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote)) {
            return remote != FALSE;
        }
        return false;
    }


    bool AntiDebug::checkDebugPort() {
        auto proc = (pNtQueryInformationProcess)getNtQueryInformationProcess();
        if (!proc) return false;

        DWORD debugPort = 0;
        ULONG retLen = 0;
        NTSTATUS status = proc(GetCurrentProcess(), (PROCESSINFOCLASS)7,
            &debugPort, sizeof(debugPort), &retLen);
        return NT_SUCCESS(status) && debugPort != 0;
    }

    bool AntiDebug::checkDebugObjectHandle() {
        auto proc = (pNtQueryInformationProcess)getNtQueryInformationProcess();
        if (!proc) return false;

        HANDLE hDebugObject = nullptr;
        ULONG retLen = 0;
        NTSTATUS status = proc(GetCurrentProcess(), (PROCESSINFOCLASS)0x1E,
            &hDebugObject, sizeof(hDebugObject), &retLen);
        return NT_SUCCESS(status) && hDebugObject != nullptr;
    }

    bool AntiDebug::checkProcessDebugFlags() {
        auto proc = (pNtQueryInformationProcess)getNtQueryInformationProcess();
        if (!proc) return false;

        ULONG flags = 0;
        ULONG retLen = 0;
        NTSTATUS status = proc(GetCurrentProcess(), (PROCESSINFOCLASS)0x1F,
            &flags, sizeof(flags), &retLen);
        // ProcessDebugFlags: non-debugged processes typically report NO_DEBUG_INHERIT (1)
        return NT_SUCCESS(status) && flags == 0;
    }

    bool AntiDebug::checkBreakOnTermination() {
        auto proc = (pNtQueryInformationProcess)getNtQueryInformationProcess();
        if (!proc) return false;

        ULONG breakOnTerm = 0;
        ULONG retLen = 0;
        NTSTATUS status = proc(GetCurrentProcess(), (PROCESSINFOCLASS)0x1D,
            &breakOnTerm, sizeof(breakOnTerm), &retLen);
        return NT_SUCCESS(status) && breakOnTerm != 0;
    }

    bool AntiDebug::checkSystemKernelDebugger() {
        auto proc = (pNtQuerySystemInformation)getNtQuerySystemInformation();
        if (!proc) return false;

        struct KDBG_INFO {
            BOOLEAN KernelDebuggerEnabled;
            BOOLEAN KernelDebuggerNotPresent;
        } info = {};

        ULONG retLen = 0;
        NTSTATUS status = proc((SYSTEM_INFORMATION_CLASS)0x92,
            &info, sizeof(info), &retLen);
        return NT_SUCCESS(status) && info.KernelDebuggerEnabled && !info.KernelDebuggerNotPresent;
    }

    bool AntiDebug::checkNtSetDebugFilterState() {
        auto proc = (pNtSetDebugFilterState)getNtSetDebugFilterState();
        if (!proc) return false;

        NTSTATUS status = proc(0, 0, TRUE);
        return NT_SUCCESS(status);
    }


    bool AntiDebug::checkNtGlobalFlag() {
        auto proc = (pNtQueryInformationProcess)getNtQueryInformationProcess();
        if (!proc) return false;

        PROCESS_BASIC_INFORMATION pbi = {};
        ULONG retLen = 0;
        NTSTATUS status = proc(GetCurrentProcess(), ProcessBasicInformation,
            &pbi, sizeof(pbi), &retLen);
        if (!NT_SUCCESS(status) || !pbi.PebBaseAddress) return false;

        __try {
            const uint8_t* peb = reinterpret_cast<const uint8_t*>(pbi.PebBaseAddress);
#ifdef _WIN64
            constexpr size_t kOffset = 0xBC;
#else
            constexpr size_t kOffset = 0x68;
#endif
            ULONG ntGlobalFlag = *reinterpret_cast<const ULONG*>(peb + kOffset);
            return (ntGlobalFlag & 0x70) != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool AntiDebug::checkHeapFlags() {
        HANDLE hHeap = GetProcessHeap();
        if (!hHeap) return false;

        __try {
#ifdef _WIN64
            // SEH guards against segment heap differences
            ULONG flags = *(ULONG*)((BYTE*)hHeap + 0x70);
            ULONG forceFlags = *(ULONG*)((BYTE*)hHeap + 0x74);
#else
            ULONG flags = *(ULONG*)((BYTE*)hHeap + 0x40);
            ULONG forceFlags = *(ULONG*)((BYTE*)hHeap + 0x44);
#endif
            return (flags & 0x40000060) != 0 || forceFlags != 0;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    bool AntiDebug::checkSoftwareBreakpoints() {
        HMODULE hMod = GetModuleHandle(nullptr);
        if (!hMod) return false;

        const uint8_t* base = reinterpret_cast<const uint8_t*>(hMod);
        const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        DWORD entryRva = nt->OptionalHeader.AddressOfEntryPoint;
        if (entryRva == 0) return false;

        const uint8_t* entry = base + entryRva;
        __try {
            if (*entry == 0xCC) return true;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }

        struct Check { const char* dll; const char* func; };
        Check checks[] = {
            { "kernel32.dll", "IsDebuggerPresent" },
            { "kernel32.dll", "CheckRemoteDebuggerPresent" },
            { "ntdll.dll", "NtQueryInformationProcess" },
            { nullptr, nullptr }
        };

        for (int i = 0; checks[i].dll; i++) {
            HMODULE hDll = GetModuleHandleA(checks[i].dll);
            if (!hDll) continue;
            void* func = GetProcAddress(hDll, checks[i].func);
            if (!func) continue;

            __try {
                if (*(uint8_t*)func == 0xCC) return true;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }
        return false;
    }

    bool AntiDebug::checkHardwareBreakpoints() {
        CONTEXT ctx = {};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

        if (!GetThreadContext(GetCurrentThread(), &ctx)) return false;

        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
            return true;

        if ((ctx.Dr7 & 0xFF) != 0)
            return true;

        return false;
    }

    bool AntiDebug::checkMemoryBreakpoints() {
        SYSTEM_INFO si;
        GetSystemInfo(&si);

        BYTE* addr = (BYTE*)si.lpMinimumApplicationAddress;
        MEMORY_BASIC_INFORMATION mbi;

        while (addr < si.lpMaximumApplicationAddress) {
            if (!VirtualQuery(addr, &mbi, sizeof(mbi))) break;

            if (mbi.State == MEM_COMMIT) {
                __try {
                    if ((mbi.Protect & PAGE_GUARD) || (mbi.Protect & PAGE_NOACCESS)) {
                        if (mbi.Type == MEM_IMAGE) return true;
                    }
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                }
            }
            if (mbi.RegionSize == 0) break;
            addr += mbi.RegionSize;
        }
        return false;
    }

    bool AntiDebug::checkMemoryProtection() {
        HMODULE hMod = GetModuleHandle(nullptr);
        if (!hMod) return false;

        BYTE* addr = (BYTE*)hMod;
        MEMORY_BASIC_INFORMATION mbi;

        while (VirtualQuery(addr, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_IMAGE) {
                if (mbi.Protect == PAGE_EXECUTE_READWRITE)
                    return true;
            }
            if (mbi.RegionSize == 0) break;
            addr += mbi.RegionSize;
        }
        return false;
    }

    bool AntiDebug::checkRdtscCpuid() {
        uint64_t tsc1 = __rdtsc();
        int cpuInfo[4];
        __cpuid(cpuInfo, 0);
        uint64_t tsc2 = __rdtsc();

        // CPUID serializes, single step tracing often inflates this
        return (tsc2 - tsc1) > 5000;
    }

    bool AntiDebug::checkSleepTiming() {
        LARGE_INTEGER freq, start, end;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        Sleep(50);
        QueryPerformanceCounter(&end);

        double elapsedMs = ((end.QuadPart - start.QuadPart) * 1000.0) / freq.QuadPart;
        // Very short or very long sleep can indicate time manipulation / debugging artifacts
        return elapsedMs < 30.0 || elapsedMs > 300.0;
    }

    bool AntiDebug::performTimingCheck() {
        auto start = std::chrono::high_resolution_clock::now();
        volatile int x = 0;
        for (int i = 0; i < 100000; i++) {
            x += i;
        }
        auto end = std::chrono::high_resolution_clock::now();
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        return ms > 500; 
    }

    bool AntiDebug::checkTimingAttacks() {
        int hits = 0;
        if (checkRdtscCpuid())   ++hits;
        if (checkSleepTiming())  ++hits;
        if (performTimingCheck())++hits;
        return hits >= 2;
    }

    uint64_t AntiDebug::getRdtsc() {
        return __rdtsc();
    }

    uint64_t AntiDebug::measureTime() {
        return getRdtsc();
    }


    bool AntiDebug::checkDrivers() {
        // Weak signal: some antiantidebug tools inject these usermode modules
        const char* dlls[] = {
            "dbk64.dll", "dbk32.dll", "dbvm64.dll", "scylla.dll",
            "x64dbg.dll", "ollydbg.dll", nullptr
        };

        for (int i = 0; dlls[i]; i++) {
            if (isDriverLoaded(dlls[i])) return true;
        }
        return false;
    }


    bool AntiDebug::checkApiHooks() {
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        if (!hKernel32) return false;

        void* p1 = GetProcAddress(hKernel32, "IsDebuggerPresent");
        void* p2 = GetProcAddress(hKernel32, "CheckRemoteDebuggerPresent");

        auto isHooked = [](void* p) -> bool {
            if (!p) return false;
            __try {
                uint8_t* b = (uint8_t*)p;
                return (b[0] == 0xE9 || b[0] == 0xEB || b[0] == 0xE8 || b[0] == 0xCC);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) { return false; }
            };

        return isHooked(p1) || isHooked(p2);
    }

    bool AntiDebug::checkInlineHooking() {
        struct Check { const char* dll; const char* func; };
        Check checks[] = {
            { "kernel32.dll", "IsDebuggerPresent" },
            { "kernel32.dll", "CheckRemoteDebuggerPresent" },
            { "ntdll.dll", "NtQueryInformationProcess" },
            { "ntdll.dll", "NtSetInformationThread" },
            { "ntdll.dll", "NtClose" },
            { "user32.dll", "FindWindowA" },
            { "user32.dll", "FindWindowW" },
            { "kernel32.dll", "GetTickCount" },
            { "kernel32.dll", "GetTickCount64" },
            { "kernel32.dll", "QueryPerformanceCounter" },
            { "kernel32.dll", "CloseHandle" },
            { nullptr, nullptr }
        };

        for (int i = 0; checks[i].dll; i++) {
            HMODULE hDll = GetModuleHandleA(checks[i].dll);
            if (!hDll) continue;
            void* func = GetProcAddress(hDll, checks[i].func);
            if (!func) continue;

            __try {
                uint8_t* b = (uint8_t*)func;
                if (b[0] == 0xE9 || b[0] == 0xEB || b[0] == 0xE8 || b[0] == 0xCC) return true;
                if (b[0] == 0xFF && b[1] == 0x25) return true;          // JMP [mem]
                if (b[0] == 0x68 && b[5] == 0xC3) return true;          // PUSH / RET
#ifdef _WIN64
                if (b[0] == 0x48 && b[1] == 0xB8) {                     // MOV RAX, imm64
                    if (b[10] == 0xFF && (b[11] == 0xE0 || b[11] == 0xD0)) return true;
                }
#endif
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                continue;
            }
        }
        return false;
    }

    bool AntiDebug::checkIATHooking() {
        HMODULE hMod = GetModuleHandle(nullptr);
        if (!hMod) return false;

        MODULEINFO modInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(modInfo))) return false;

        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hMod;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)dos + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        IMAGE_DATA_DIRECTORY importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress == 0) return false;

        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)((BYTE*)dos + importDir.VirtualAddress);

        for (; importDesc->Name != 0; importDesc++) {
            char* dllName = (char*)((BYTE*)dos + importDesc->Name);
            if (_stricmp(dllName, "kernel32.dll") != 0 &&
                _stricmp(dllName, "ntdll.dll") != 0 &&
                _stricmp(dllName, "user32.dll") != 0 &&
                _stricmp(dllName, "kernelbase.dll") != 0) {
                continue;
            }

            IMAGE_THUNK_DATA* iat = (IMAGE_THUNK_DATA*)((BYTE*)dos + importDesc->FirstThunk);
            for (; iat->u1.AddressOfData != 0; iat++) {
                void* func = (void*)iat->u1.Function;
                if (!func) continue;

                __try {
                    // IAT pointing back into our own image = trampoline / hook
                    if (func >= modInfo.lpBaseOfDll &&
                        func < (BYTE*)modInfo.lpBaseOfDll + modInfo.SizeOfImage) {
                        return true;
                    }
                    // Target begins with JMP = likely hooked
                    uint8_t* b = (uint8_t*)func;
                    if (b[0] == 0xE9 || b[0] == 0xEB || b[0] == 0xE8) return true;
                }
                __except (EXCEPTION_EXECUTE_HANDLER) {
                    continue;
                }
            }
        }
        return false;
    }

    bool AntiDebug::checkModuleHooking() {
        const char* criticalDlls[] = { "kernel32.dll", "ntdll.dll", "kernelbase.dll", nullptr };
        const char* criticalExports[] = {
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess", "NtSetInformationThread",
            "GetTickCount", "QueryPerformanceCounter", nullptr
        };

        for (int d = 0; criticalDlls[d]; d++) {
            HMODULE hDll = GetModuleHandleA(criticalDlls[d]);
            if (!hDll) continue;

            IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hDll;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;

            IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((BYTE*)dos + dos->e_lfanew);
            if (nt->Signature != IMAGE_NT_SIGNATURE) continue;

            IMAGE_DATA_DIRECTORY exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
            if (exportDir.VirtualAddress == 0) continue;

            IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)((BYTE*)dos + exportDir.VirtualAddress);
            DWORD* names = (DWORD*)((BYTE*)dos + exp->AddressOfNames);
            WORD* ords = (WORD*)((BYTE*)dos + exp->AddressOfNameOrdinals);
            DWORD* funcs = (DWORD*)((BYTE*)dos + exp->AddressOfFunctions);

            for (DWORD n = 0; n < exp->NumberOfNames; n++) {
                char* funcName = (char*)((BYTE*)dos + names[n]);
                for (int c = 0; criticalExports[c]; c++) {
                    if (strcmp(funcName, criticalExports[c]) == 0) {
                        void* funcAddr = (void*)((BYTE*)dos + funcs[ords[n]]);
                        __try {
                            uint8_t* b = (uint8_t*)funcAddr;
                            if (b[0] == 0xE9 || b[0] == 0xEB || b[0] == 0xE8 || b[0] == 0xCC) return true;
                        }
                        __except (EXCEPTION_EXECUTE_HANDLER) {
                            break;
                        }
                    }
                }
            }
        }
        return false;
    }

    bool AntiDebug::checkFunctionHooking() {
        return checkApiHooks() || checkInlineHooking() || checkIATHooking() || checkModuleHooking();
    }

    void AntiDebug::enableThreadHideFromDebugger() {
        auto proc = (pNtSetInformationThread)getNtSetInformationThread();
        if (!proc) return;

        // Undocumented class, treat as best effort hardening
        DWORD hide = 1;
        NTSTATUS status = proc(GetCurrentThread(), (THREADINFOCLASS)0x11, &hide, sizeof(hide));
        if (NT_SUCCESS(status)) threadHidden = true;
    }

    void AntiDebug::disableThreadHideFromDebugger() {
        auto proc = (pNtSetInformationThread)getNtSetInformationThread();
        if (!proc) return;

        DWORD hide = 0;
        NTSTATUS status = proc(GetCurrentThread(), (THREADINFOCLASS)0x11, &hide, sizeof(hide));
        if (NT_SUCCESS(status)) threadHidden = false;
    }

    bool AntiDebug::checkThreadHideFromDebugger() {
        auto proc = (pNtQueryInformationThread)getNtQueryInformationThread();
        if (!proc) return false;

        DWORD hideState = 0;
        ULONG retLen = 0;
        NTSTATUS status = proc(GetCurrentThread(), (THREADINFOCLASS)0x11, &hideState, sizeof(hideState), &retLen);
        if (!NT_SUCCESS(status)) return false;

        // If we set it but it's now cleared, someone tampered with it
        if (threadHidden && hideState == 0) return true;
        // If we didn't set it but it's set, something else is interfering
        if (!threadHidden && hideState != 0) return true;

        return false;
    }

    void AntiDebug::setupExceptionHandling() {
        AddVectoredExceptionHandler(1, VectoredExceptionHandler);
        setUnhandledExceptionFilter();
    }

    void AntiDebug::setUnhandledExceptionFilter() {
        ::SetUnhandledExceptionFilter(UnhandledExceptionHandler);
    }

    LONG WINAPI AntiDebug::VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo) {
        DWORD code = pExceptionInfo->ExceptionRecord->ExceptionCode;
        (void)code;
        return EXCEPTION_CONTINUE_SEARCH;
    }

    LONG WINAPI AntiDebug::UnhandledExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo) {
        TerminateProcess(GetCurrentProcess(), 0xDEADBEEF);
        return EXCEPTION_EXECUTE_HANDLER;
    }

    bool AntiDebug::isWindowClassPresent(const char* className) {
        return FindWindowA(className, nullptr) != nullptr;
    }

    bool AntiDebug::isDriverLoaded(const char* driverName) {
        return GetModuleHandleA(driverName) != nullptr;
    }

} // namespace AegisVM
