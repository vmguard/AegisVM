#pragma once

#include <cstdint>
#include <windows.h>

namespace AegisVM {

class AntiDebug {
public:
    AntiDebug() = default;

    bool initialize();
    void shutdown();

    bool isDebuggerPresent();
    bool debuggerDetected() const;

    void takeAction();
    void removeDebugger();

private:
    void* getNtQueryInformationProcess();
    void* getNtQuerySystemInformation();
    void* getNtQueryObject();
    void* getNtSetInformationThread();
    void* getNtQueryInformationThread();
    void* getNtSetDebugFilterState();
    void* getNtYieldExecution();
    void crashProcess();
    void exitProcess();
    bool checkIsDebuggerPresent();
    bool checkRemoteDebuggerPresent();
    bool checkDebugPort();
    bool checkDebugObjectHandle();
    bool checkProcessDebugFlags();
    bool checkNtGlobalFlag();
    bool checkHeapFlags();
    bool checkTimingAttacks();
    bool checkSleepTiming();
    bool checkRdtscCpuid();
    bool checkDrivers();
    bool checkApiHooks();
    bool checkInlineHooking();
    bool checkIATHooking();
    bool checkModuleHooking();
    bool checkFunctionHooking();
    bool checkSoftwareBreakpoints();
    bool checkHardwareBreakpoints();
    bool checkMemoryBreakpoints();
    bool checkMemoryProtection();
    bool checkSystemKernelDebugger();
    bool checkBreakOnTermination();
    bool checkNtSetDebugFilterState();
    void enableThreadHideFromDebugger();
    void disableThreadHideFromDebugger();
    bool checkThreadHideFromDebugger();
    void setupExceptionHandling();
    void setUnhandledExceptionFilter();
    static LONG WINAPI VectoredExceptionHandler(PEXCEPTION_POINTERS pExceptionInfo);
    static LONG WINAPI UnhandledExceptionHandler(EXCEPTION_POINTERS* pExceptionInfo);
    bool isWindowClassPresent(const char* className);
    bool isDriverLoaded(const char* driverName);
    std::uint64_t getRdtsc();
    std::uint64_t measureTime();
    bool performTimingCheck();
private:
    bool initialized = false;
    bool threadHidden = false;
    volatile LONG debuggerDetectedFlag = 0;
};

} // namespace AegisVM
