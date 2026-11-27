#include "rvm_markers.hpp"

#include <cstdint>
#include <cstddef>

namespace rvm {
struct RvmContext;
}

extern "C" std::uint64_t RvmExecutePtr(rvm::RvmContext*);
extern "C" std::uint64_t RvmExecutePtrHardened(rvm::RvmContext*);
extern "C" std::uint64_t RvmRun(const std::uint8_t*, std::size_t,
                                  const std::uint64_t*, std::size_t);

// Portable noinline attribute
#if defined(_MSC_VER)
    #define RVM_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
    #define RVM_NOINLINE __attribute__((noinline))
#else
    #define RVM_NOINLINE
#endif

#pragma pack(push, 1)
struct RvmPrivateLocator {
    std::uint64_t magic;
    std::uint32_t version;
    std::uint32_t reserved;
    std::uint64_t begin;
    std::uint64_t end;
    std::uint64_t execute;
    std::uint64_t hardened;
    std::uint64_t run;
};
#pragma pack(pop)

static constexpr std::uint64_t kRvmPrivateLocatorMagic =
    0xA3E91C5D0B7A4F21ULL;
static constexpr std::uint32_t kRvmPrivateLocatorVersion = 3;

extern "C" {

void __aegis_marker_begin(void);
void __aegis_marker_end(void);

#pragma section(".rdata$rvm", read)
__declspec(allocate(".rdata$rvm"))
extern const RvmPrivateLocator g_rvm_private_locator = {
    kRvmPrivateLocatorMagic,
    kRvmPrivateLocatorVersion,
    0,
    reinterpret_cast<std::uint64_t>(&__aegis_marker_begin),
    reinterpret_cast<std::uint64_t>(&__aegis_marker_end),
    reinterpret_cast<std::uint64_t>(&RvmExecutePtr),
    reinterpret_cast<std::uint64_t>(&RvmExecutePtrHardened),
    reinterpret_cast<std::uint64_t>(&RvmRun),
};

RVM_NOINLINE
void __aegis_marker_begin(void) {
    volatile int tag = 0xBEEF;
    volatile std::uint64_t anchor = 0xBEEF13579BDF2468ULL;
    (void)tag;
    (void)anchor;
}

RVM_NOINLINE
void __aegis_marker_end(void) {
    volatile int tag = 0xDEAD;
    volatile std::uint64_t anchor = 0xDEAD02468ACE1357ULL;
    (void)tag;
    (void)anchor;
}

}
