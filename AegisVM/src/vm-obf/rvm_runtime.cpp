#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "rvm_runtime.hpp"
#include "rvm_hardened.hpp"
#include "rvm_crypto.hpp"
#include "aegisvm.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace {

#if defined(RVM_PHASE3_TEST_HOOK) || defined(RVM_PHASE4_TEST_HOOK)
using RvmCallback = std::uint64_t (*)();
#endif

#ifdef RVM_PHASE3_TEST_HOOK
thread_local RvmCallback g_phase3_nested_callback = nullptr;
thread_local unsigned g_phase3_nested_remaining = 0;
thread_local int g_phase3_throw_mode = 0;
thread_local void (*g_phase3_probe_callback)() = nullptr;
#endif

#ifdef RVM_PHASE4_TEST_HOOK
thread_local RvmCallback g_phase4_nested_callback = nullptr;
thread_local unsigned g_phase4_nested_remaining = 0;
thread_local int g_phase4_throw_mode = 0;
thread_local void (*g_phase4_probe_callback)() = nullptr;
std::atomic<unsigned long long> g_phase4_private_allocations{0};
std::atomic<unsigned long long> g_phase4_private_frees{0};
std::atomic<unsigned long long> g_phase4_active{0};
std::atomic<unsigned long long> g_phase4_max_active{0};
std::atomic<unsigned long long> g_phase4_protect_calls{0};
std::atomic<unsigned long long> g_phase4_protect_failures{0};
std::atomic<unsigned long long> g_phase4_cleanup_protect_failures{0};
std::atomic<unsigned> g_phase4_fault_mode{0};

void update_max_active(unsigned long long value) noexcept {
    unsigned long long old = g_phase4_max_active.load(std::memory_order_relaxed);
    while (old < value &&
           !g_phase4_max_active.compare_exchange_weak(
               old, value, std::memory_order_relaxed, std::memory_order_relaxed)) {
    }
}
#endif

static void secure_wipe(void* memory, std::size_t size) noexcept {
    rvm::crypto::secure_wipe(memory, size);
}

static void* alloc_private(std::size_t size) noexcept {
#ifdef RVM_PHASE4_TEST_HOOK
    if ((g_phase4_fault_mode.load(std::memory_order_relaxed) & 1u) != 0)
        return nullptr;
#endif
    return VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
}

static bool protect_private(void* memory, std::size_t size,
                            DWORD protection, bool cleanup) noexcept {
#ifndef RVM_PHASE4_TEST_HOOK
    (void)cleanup;
#endif
#ifdef RVM_PHASE4_TEST_HOOK
    g_phase4_protect_calls.fetch_add(1, std::memory_order_relaxed);
    const unsigned fault_mode = g_phase4_fault_mode.load(std::memory_order_relaxed);
    if ((fault_mode & 2u) != 0 || (cleanup && (fault_mode & 4u) != 0)) {
        g_phase4_protect_failures.fetch_add(1, std::memory_order_relaxed);
        if (cleanup)
            g_phase4_cleanup_protect_failures.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
#endif
    DWORD old_protection = 0;
    const BOOL ok = VirtualProtect(memory, size, protection, &old_protection);
    if (!ok) {
#ifdef RVM_PHASE4_TEST_HOOK
        g_phase4_protect_failures.fetch_add(1, std::memory_order_relaxed);
        if (cleanup)
            g_phase4_cleanup_protect_failures.fetch_add(1, std::memory_order_relaxed);
#endif
    }
    return ok != FALSE;
}

#ifdef RVM_PHASE4_TEST_HOOK
class ActiveExecution final {
public:
    ActiveExecution() noexcept
        : active_(g_phase4_active.fetch_add(1, std::memory_order_relaxed) + 1) {
        update_max_active(active_);
    }
    ActiveExecution(const ActiveExecution&) = delete;
    ActiveExecution& operator=(const ActiveExecution&) = delete;
    ~ActiveExecution() noexcept {
        g_phase4_active.fetch_sub(1, std::memory_order_relaxed);
    }
private:
    unsigned long long active_;
};
#endif

class PrivateBytecode final {
public:
    PrivateBytecode() = default;

    PrivateBytecode(const PrivateBytecode&) = delete;
    PrivateBytecode& operator=(const PrivateBytecode&) = delete;

    ~PrivateBytecode() noexcept { (void)release(); }

    bool acquire(const uint8_t* encrypted, std::size_t size, uint64_t key_part,
                 uint64_t checksum_part, const uint8_t* native_coverage,
                 std::size_t native_coverage_size,
                 const uint32_t* native_allowlist,
                 std::size_t native_allowlist_count) {
        if (!encrypted || size <= rvm::crypto::kProtectedOverheadBytes ||
            size > ULONG_MAX) return false;
        if ((native_coverage == nullptr) != (native_coverage_size == 0) ||
            (native_allowlist == nullptr) != (native_allowlist_count == 0) ||
            native_allowlist_count > (ULONG_MAX / sizeof(uint32_t)))
            return false;

        std::uint32_t paged_magic = 0;
        if (size >= rvm::crypto::kPagedMagicBytes)
            std::memcpy(&paged_magic, encrypted, sizeof(paged_magic));
        if (paged_magic == rvm::crypto::kPagedMagic) {
            const std::size_t payload = size - rvm::crypto::kPagedMagicBytes;
            if (payload < 2 * rvm::crypto::kPagedRecordBytes ||
                payload % rvm::crypto::kPagedRecordBytes != 0)
                return false;
            std::array<std::uint8_t, rvm::crypto::kNativeDigestBytes> digest{};
            std::array<std::uint8_t, 8> allowlist_digest{};
            if (native_coverage_size != 0 &&
                !rvm::crypto::sha256(native_coverage, native_coverage_size, digest))
                return false;
            if (native_allowlist_count != 0) {
                std::array<std::uint8_t, 32> allowlist_hash{};
                if (!rvm::crypto::sha256(
                        reinterpret_cast<const std::uint8_t*>(native_allowlist),
                        native_allowlist_count * sizeof(uint32_t), allowlist_hash))
                    return false;
                std::memcpy(allowlist_digest.data(), allowlist_hash.data(),
                            allowlist_digest.size());
                rvm::crypto::secure_wipe(allowlist_hash);
            }
            std::array<std::uint8_t, rvm::crypto::kAesKeySeedBytes> seed{};
            std::array<std::uint8_t, rvm::crypto::kAesKeyBytes> key{};
            std::memcpy(seed.data(), &key_part, sizeof(key_part));
            std::memcpy(seed.data() + sizeof(key_part), &checksum_part,
                        sizeof(checksum_part));
            if (!rvm::crypto::expand_aes256_key(seed, key)) return false;
            paged_ = true;
            paged_record_count_ = static_cast<std::uint32_t>(
                payload / rvm::crypto::kPagedRecordBytes);
            std::memcpy(paged_key_, key.data(), key.size());
            std::memcpy(paged_native_digest_, digest.data(), digest.size());
            std::memcpy(paged_allowlist_digest_, allowlist_digest.data(),
                        allowlist_digest.size());
            rvm::crypto::secure_wipe(seed);
            rvm::crypto::secure_wipe(key);
            rvm::crypto::secure_wipe(digest);
            rvm::crypto::secure_wipe(allowlist_digest);
            return true;
        }

        std::array<std::uint8_t, 8> allowlist_digest{};
        if (native_allowlist_count != 0) {
            std::array<std::uint8_t, 32> digest{};
            if (!rvm::crypto::sha256(
                    reinterpret_cast<const std::uint8_t*>(native_allowlist),
                    native_allowlist_count * sizeof(uint32_t), digest))
                return false;
            std::memcpy(allowlist_digest.data(), digest.data(),
                        allowlist_digest.size());
            rvm::crypto::secure_wipe(digest);
        }

        const std::size_t plaintext_size = size - rvm::crypto::kProtectedOverheadBytes;
        std::array<std::uint8_t, rvm::crypto::kAesKeySeedBytes> key_seed{};
        std::array<std::uint8_t, rvm::crypto::kAesKeyBytes> aes_key{};
        std::memcpy(key_seed.data(), &key_part, sizeof(key_part));
        std::memcpy(key_seed.data() + sizeof(key_part), &checksum_part,
                    sizeof(checksum_part));
        if (!rvm::crypto::expand_aes256_key(key_seed, aes_key)) {
            rvm::crypto::secure_wipe(key_seed);
            return false;
        }

        std::vector<std::uint8_t> plaintext;
        std::array<std::uint8_t, rvm::crypto::kNativeDigestBytes> native_digest{};
        std::array<std::uint8_t, rvm::crypto::kNativeAadBytes> native_aad{};
        const std::uint8_t* aad_data = nullptr;
        std::size_t aad_size = 0;
        if (native_coverage && native_coverage_size != 0) {
            if (native_coverage_size > ULONG_MAX ||
                !rvm::crypto::sha256(native_coverage, native_coverage_size,
                                     native_digest)) {
                rvm::crypto::secure_wipe(aes_key);
                rvm::crypto::secure_wipe(key_seed);
                return false;
            }
        }
        if ((native_coverage && native_coverage_size != 0) ||
            native_allowlist_count != 0) {
            native_aad = rvm::crypto::make_native_aad(
                plaintext_size, native_digest, allowlist_digest);
            aad_data = native_aad.data();
            aad_size = native_aad.size();
        } else {
            const auto legacy_aad = rvm::crypto::make_aad(plaintext_size);
            native_aad.fill(0);
            std::memcpy(native_aad.data(), legacy_aad.data(), legacy_aad.size());
            aad_data = native_aad.data();
            aad_size = legacy_aad.size();
        }
        bool decrypted = false;
        try {
            decrypted = rvm::crypto::aes_gcm_decrypt(
            encrypted + rvm::crypto::kProtectedPrefixBytes,
            plaintext_size, aes_key, encrypted,
            rvm::crypto::kProtectedPrefixBytes,
            encrypted + rvm::crypto::kProtectedPrefixBytes + plaintext_size,
            rvm::crypto::kProtectedSuffixBytes, aad_data, aad_size, plaintext);
        } catch (...) {
            rvm::crypto::secure_wipe(aes_key);
            rvm::crypto::secure_wipe(key_seed);
            return false;
        }
        if (!decrypted || plaintext.size() != plaintext_size ||
            plaintext.size() < sizeof(rvm::RvmBytecodeHeader)) {
            rvm::crypto::secure_wipe(aes_key);
            rvm::crypto::secure_wipe(key_seed);
            return false;
        }
        rvm::crypto::secure_wipe(aes_key);
        rvm::crypto::secure_wipe(key_seed);

        memory_ = static_cast<uint8_t*>(alloc_private(plaintext_size));
        if (!memory_) {
            secure_wipe(plaintext.data(), plaintext.size());
            return false;
        }
        size_ = plaintext_size;
#ifdef RVM_PHASE4_TEST_HOOK
        g_phase4_private_allocations.fetch_add(1, std::memory_order_relaxed);
#endif
        std::memcpy(memory_, plaintext.data(), plaintext_size);
        secure_wipe(plaintext.data(), plaintext.size());

        if (!protect_private(memory_, size_, PAGE_EXECUTE_READ, false)) {
            release();
            return false;
        }
        return true;
    }

    const uint8_t* data() const noexcept { return memory_; }
    std::size_t size() const noexcept { return size_; }
    bool is_paged() const noexcept { return paged_; }

    void configure_paged_context(rvm::RvmContext* ctx) const noexcept {
        if (!ctx || !paged_) return;
        ctx->paged_bytecode = true;
        ctx->paged_record_count = paged_record_count_;
        ctx->paged_record_size = rvm::crypto::kPagedRecordBytes;
        ctx->paged_header_reader = &rvm::rvm_paged_read_header;
        ctx->paged_instruction_reader = &rvm::rvm_paged_read_instruction;
        std::memcpy(ctx->paged_key, paged_key_, sizeof(paged_key_));
        std::memcpy(ctx->paged_native_digest, paged_native_digest_,
                    sizeof(paged_native_digest_));
        std::memcpy(ctx->paged_allowlist_digest, paged_allowlist_digest_,
                    sizeof(paged_allowlist_digest_));
    }

public:
    bool release_now() noexcept { return release(); }

private:
    bool release() noexcept {
        if (paged_) {
            paged_ = false;
            rvm::crypto::secure_wipe(paged_key_, sizeof(paged_key_));
            rvm::crypto::secure_wipe(paged_native_digest_, sizeof(paged_native_digest_));
            rvm::crypto::secure_wipe(paged_allowlist_digest_, sizeof(paged_allowlist_digest_));
            paged_record_count_ = 0;
            return true;
        }
        if (!memory_) return true;
        const bool wiped = protect_private(memory_, size_, PAGE_READWRITE, true);
        if (wiped)
            secure_wipe(memory_, size_);
        VirtualFree(memory_, 0, MEM_RELEASE);
#ifdef RVM_PHASE4_TEST_HOOK
        g_phase4_private_frees.fetch_add(1, std::memory_order_relaxed);
#endif
        memory_ = nullptr;
        size_ = 0;
        return wiped;
    }

    uint8_t* memory_ = nullptr;
    std::size_t size_ = 0;
    bool paged_ = false;
    std::uint32_t paged_record_count_ = 0;
    std::uint8_t paged_key_[rvm::crypto::kAesKeyBytes] = {};
    std::uint8_t paged_native_digest_[rvm::crypto::kNativeDigestBytes] = {};
    std::uint8_t paged_allowlist_digest_[8] = {};
};

} 

namespace rvm {

namespace {

bool decrypt_paged_record(RvmContext* ctx, std::size_t record_index,
                          std::uint8_t output[16]) noexcept {
    if (!ctx || !output || !ctx->paged_bytecode ||
        ctx->paged_record_size != rvm::crypto::kPagedRecordBytes ||
        record_index >= ctx->paged_record_count ||
        !ctx->bytecode || ctx->bc_size < rvm::crypto::kPagedMagicBytes)
        return false;
    if (record_index >
        (std::numeric_limits<std::size_t>::max() - rvm::crypto::kPagedMagicBytes) /
            ctx->paged_record_size)
        return false;
    const std::size_t offset = rvm::crypto::kPagedMagicBytes +
                               record_index * ctx->paged_record_size;
    if (offset > ctx->bc_size ||
        ctx->paged_record_size > ctx->bc_size - offset)
        return false;

    std::array<std::uint8_t, rvm::crypto::kAesKeyBytes> key{};
    std::array<std::uint8_t, rvm::crypto::kNativeDigestBytes> native_digest{};
    std::array<std::uint8_t, 8> allowlist_digest{};
    std::memcpy(key.data(), ctx->paged_key, key.size());
    std::memcpy(native_digest.data(), ctx->paged_native_digest,
                native_digest.size());
    std::memcpy(allowlist_digest.data(), ctx->paged_allowlist_digest,
                allowlist_digest.size());
    const auto aad = rvm::crypto::make_paged_aad(
        native_digest, allowlist_digest, record_index);
    std::vector<std::uint8_t> plaintext;
    bool ok = false;
    try {
        ok = rvm::crypto::aes_gcm_decrypt(
            ctx->bytecode + offset + rvm::crypto::kProtectedPrefixBytes,
            rvm::crypto::kPagedRecordPlainBytes, key,
            ctx->bytecode + offset, rvm::crypto::kProtectedPrefixBytes,
            ctx->bytecode + offset + rvm::crypto::kProtectedPrefixBytes +
                rvm::crypto::kPagedRecordPlainBytes,
            rvm::crypto::kProtectedSuffixBytes,
            aad.data(), aad.size(), plaintext);
    } catch (...) {
        ok = false;
    }
    if (ok && plaintext.size() == sizeof(RvmInstruction))
        std::memcpy(output, plaintext.data(), sizeof(RvmInstruction));
    if (!plaintext.empty())
        rvm::crypto::secure_wipe(plaintext.data(), plaintext.size());
    rvm::crypto::secure_wipe(key);
    rvm::crypto::secure_wipe(native_digest);
    rvm::crypto::secure_wipe(allowlist_digest);
    return ok;
}

} 

bool rvm_paged_read_header(RvmContext* ctx,
                           RvmBytecodeHeader& header) noexcept {
    if (!ctx || !ctx->paged_bytecode || !decrypt_paged_record(
            ctx, 0, reinterpret_cast<std::uint8_t*>(&header)))
        return false;
    ctx->paged_header_cache = header;
    return true;
}

bool rvm_paged_read_instruction(RvmContext* ctx,
                                std::size_t instruction_index,
                                RvmInstruction& instruction) noexcept {
    if (!ctx || ctx->paged_record_count < 2 ||
        instruction_index >= ctx->paged_record_count - 1 ||
        !decrypt_paged_record(ctx, instruction_index + 1,
                              reinterpret_cast<std::uint8_t*>(&instruction)))
        return false;
    ctx->paged_instruction_cache = instruction;
    return true;
}

RvmContext* rvm_context_alloc() noexcept {
    void* memory = alloc_private(sizeof(RvmContext));
    if (!memory) return nullptr;
    auto* context = new (memory) RvmContext{};
    context->context_size = sizeof(RvmContext);
    return context;
}

void rvm_context_free(RvmContext* ctx) noexcept {
    if (!ctx) return;
    if (protect_private(ctx, sizeof(*ctx), PAGE_READWRITE, true))
        secure_wipe(ctx, sizeof(*ctx));
    VirtualFree(ctx, 0, MEM_RELEASE);
}

bool rvm_context_protect(RvmContext* ctx, bool writable) noexcept {
    if (!ctx) return false;
    return protect_private(ctx, sizeof(*ctx),
                           writable ? PAGE_READWRITE : PAGE_READONLY, false);
}

uint64_t rvm_execute_protected(RvmContext* ctx, bool hardened) {
    if (!ctx)
        return rvm_validation_fail(nullptr, RvmFaultCode::InvalidContext);

    ctx->fault_code = RvmFaultCode::None;
    ctx->memory_fault = false;
    if (!ctx->bytecode || ctx->bc_size == 0)
        return rvm_validation_fail(ctx, RvmFaultCode::InvalidContext);
    
  // testing api
    if (AegisVM::is_untrusted_environment()) {
        ctx->fault_code = RvmFaultCode::EnvironmentDenied;
        ctx->result = RVM_ENVIRONMENT_DENIED_RESULT;
        return ctx->result;
    }

    const uint8_t* encrypted = ctx->bytecode;
    const std::size_t encrypted_size = ctx->bc_size;
    const uint64_t key = ctx->bytecode_key;
    const uint64_t checksum = ctx->bytecode_checksum;

#ifdef RVM_PHASE4_TEST_HOOK
    if (g_phase4_throw_mode == 1)
        throw std::runtime_error("Phase 4 C++ exception after protected setup");
#endif

    PrivateBytecode private_code;
    if (!private_code.acquire(encrypted, encrypted_size, key, checksum,
                              ctx->native_coverage,
                              ctx->native_coverage_size,
                              ctx->native_call_allowlist,
                              ctx->native_call_allowlist_count)) {
        ctx->fault_code = RvmFaultCode::Lifecycle;
        ctx->result = RVM_LIFECYCLE_FAILURE_RESULT;
        return ctx->result;
    }

#ifdef RVM_PHASE4_TEST_HOOK
    ActiveExecution active_execution;
    if (g_phase4_throw_mode == 2)
        RaiseException(0xE0000401u, 0, 0, nullptr);
    if (g_phase4_throw_mode == 4)
        throw std::runtime_error("Phase 4 C++ exception during private execution");
    if (g_phase4_probe_callback)
        g_phase4_probe_callback();
    if (g_phase4_nested_callback && g_phase4_nested_remaining != 0) {
        --g_phase4_nested_remaining;
        (void)g_phase4_nested_callback();
    }
    if (g_phase4_throw_mode == 3)
        *static_cast<volatile int*>(nullptr) = 0x4;
#endif

    // only context that receives the  decrypted bytecode pointer
    RvmContext* execution = rvm_context_alloc();
    if (!execution) {
        ctx->fault_code = RvmFaultCode::Lifecycle;
        ctx->result = RVM_LIFECYCLE_FAILURE_RESULT;
        return ctx->result;
    }
    *execution = *ctx;
    execution->paged_bytecode = false;
    execution->paged_record_count = 0;
    execution->paged_record_size = 0;
    execution->paged_plaintext_size = 0;
    execution->paged_header_reader = nullptr;
    execution->paged_instruction_reader = nullptr;
    execution->context_size = sizeof(RvmContext);
    execution->memory_fault = false;
    execution->fault_code = RvmFaultCode::None;
    execution->environment_check = &AegisVM::is_untrusted_environment;
    execution->environment_check_interval = 256;
    if (private_code.is_paged()) {
        execution->bytecode = encrypted;
        execution->bc_size = encrypted_size;
        private_code.configure_paged_context(execution);
    } else {
        execution->bytecode = private_code.data();
        execution->bc_size = private_code.size();
    }
    execution->bytecode_key = 0;
    execution->bytecode_checksum = 0;

    uint64_t result = RVM_LIFECYCLE_FAILURE_RESULT;
    try {
        result = hardened
            ? rvm::rvm_harden_execute(execution)
            : rvm::rvm_execute(execution);
    } catch (...) {
        rvm_context_free(execution);
        throw;
    }

    execution->side_channel = result ^ key ^ checksum ^
                              0xA3C59AC3D1E7B5F9ULL;
    *ctx = *execution;
    ctx->bytecode = encrypted;
    ctx->bc_size = encrypted_size;
    ctx->bytecode_key = key;
    ctx->bytecode_checksum = checksum;
    ctx->paged_bytecode = false;
    ctx->paged_record_count = 0;
    ctx->paged_record_size = 0;
    ctx->paged_plaintext_size = 0;
    ctx->paged_header_reader = nullptr;
    ctx->paged_instruction_reader = nullptr;
    rvm::crypto::secure_wipe(ctx->paged_key, sizeof(ctx->paged_key));
    rvm::crypto::secure_wipe(ctx->paged_native_digest, sizeof(ctx->paged_native_digest));
    rvm::crypto::secure_wipe(ctx->paged_allowlist_digest,
                             sizeof(ctx->paged_allowlist_digest));
    rvm_context_free(execution);

    // The context has been restored to the immutable source before cleanup,
    // so a cleanup failure cannot leave a dangling private bytecode pointer.
    if (!private_code.release_now()) {
        ctx->fault_code = RvmFaultCode::Lifecycle;
        ctx->result = RVM_LIFECYCLE_FAILURE_RESULT;
        return ctx->result;
    }
    return result;
}

} 

extern "C" {

#if defined(_MSC_VER)
#define RVM_NOINLINE __declspec(noinline)
#elif defined(__GNUC__) || defined(__clang__)
#define RVM_NOINLINE __attribute__((noinline))
#else
#define RVM_NOINLINE
#endif

#ifdef RVM_PHASE3_TEST_HOOK
void RvmSetPhase3NestedCallback(RvmCallback callback, unsigned remaining) {
    g_phase3_nested_callback = callback;
    g_phase3_nested_remaining = remaining;
}
void RvmSetPhase3ThrowMode(int mode) { g_phase3_throw_mode = mode; }
void RvmSetPhase3ProbeCallback(void (*callback)()) { g_phase3_probe_callback = callback; }
#endif

#ifdef RVM_PHASE4_TEST_HOOK
unsigned long long RvmGetPhase4Active() {
    return g_phase4_active.load(std::memory_order_relaxed);
}
void RvmSetPhase4NestedCallback(RvmCallback callback, unsigned remaining) {
    g_phase4_nested_callback = callback;
    g_phase4_nested_remaining = remaining;
}
void RvmSetPhase4ThrowMode(int mode) { g_phase4_throw_mode = mode; }
void RvmSetPhase4ProbeCallback(void (*callback)()) { g_phase4_probe_callback = callback; }
void RvmSetPhase4FaultMode(unsigned mode) {
    g_phase4_fault_mode.store(mode, std::memory_order_relaxed);
}
unsigned long long RvmGetPhase4PrivateAllocations() {
    return g_phase4_private_allocations.load(std::memory_order_relaxed);
}
unsigned long long RvmGetPhase4PrivateFrees() {
    return g_phase4_private_frees.load(std::memory_order_relaxed);
}
unsigned long long RvmGetPhase4MaxActive() {
    return g_phase4_max_active.load(std::memory_order_relaxed);
}
unsigned long long RvmGetPhase4ProtectFailures() {
    return g_phase4_protect_failures.load(std::memory_order_relaxed);
}
unsigned long long RvmGetPhase4CleanupProtectFailures() {
    return g_phase4_cleanup_protect_failures.load(std::memory_order_relaxed);
}
#endif

RVM_NOINLINE
uint64_t RvmExecutePtr(rvm::RvmContext* ctx) {
#ifdef RVM_PHASE3_TEST_HOOK
    if (g_phase3_nested_callback && g_phase3_nested_remaining != 0) {
        --g_phase3_nested_remaining;
        (void)g_phase3_nested_callback();
    }
    if (g_phase3_probe_callback) g_phase3_probe_callback();
    if (g_phase3_throw_mode == 1)
        throw std::runtime_error("Phase 3 C++ exception through VM-enter stub");
    if (g_phase3_throw_mode == 2)
        RaiseException(0xE0000301u, EXCEPTION_NONCONTINUABLE, 0, nullptr);
    if (g_phase3_throw_mode == 3)
        *static_cast<volatile int*>(nullptr) = 0x3;
#endif
    return rvm::rvm_execute_protected(ctx, false);
}

RVM_NOINLINE
uint64_t RvmExecutePtrHardened(rvm::RvmContext* ctx) {
    return rvm::rvm_execute_protected(ctx, true);
}

RVM_NOINLINE
uint64_t RvmRun(const uint8_t* bytecode, size_t bc_size,
                const uint64_t* args, size_t nargs) {
    return rvm::rvm_run(bytecode, bc_size, args, nargs);
}

} 
