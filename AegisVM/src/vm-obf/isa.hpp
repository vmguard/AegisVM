/*
    0: uint8_t  opcode
    1: uint8_t  dst (destination register, 0-15)
    2: uint8_t  src (source register, 0-15)
    3: uint8_t  flags (encoding flags)
    4-7: int32_t  imm32 (32bit immediate or branch offset)
    8-11: int32_t  _pad (reserved)
    12-15: int32_t  imm32_hi (upper 32 bits for imm64)
*/

#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>

// uh I have an pseduorandom opcode generator, will upload later
#include "rvm_opcodes_gen2.inc"

//chances are I will never support x86, I dont enjoy writing it, and do not want to rewrite half the codebase.
#if !defined(_WIN64) && !defined(_M_X64)
#error "RealVM requires a Win64/x64 toolchain"
#endif
static_assert(sizeof(void*) == 8 && sizeof(std::size_t) == 8,
              "RealVM requires 64-bit pointers and size_t");

namespace rvm {
enum : uint8_t {
    RVM_F_IMM64   = 0x01,   // imm64 present (imm32 | ((uint64_t)imm32_hi << 32))
    // Contextual bit for RVM_MUL: use signed IMUL overflow semantics.
    // RVM_MUL immediate forms use IMM32 together with this bit.
    RVM_F_SIGNED  = 0x01,
    RVM_F_IMM32   = 0x02,   // 32-bit immediate present (in imm32 field)
    RVM_F_REL32   = 0x04,   // imm32 is a signed relative branch offset
    // Contextual bit for non branch binary ops: source is memory addressed by
    // src + imm32 + optional index*scale. Branches never inspect this bit.
    RVM_F_MEM_SRC = 0x04,
    // For RVM_MOV_RM only: zero-extend the loaded source width instead of
    // preserving the destination register's upper bits.
    RVM_F_ZERO_EXT = 0x04,
    RVM_F_SIZE8   = 0x00,   // 64-bit operation
    RVM_F_SIZE4   = 0x08,   // 32-bit operation
    RVM_F_SIZE2   = 0x10,   // 16-bit operation
    RVM_F_SIZE1   = 0x18,   // 8-bit operation
    RVM_F_SIZEMSK = 0x18,
    RVM_F_HAS_INDEX = 0x80, // memory op has an index register in imm32_hi
    RVM_F_SCALE_SHIFT = 5,
    RVM_F_SCALE_MASK  = 0x60, // bits 5-6 encode scale: 0=1, 1=2, 2=4, 3=8
};

//  The physical bytes placed in bytecode are determined at build time by rvm_opcodes_gen.inc, once again, will upload latar.  
enum RvmOpcode : uint8_t {
    RVM_NOP    = 0,

    // Data movement
    RVM_MOV_RR = 1,   // vreg[dst] = vreg[src]
    RVM_MOV_RI = 2,   // vreg[dst] = imm (32 or 64 bit, per flags)
    RVM_MOV_RM = 3,   // vreg[dst] = mem[vreg[src] + imm32]
    RVM_MOV_MR = 4,   // mem[vreg[dst] + imm32] = vreg[src]
    RVM_MOV_RF = 5,   // vreg[dst] = vflags
    RVM_MOV_FR = 6,   // vflags = vreg[src]

    // Stack
    RVM_PUSH   = 7,
    RVM_POP    = 8,

    // Arithmetic
    RVM_ADD    = 9,
    RVM_SUB    = 10,
    RVM_MUL    = 11,
    RVM_DIV    = 12,
    RVM_MOD    = 13,
    RVM_AND    = 14,
    RVM_OR     = 15,
    RVM_XOR    = 16,
    RVM_SHL    = 17,
    RVM_SHR    = 18,
    RVM_SAR    = 19,
    RVM_ROL    = 20,
    RVM_ROR    = 21,

    // Unary
    RVM_NEG    = 22,
    RVM_NOT    = 23,
    RVM_INC    = 24,
    RVM_DEC    = 25,

    // Compare / test
    RVM_CMP    = 26,
    RVM_TEST   = 27,

    // Control flow
    RVM_JMP    = 28,   // unconditional (imm32 = rel offset from NEXT insn)
    RVM_JZ     = 29,   // jump if ZF=1
    RVM_JNZ    = 30,   // jump if ZF=0
    RVM_JB     = 31,   // jump if CF=1 (below)
    RVM_JNB    = 32,   // jump if CF=0 (not below)
    RVM_JA     = 33,   // jump if CF=0 && ZF=0 (above)
    RVM_JNA    = 34,   // jump if CF=1 || ZF=1 (not above)
    RVM_JL     = 35,   // jump if SF!=OF (less, signed)
    RVM_JGE    = 36,   // jump if SF==OF (greater or equal, signed)
    RVM_JG     = 37,   // jump if ZF=0 && SF==OF (greater, signed)
    RVM_JLE    = 38,   // jump if ZF=1 || SF!=OF (less or equal, signed)
    RVM_CALL   = 39,   // push VIP+16; VIP += rel32
    RVM_RET    = 40,   // VIP = pop()
    RVM_HALT   = 41,   // stop execution; return vreg[0]

    // Special
    RVM_LEA    = 42,   // vreg[dst] = vreg[src] + imm32
    RVM_TRAP   = 43,   // intentional trap (debugging)
    RVM_MAX    = 44,
};

// These are intentionally not enum values so the generated mapping can be changed without recompiling the rest of the code.
inline uint8_t rvm_encode_opcode(uint8_t logical) noexcept {
    return rvm_logical_to_physical[logical];
}
inline uint8_t rvm_decode_opcode(uint8_t physical) noexcept {
    return rvm_physical_to_logical[physical];
}

enum RvmRegister : uint8_t {
    RVM_R0 = 0,  RVM_R1,  RVM_R2,  RVM_R3,
    RVM_R4,  RVM_R5,  RVM_R6,  RVM_R7,
    RVM_R8,  RVM_R9,  RVM_R10, RVM_R11,
    RVM_R12, RVM_R13, RVM_R14, RVM_R15,
    RVM_REG_COUNT = 16,
    RVM_REG_NONE  = 0xFF,
};

enum : uint64_t {
    RVM_VF_ZF = 1ULL << 0,   // zero
    RVM_VF_SF = 1ULL << 1,   // sign
    RVM_VF_CF = 1ULL << 7,   // carry
    RVM_VF_OF = 1ULL << 11,  // overflow
};

#pragma pack(push, 1)
struct RvmInstruction {
    uint8_t  opcode;
    uint8_t  dst;
    uint8_t  src;
    uint8_t  flags;
    int32_t  imm32;
    int32_t  _pad;
    int32_t  imm32_hi;
};
#pragma pack(pop)

static_assert(sizeof(RvmInstruction) == 16, "RvmInstruction must be 16 bytes");

inline RvmInstruction make_insn(uint8_t op, uint8_t d = 0, uint8_t s = 0,
                                 uint8_t fl = 0, int32_t i32 = 0,
                                 int32_t i32h = 0) noexcept {
    RvmInstruction insn{};
    insn.opcode = rvm_encode_opcode(op);
    insn.dst    = d;
    insn.src    = s;
    insn.flags  = fl;
    insn.imm32  = i32;
    insn.imm32_hi = i32h;
    return insn;
}

inline RvmInstruction make_mov_ri(uint8_t d, uint64_t v) noexcept {
    RvmInstruction insn = make_insn(RVM_MOV_RI, d);
    if (v <= 0xFFFFFFFFULL && (int64_t)v == (int32_t)v) {
        insn.flags = RVM_F_IMM32;
        insn.imm32 = (int32_t)v;
    } else {
        insn.flags = RVM_F_IMM64;
        insn.imm32 = (int32_t)(v & 0xFFFFFFFFULL);
        insn.imm32_hi = (int32_t)(v >> 32);
    }
    return insn;
}

inline RvmInstruction make_branch(uint8_t op, int32_t rel) noexcept {
    RvmInstruction insn = make_insn(op);
    insn.flags = RVM_F_REL32;
    insn.imm32 = rel;
    return insn;
}

inline RvmInstruction make_call(int32_t rel) noexcept {
    return make_branch(RVM_CALL, rel);
}

inline int32_t insn_size(const RvmInstruction&) noexcept { return 16; }

inline uint64_t insn_imm64(const RvmInstruction& insn) noexcept {
    return (uint64_t)(uint32_t)insn.imm32 |
           ((uint64_t)(uint32_t)insn.imm32_hi << 32);
}

inline int32_t insn_rel32(const RvmInstruction& insn) noexcept {
    return insn.imm32;
}


struct RvmBytecodeHeader {
    uint32_t magic;          // RVM 0x004D5652
    uint32_t version;        // 2 for the authenticated container
    uint32_t num_insns;      // number of RvmInstruction entries
    uint32_t data_size;      // size of trailing data segment (if any)
};
static constexpr uint32_t RVM_BC_MAGIC   = 0x004D5652u; // "RVM\0"
static constexpr uint32_t RVM_BC_VERSION = 2;

struct RvmContext {
    uint64_t vreg[16];        // general-purpose registers
    uint64_t vflags;          // virtual flags

    // Hardening fields (defeat symbolic execution / taint tracking) 
    uint64_t side_channel;    // deterministic accumulator; every handler XORs
                               // its result here, making all handlers impure
    uint64_t scratch[16];     // decoy memory — handlers write garbage here to
                               // introduce fake data dependencies for taint tracking
    uint64_t entropy_seed;    // PRNG state for per-handler jitter

    uint64_t vsp;             // virtual stack pointer 
    uint64_t vstack[256];     // virtual call stack
    const uint8_t* bytecode;  // pointer to bytecode array
    size_t    bc_size;        // total bytecode size
    size_t    vip;            // virtual instruction pointer (byte offset)
    uint64_t  result;         // return value, set by HALT

    // Protected entry metadata. These fields are zero for ordinary rvm_run() calls.
    uint64_t  bytecode_key;
    uint64_t  bytecode_checksum;
};

// The rewriter emits a native VM-enter stub which lays out this structure directly on the stack.
// Keep these offsets in one authoritative place so the interpreter and generated machine code wot drift apart.
inline constexpr std::size_t RVM_CTX_VREG_OFFSET    = offsetof(RvmContext, vreg);
inline constexpr std::size_t RVM_CTX_VFLAGS_OFFSET  = offsetof(RvmContext, vflags);
inline constexpr std::size_t RVM_CTX_VSP_OFFSET     = offsetof(RvmContext, vsp);
inline constexpr std::size_t RVM_CTX_BYTECODE_OFFSET = offsetof(RvmContext, bytecode);
inline constexpr std::size_t RVM_CTX_BCSIZE_OFFSET  = offsetof(RvmContext, bc_size);
inline constexpr std::size_t RVM_CTX_VIP_OFFSET     = offsetof(RvmContext, vip);
inline constexpr std::size_t RVM_CTX_RESULT_OFFSET  = offsetof(RvmContext, result);
inline constexpr std::size_t RVM_CTX_KEY_OFFSET     = offsetof(RvmContext, bytecode_key);
inline constexpr std::size_t RVM_CTX_CSUM_OFFSET    = offsetof(RvmContext, bytecode_checksum);
inline constexpr std::size_t RVM_CTX_SIZE           = sizeof(RvmContext);

// Structural assertions only, the compilers offsetof/sizeof values are the ABI authority consumed by the generated VM-enter stub. 
static_assert(RVM_CTX_VREG_OFFSET == offsetof(RvmContext, vreg));
static_assert(RVM_CTX_VFLAGS_OFFSET == RVM_CTX_VREG_OFFSET + sizeof(RvmContext::vreg));
static_assert(offsetof(RvmContext, side_channel) == RVM_CTX_VFLAGS_OFFSET + sizeof(RvmContext::vflags));
static_assert(RVM_CTX_VSP_OFFSET == offsetof(RvmContext, entropy_seed) + sizeof(RvmContext::entropy_seed));
static_assert(RVM_CTX_BYTECODE_OFFSET == RVM_CTX_VSP_OFFSET + sizeof(RvmContext::vsp) + sizeof(RvmContext::vstack));
static_assert(RVM_CTX_BCSIZE_OFFSET == RVM_CTX_BYTECODE_OFFSET + sizeof(RvmContext::bytecode));
static_assert(RVM_CTX_VIP_OFFSET == RVM_CTX_BCSIZE_OFFSET + sizeof(RvmContext::bc_size));
static_assert(RVM_CTX_RESULT_OFFSET == RVM_CTX_VIP_OFFSET + sizeof(RvmContext::vip));
static_assert(RVM_CTX_KEY_OFFSET == RVM_CTX_RESULT_OFFSET + sizeof(RvmContext::result));
static_assert(RVM_CTX_CSUM_OFFSET == RVM_CTX_KEY_OFFSET + sizeof(RvmContext::bytecode_key));
static_assert(RVM_CTX_SIZE == RVM_CTX_CSUM_OFFSET + sizeof(RvmContext::bytecode_checksum));

} // namespace rvm

