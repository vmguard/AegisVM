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
#include <cstring>

namespace AegisVM {

enum : uint8_t {
    RVM_F_IMM64   = 0x01,   // imm64 present (imm32 | ((uint64_t)imm32_hi << 32))
    RVM_F_IMM32   = 0x02,   // 32-bit immediate present (in imm32 field)
    RVM_F_REL32   = 0x04,   // imm32 is a signed relative branch offset
    RVM_F_SIZE8   = 0x00,   // 64-bit operation (default)
    RVM_F_SIZE4   = 0x08,   // 32-bit operation
    RVM_F_SIZE2   = 0x10,   // 16-bit operation
    RVM_F_SIZE1   = 0x18,   // 8-bit operation
    RVM_F_SIZEMSK = 0x18,
};

enum RvmOpcode : uint8_t {
    RVM_NOP    = 0x00,

    RVM_MOV_RR = 0x01,   // vreg[dst] = vreg[src]
    RVM_MOV_RI = 0x02,   // vreg[dst] = imm (32 or 64 bit, per flags)
    RVM_MOV_RM = 0x03,   // vreg[dst] = mem[vreg[src] + imm32]
    RVM_MOV_MR = 0x04,   // mem[vreg[dst] + imm32] = vreg[src]
    RVM_MOV_RF = 0x05,   // vreg[dst] = vflags
    RVM_MOV_FR = 0x06,   // vflags = vreg[src]

    RVM_PUSH   = 0x10,
    RVM_POP    = 0x11,

    RVM_ADD    = 0x20,
    RVM_SUB    = 0x21,
    RVM_MUL    = 0x22,
    RVM_DIV    = 0x23,
    RVM_MOD    = 0x24,
    RVM_AND    = 0x25,
    RVM_OR     = 0x26,
    RVM_XOR    = 0x27,
    RVM_SHL    = 0x28,
    RVM_SHR    = 0x29,
    RVM_SAR    = 0x2A,
    RVM_ROL    = 0x2B,
    RVM_ROR    = 0x2C,

    RVM_NEG    = 0x30,
    RVM_NOT    = 0x31,
    RVM_INC    = 0x32,
    RVM_DEC    = 0x33,

    RVM_CMP    = 0x40,
    RVM_TEST   = 0x41,

    RVM_JMP    = 0x50,   // unconditional (imm32 = rel offset from NEXT insn)
    RVM_JZ     = 0x51,   // jump if ZF=1
    RVM_JNZ    = 0x52,   // jump if ZF=0
    RVM_JB     = 0x53,   // jump if CF=1 (below)
    RVM_JNB    = 0x54,   // jump if CF=0 (not below)
    RVM_JA     = 0x55,   // jump if CF=0 && ZF=0 (above)
    RVM_JNA    = 0x56,   // jump if CF=1 || ZF=1 (not above)
    RVM_JL     = 0x57,   // jump if SF!=OF (less, signed)
    RVM_JGE    = 0x58,   // jump if SF==OF (greater or equal, signed)
    RVM_JG     = 0x59,   // jump if ZF=0 && SF==OF (greater, signed)
    RVM_JLE    = 0x5A,   // jump if ZF=1 || SF!=OF (less or equal, signed)
    RVM_CALL   = 0x5B,   // push VIP+16; VIP += rel32
    RVM_RET    = 0x5C,   // VIP = pop()
    RVM_HALT   = 0x5D,   // stop execution; return vreg[0]

    RVM_LEA    = 0x60,   // vreg[dst] = vreg[src] + imm32
    RVM_TRAP   = 0xFE,   // intentional trap (debugging)
    RVM_MAX    = 0xFF,
};


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
    insn.opcode = op;
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
    uint32_t version;        // 1
    uint32_t num_insns;      // number of RvmInstruction entries
    uint32_t data_size;      // size of trailing data segment 
};
static constexpr uint32_t RVM_BC_MAGIC   = 0x004D5652u; // "RVM\0"
static constexpr uint32_t RVM_BC_VERSION = 1;

struct RvmContext {
    uint64_t vreg[16];        // general purpose regs
    uint64_t vflags;          // virt flags
    uint64_t vsp;             // virt stack pointer 
    uint64_t vstack[256];     // virt call stack
    const uint8_t* bytecode;  // pointer to bytecode array
    size_t    bc_size;        // total bytecode size
    size_t    vip;            // virt instruction pointer (byte offset)
    uint64_t  result;         // return value 
};

} 
