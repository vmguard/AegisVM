#pragma once

#include "rvm_isa.hpp"
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>

namespace rvm {

inline constexpr uint64_t RVM_BAD_BYTECODE_RESULT = 0xDEAD00FFDEAD00FFULL;
inline constexpr uint64_t RVM_LIFECYCLE_FAILURE_RESULT = 0xDEAD00F0DEAD00F0ULL;
inline constexpr uint64_t RVM_ENVIRONMENT_DENIED_RESULT = 0xDEAD00E0DEAD00E0ULL;
inline constexpr std::size_t RVM_MAX_VALID_INSTRUCTIONS = 1u << 20;
inline constexpr uint64_t RVM_MIN_EXECUTION_STEPS = 65536;
inline constexpr uint64_t RVM_MAX_EXECUTION_STEPS = 16000000;

struct RvmValidationState {
    std::size_t code_start = 0;
    std::size_t code_end = 0;       
    std::size_t bytecode_size = 0;  
    std::size_t instruction_count = 0;
    uint32_t opcode_seed = 0;
    uint64_t steps_remaining = 0;
};

inline void rvm_set_fault(RvmContext* ctx, RvmFaultCode fault) noexcept {
    if (ctx && ctx->fault_code == RvmFaultCode::None)
        ctx->fault_code = fault;
}

inline uint64_t rvm_validation_fail(
    RvmContext* ctx,
    RvmFaultCode fault = RvmFaultCode::InvalidBytecode) noexcept {
    rvm_set_fault(ctx, fault);
    if (ctx) ctx->result = RVM_BAD_BYTECODE_RESULT;
    return RVM_BAD_BYTECODE_RESULT;
}

inline uint64_t rvm_step_limit_fail(RvmContext* ctx) noexcept {
    return rvm_validation_fail(ctx, RvmFaultCode::StepLimit);
}

inline uint64_t rvm_environment_fail(RvmContext* ctx) noexcept {
    rvm_set_fault(ctx, RvmFaultCode::EnvironmentDenied);
    if (ctx) ctx->result = RVM_ENVIRONMENT_DENIED_RESULT;
    return RVM_ENVIRONMENT_DENIED_RESULT;
}

inline bool rvm_poll_environment(RvmContext* ctx) noexcept {
    if (!ctx || !ctx->environment_check ||
        ctx->environment_check_interval == 0)
        return true;
    const std::size_t instruction_index =
        ctx->vip >= sizeof(RvmBytecodeHeader)
            ? (ctx->vip - sizeof(RvmBytecodeHeader)) / sizeof(RvmInstruction)
            : ctx->vip / sizeof(RvmInstruction);
    if ((instruction_index % ctx->environment_check_interval) != 0)
        return true;
    return !ctx->environment_check();
}

inline bool rvm_has_instruction(std::size_t vip, std::size_t code_end) noexcept {
    return vip <= code_end && code_end - vip >= sizeof(RvmInstruction);
}

inline bool rvm_validate_target(std::size_t current,
                                int32_t relative,
                                std::size_t code_start,
                                std::size_t code_end,
                                std::size_t& target) noexcept {
    constexpr std::size_t kInsn = sizeof(RvmInstruction);
    if (code_start > code_end ||
        code_end - code_start < kInsn ||
        current < code_start || current > code_end - kInsn)
        return false;

    std::size_t candidate = 0;
    if (relative >= 0) {
        const std::size_t forward = static_cast<std::size_t>(relative);
        if (forward > code_end - current)
            return false;
        candidate = current + forward;
    } else {
        const std::size_t backward = static_cast<std::size_t>(
            -(static_cast<std::int64_t>(relative)));
        if (backward > current - code_start)
            return false;
        candidate = current - backward;
    }

    if (candidate < code_start || candidate > code_end - kInsn)
        return false;
    if (((candidate - code_start) % kInsn) != 0)
        return false;

    target = candidate;
    return true;
}

inline bool rvm_set_branch_target(RvmContext* ctx, int32_t relative,
                                  std::size_t code_start,
                                  std::size_t code_end) noexcept {
    if (!ctx) return false;
    std::size_t target = 0;
    if (!rvm_validate_target(ctx->vip, relative, code_start, code_end, target))
        return false;
    ctx->vip = target;
    return true;
}

inline bool rvm_validate_absolute_target(std::size_t absolute,
                                          std::size_t code_start,
                                          std::size_t code_end) noexcept {
    constexpr std::size_t kInsn = sizeof(RvmInstruction);
    if (code_start > code_end || code_end - code_start < kInsn ||
        absolute < code_start || absolute > code_end - kInsn)
        return false;
    return ((absolute - code_start) % kInsn) == 0;
}

inline bool rvm_validation_consume_step(RvmValidationState& state) noexcept {
    if (state.steps_remaining == 0) return false;
    --state.steps_remaining;
    return true;
}

inline uint64_t rvm_validation_step_budget(std::size_t instruction_count) noexcept {
    uint64_t budget = RVM_MIN_EXECUTION_STEPS;
    if (instruction_count > 0 &&
        instruction_count <= (RVM_MAX_EXECUTION_STEPS / 4096u)) {
        const uint64_t scaled = static_cast<uint64_t>(instruction_count) * 4096u;
        if (scaled > budget) budget = scaled;
    }
    return budget > RVM_MAX_EXECUTION_STEPS ? RVM_MAX_EXECUTION_STEPS : budget;
}

inline bool rvm_valid_size_flags(uint8_t flags) noexcept {
    const uint8_t size = static_cast<uint8_t>(flags & RVM_F_SIZEMSK);
    return size == RVM_F_SIZE8 || size == RVM_F_SIZE4 ||
           size == RVM_F_SIZE2 || size == RVM_F_SIZE1;
}

inline bool rvm_valid_registers(const RvmInstruction& insn) noexcept {
    return insn.dst < RVM_REG_COUNT && insn.src < RVM_REG_COUNT;
}

inline bool rvm_valid_instruction(const RvmInstruction& insn,
                                  uint8_t logical_opcode) noexcept {
    if (logical_opcode == 0xFF || logical_opcode >= RVM_MAX ||
        !rvm_valid_size_flags(insn.flags))
        return false;

    const bool address_opcode =
        logical_opcode == RVM_MOV_RM || logical_opcode == RVM_MOV_MR ||
        logical_opcode == RVM_LEA ||
        logical_opcode == RVM_ADD || logical_opcode == RVM_SUB ||
        logical_opcode == RVM_MUL || logical_opcode == RVM_AND ||
        logical_opcode == RVM_OR || logical_opcode == RVM_XOR ||
        logical_opcode == RVM_CMP || logical_opcode == RVM_TEST;
    const bool rip_src = insn.src == RVM_REG_NONE;
    const bool rip_dst = insn.dst == RVM_REG_NONE;
    const bool dst_is_address_base = logical_opcode == RVM_MOV_MR;
    if ((!rip_src && insn.src >= RVM_REG_COUNT) ||
        (!rip_dst && insn.dst >= RVM_REG_COUNT) ||
        (rip_src && !address_opcode) ||
        (rip_dst && !dst_is_address_base))
        return false;

    const uint8_t scale = static_cast<uint8_t>(
        (insn.flags & RVM_F_SCALE_MASK) >> RVM_F_SCALE_SHIFT);
    const bool has_index = (insn.flags & RVM_F_HAS_INDEX) != 0;
    if (!has_index && scale != 0)
        return false;
    if (has_index && (insn.imm32_hi < 0 || insn.imm32_hi >= RVM_REG_COUNT))
        return false;

    const uint8_t size_bits = RVM_F_SIZEMSK;
    const uint8_t address_bits = static_cast<uint8_t>(
        RVM_F_HAS_INDEX | RVM_F_SCALE_MASK);
    const bool is_branch = logical_opcode >= RVM_JMP && logical_opcode <= RVM_CALL;
    const bool is_memory_source =
        logical_opcode == RVM_ADD || logical_opcode == RVM_SUB ||
        logical_opcode == RVM_MUL || logical_opcode == RVM_AND ||
        logical_opcode == RVM_OR || logical_opcode == RVM_XOR ||
        logical_opcode == RVM_CMP || logical_opcode == RVM_TEST;

    if (is_branch)
        return insn.flags == RVM_F_REL32;

    if (logical_opcode == RVM_RET || logical_opcode == RVM_PUSH ||
        logical_opcode == RVM_POP || logical_opcode == RVM_MOV_RF ||
        logical_opcode == RVM_MOV_FR || logical_opcode == RVM_NOP ||
        logical_opcode == RVM_HALT || logical_opcode == RVM_TRAP)
        return insn.flags == 0;

    if (logical_opcode == RVM_MOV_RR || logical_opcode == RVM_NEG ||
        logical_opcode == RVM_NOT || logical_opcode == RVM_INC ||
        logical_opcode == RVM_DEC) {
        // These forms only carry an operand size selector. in particular
        // index/scale and contextual immediate bits are not meaningful here.
        return (insn.flags & static_cast<uint8_t>(~size_bits)) == 0;
    }

    if (logical_opcode == RVM_NATIVE_CALL) {
        return insn.dst == 0 && insn.src == 0 && insn.flags == RVM_F_IMM32;
    }

    if (logical_opcode == RVM_MOV_RI) {
        const uint8_t imm_mode = static_cast<uint8_t>(
            insn.flags & (RVM_F_IMM32 | RVM_F_IMM64));
        const uint8_t allowed = static_cast<uint8_t>(size_bits |
            RVM_F_IMM32 | RVM_F_IMM64);
        return (imm_mode == RVM_F_IMM32 || imm_mode == RVM_F_IMM64) &&
               (insn.flags & static_cast<uint8_t>(~allowed)) == 0;
    }

    if (logical_opcode == RVM_MOV_RM) {
        const uint8_t allowed = static_cast<uint8_t>(size_bits |
            RVM_F_IMM32 | RVM_F_ZERO_EXT | address_bits);
        return (insn.flags & static_cast<uint8_t>(~allowed)) == 0;
    }
    if (logical_opcode == RVM_MOV_MR) {
        const uint8_t allowed = static_cast<uint8_t>(size_bits |
            RVM_F_IMM32 | address_bits);
        return (insn.flags & static_cast<uint8_t>(~allowed)) == 0;
    }
    if (logical_opcode == RVM_LEA) {
        const uint8_t allowed = static_cast<uint8_t>(size_bits |
            RVM_F_IMM32 | address_bits);
        return (insn.flags & static_cast<uint8_t>(~allowed)) == 0;
    }

    if (is_memory_source && (insn.flags & RVM_F_MEM_SRC)) {
        const uint8_t allowed = static_cast<uint8_t>(size_bits |
            RVM_F_MEM_SRC | address_bits |
            (logical_opcode == RVM_MUL ? RVM_F_SIGNED : 0));
        return (insn.flags & static_cast<uint8_t>(~allowed)) == 0;
    }

    if (is_memory_source) {
       
        const uint8_t allowed = static_cast<uint8_t>(size_bits |
            RVM_F_IMM32 | RVM_F_IMM64 |
            (logical_opcode == RVM_MUL ? RVM_F_SIGNED : 0));
        const uint8_t imm_modes = static_cast<uint8_t>(
            insn.flags & (RVM_F_IMM32 | RVM_F_IMM64));
        return (insn.flags & static_cast<uint8_t>(~allowed)) == 0 &&
               (imm_modes == 0 || imm_modes == RVM_F_IMM32 ||
                imm_modes == RVM_F_IMM64 ||
                (logical_opcode == RVM_MUL &&
                 (insn.flags & RVM_F_SIGNED) != 0 &&
                 imm_modes == (RVM_F_IMM32 | RVM_F_IMM64)));
    }

    const uint8_t allowed = static_cast<uint8_t>(size_bits |
        RVM_F_IMM32 | RVM_F_IMM64);
    return (insn.flags & static_cast<uint8_t>(~allowed)) == 0;
}

inline bool rvm_validate_paged_context(RvmContext* ctx,
                                        RvmValidationState& state) noexcept {
    RvmBytecodeHeader header{};
    if (!ctx || !ctx->paged_header_reader ||
        !ctx->paged_header_reader(ctx, header) ||
        header.magic != RVM_BC_MAGIC ||
        header.version != RVM_BC_VERSION ||
        header.num_insns == 0 ||
        header.num_insns > RVM_MAX_VALID_INSTRUCTIONS ||
        rvm_header_opcode_seed(header) == 0)
        return false;

    const std::size_t instruction_count = header.num_insns;
    const std::size_t code_start = sizeof(RvmBytecodeHeader);
    const std::size_t code_end = code_start +
        instruction_count * sizeof(RvmInstruction);
    const std::size_t record_count = instruction_count + 1;
    if (ctx->paged_record_size != 44u ||
        ctx->paged_record_count != record_count ||
        ctx->bc_size != 4u + record_count * 44u)
        return false;

    RvmValidationState scan{};
    scan.code_start = code_start;
    scan.code_end = code_end;
    scan.bytecode_size = ctx->bc_size;
    scan.instruction_count = instruction_count;
    scan.opcode_seed = rvm_header_opcode_seed(header);

    for (std::size_t i = 0; i < instruction_count; ++i) {
        RvmInstruction instruction{};
        if (!ctx->paged_instruction_reader ||
            !ctx->paged_instruction_reader(ctx, i, instruction)) return false;
        const uint8_t logical = rvm_decode_opcode_seed(
            instruction.opcode, scan.opcode_seed);
        if (!rvm_valid_instruction(instruction, logical)) return false;
        const std::size_t offset = code_start + i * sizeof(RvmInstruction);
        if (logical >= RVM_JMP && logical <= RVM_CALL) {
            std::size_t target = 0;
            if (!rvm_validate_target(offset, instruction.imm32,
                                     code_start, code_end, target))
                return false;
            if (logical == RVM_CALL &&
                !rvm_validate_absolute_target(offset + sizeof(RvmInstruction),
                                              code_start, code_end))
                return false;
        }
    }

    if (ctx->vip == 0) ctx->vip = code_start;
    if (!rvm_validate_absolute_target(ctx->vip, code_start, code_end))
        return false;
    state = scan;
    state.steps_remaining = rvm_validation_step_budget(instruction_count);
    return true;
}

inline bool rvm_read_instruction(const RvmValidationState& state,
                                 const uint8_t* bytecode,
                                 std::size_t vip,
                                 const RvmInstruction*& insn,
                                 uint8_t& logical_opcode) noexcept {
    if (!bytecode || !rvm_has_instruction(vip, state.code_end)) return false;
    insn = reinterpret_cast<const RvmInstruction*>(bytecode + vip);
    logical_opcode = rvm_decode_opcode_seed(insn->opcode, state.opcode_seed);
    return rvm_valid_instruction(*insn, logical_opcode);
}

inline bool rvm_validate_context(RvmContext* ctx,
                                 RvmValidationState& state) noexcept {
    state = {};
    if (!ctx || !ctx->bytecode || ctx->bc_size == 0 || ctx->vsp > 256)
        return false;
    if ((ctx->native_call_allowlist == nullptr) !=
        (ctx->native_call_allowlist_count == 0))
        return false;
    if (ctx->image_size != 0 &&
        ctx->image_base > std::numeric_limits<uint64_t>::max() - ctx->image_size)
        return false;
    if (ctx->memory_size != 0 &&
        ctx->memory_base > std::numeric_limits<uint64_t>::max() - ctx->memory_size)
        return false;
    if (ctx->context_size != 0 &&
        (ctx->context_size < sizeof(RvmContext) ||
         static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ctx)) >
             std::numeric_limits<uint64_t>::max() - ctx->context_size))
        return false;
    if (ctx->paged_bytecode)
        return rvm_validate_paged_context(ctx, state);

    const uint8_t* bytecode = ctx->bytecode;
    const std::size_t bytecode_size = ctx->bc_size;
    constexpr std::size_t kHeader = sizeof(RvmBytecodeHeader);
    constexpr std::size_t kInsn = sizeof(RvmInstruction);
    std::size_t code_start = 0;
    std::size_t code_end = 0;
    std::size_t instruction_count = 0;
    bool has_header = false;

    if (bytecode_size >= sizeof(uint32_t)) {
        uint32_t magic = 0;
        std::memcpy(&magic, bytecode, sizeof(magic));
        has_header = magic == RVM_BC_MAGIC;
    }


    // This catches wrong magic and truncated header mutations 
    if (!has_header && bytecode_size >= kHeader) {
        uint32_t words[4] = {};
        std::memcpy(words, bytecode, sizeof(words));
        if (words[1] == RVM_BC_VERSION && words[2] != 0 &&
            words[2] <= RVM_MAX_VALID_INSTRUCTIONS)
            return false;
    }

    if (has_header) {
        if (bytecode_size < kHeader) return false;
        RvmBytecodeHeader header{};
        std::memcpy(&header, bytecode, sizeof(header));
        if (header.version != RVM_BC_VERSION || header.num_insns == 0 ||
            header.num_insns > RVM_MAX_VALID_INSTRUCTIONS)
            return false;
        if (static_cast<std::size_t>(header.num_insns) >
            (std::numeric_limits<std::size_t>::max() - kHeader) / kInsn)
            return false;
        const std::size_t instruction_bytes =
            static_cast<std::size_t>(header.num_insns) * kInsn;
        const std::size_t expected_without_data = kHeader + instruction_bytes;
        if (expected_without_data > bytecode_size) return false;
        const std::size_t available_data = bytecode_size - expected_without_data;
        const uint32_t opcode_seed = rvm_header_opcode_seed(header);
        if (opcode_seed != 0) {
            if (available_data != 0 || opcode_seed == 0) return false;
        } else if (static_cast<std::size_t>(header.data_size) != available_data) {
            return false;
        }
        code_start = kHeader;
        code_end = expected_without_data;
        instruction_count = header.num_insns;
        state.opcode_seed = opcode_seed;
    } else {
        if (bytecode_size % kInsn != 0) return false;
        instruction_count = bytecode_size / kInsn;
        if (instruction_count == 0 || instruction_count > RVM_MAX_VALID_INSTRUCTIONS)
            return false;
        code_start = 0;
        code_end = bytecode_size;
    }

    if (code_end < code_start || code_end - code_start < kInsn ||
        instruction_count > (code_end - code_start) / kInsn)
        return false;

    RvmValidationState scan{};
    scan.code_start = code_start;
    scan.code_end = code_end;
    scan.bytecode_size = bytecode_size;
    scan.instruction_count = instruction_count;
    scan.opcode_seed = state.opcode_seed;

    for (std::size_t i = 0; i < instruction_count; ++i) {
        const std::size_t offset = code_start + i * kInsn;
        const RvmInstruction* insn = nullptr;
        uint8_t logical = 0xFF;
        if (!rvm_read_instruction(scan, bytecode, offset, insn, logical))
            return false;
        if (logical >= RVM_JMP && logical <= RVM_CALL) {
            std::size_t target = 0;
            if (!rvm_validate_target(offset, insn->imm32,
                                     code_start, code_end, target))
                return false;
            if (logical == RVM_CALL) {
                // CALL must be able to return to the complete instruction
                const std::size_t return_address = offset + kInsn;
                if (!rvm_validate_absolute_target(return_address,
                                                  code_start, code_end))
                    return false;
            }
        }
    }

    if (ctx->vip == 0) ctx->vip = code_start;
    if (!rvm_validate_absolute_target(ctx->vip, code_start, code_end))
        return false;

    state = scan;
    state.steps_remaining = rvm_validation_step_budget(instruction_count);
    return true;
}

} 
