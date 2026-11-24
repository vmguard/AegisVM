import random
import sys

LOGICAL_OPCODES = [
    "RVM_NOP",
    "RVM_MOV_RR",
    "RVM_MOV_RI",
    "RVM_MOV_RM",
    "RVM_MOV_MR",
    "RVM_MOV_RF",
    "RVM_MOV_FR",
    "RVM_PUSH",
    "RVM_POP",
    "RVM_ADD",
    "RVM_SUB",
    "RVM_MUL",
    "RVM_DIV",
    "RVM_MOD",
    "RVM_AND",
    "RVM_OR",
    "RVM_XOR",
    "RVM_SHL",
    "RVM_SHR",
    "RVM_SAR",
    "RVM_ROL",
    "RVM_ROR",
    "RVM_NEG",
    "RVM_NOT",
    "RVM_INC",
    "RVM_DEC",
    "RVM_CMP",
    "RVM_TEST",
    "RVM_JMP",
    "RVM_JZ",
    "RVM_JNZ",
    "RVM_JB",
    "RVM_JNB",
    "RVM_JA",
    "RVM_JNA",
    "RVM_JL",
    "RVM_JGE",
    "RVM_JG",
    "RVM_JLE",
    "RVM_CALL",
    "RVM_RET",
    "RVM_HALT",
    "RVM_LEA",
    "RVM_TRAP",
    "RVM_NATIVE_CALL",
    "RVM_MOVSXD",
    "RVM_CWDE",
    "RVM_CQO",
    "RVM_ADD_MR",
    "RVM_SUB_MR",
    "RVM_AND_MR",
    "RVM_OR_MR",
    "RVM_XOR_MR",
    "RVM_INC_MR",
    "RVM_DEC_MR",
    "RVM_CMP_MR",
    "RVM_TEST_MR",
    "RVM_ESCAPE",
    "RVM_AES_GCM_DECRYPT",
    "RVM_HMAC_SHA256",
    "RVM_CHECK",
]

def main():
    n = len(LOGICAL_OPCODES)
    if n > 256:
        print("Too many opcodes", file=sys.stderr)
        sys.exit(1)
    
    rng = random.SystemRandom()
    seed = rng.randint(0, 0xFFFFFFFF)
    phys = list(range(256))
    rng.shuffle(phys)

    output_path = sys.argv[1] if len(sys.argv) > 1 else "rvm_opcodes_gen.inc"

    out = []
    out.append(f"// build seed: {seed}")
    out.append("#pragma once")
    out.append("#include <cstdint>")
    out.append("")
    out.append("namespace rvm {")

    # Physical value macros
    for name, p in zip(LOGICAL_OPCODES, phys[:n]):
        out.append(f"#define RVM_PHY_{name[len('RVM_'):]} 0x{p:02X}")
    out.append("")

    # Logical to physical table
    out.append("inline constexpr uint8_t rvm_logical_to_physical[] = {")
    out.append("    " + ", ".join(f"0x{p:02X}" for p in phys[:n]))
    out.append("};")
    out.append("")

    # Physical to logical decode table
    inv = [0xFF] * 256
    for logical, physical in enumerate(phys[:n]):
        inv[physical] = logical
    out.append("inline constexpr uint8_t rvm_physical_to_logical[256] = {")
    for i in range(0, 256, 16):
        vals = ", ".join(f"0x{inv[j]:02X}" for j in range(i, min(i + 16, 256)))
        out.append(f"    {vals},")
    out.append("};")
    out.append("")
    out.append("}")
    out.append("")

    content = "\n".join(out) + "\n"
    with open(output_path, "w") as f:
        f.write(content)

if __name__ == "__main__":
    main()
