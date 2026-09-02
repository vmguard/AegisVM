// function locates VirtualProtect through the loaders module lists so the packed image does not need a new import table dependency.
#include <stdint.h>
#include <stddef.h>

#if defined(_MSC_VER) || defined(__clang__)
#include <intrin.h>
#endif

typedef int (*virtual_protect_fn)(void*, size_t, uint32_t, uint32_t*);

static uint64_t read_peb(void) {
#if defined(_MSC_VER) || defined(__clang__)
    return __readgsqword(0x60);
#else
    return 0;
#endif
}

static int is_virtual_protect(const unsigned char* p) {
    static const unsigned char name[] = {
        'V','i','r','t','u','a','l','P','r','o','t','e','c','t',0
    };
    for (unsigned i = 0; i < sizeof(name); ++i)
        if (p[i] != name[i]) return 0;
    return 1;
}

void erase_pe_headers_runtime(void) {
    unsigned char* peb = (unsigned char*)(uintptr_t)read_peb();
    if (!peb) return;
    unsigned char* image = *(unsigned char**)(peb + 0x10);
    unsigned char* ldr = *(unsigned char**)(peb + 0x18);
    if (!image || !ldr) return;

    unsigned char* image_nt = image + *(int32_t*)(image + 0x3C);
    uint32_t header_size = *(uint32_t*)(image_nt + 0x54);
    unsigned char* list = ldr + 0x10;
    unsigned char* entry = *(unsigned char**)list;
    virtual_protect_fn protect = (virtual_protect_fn)0;

    for (unsigned guard = 0; entry && entry != list && guard < 64; ++guard) {
        unsigned char* module = *(unsigned char**)(entry + 0x30);
        if (module) {
            unsigned char* nt = module + *(int32_t*)(module + 0x3C);
            uint32_t export_rva = *(uint32_t*)(nt + 0x88);
            uint32_t export_size = *(uint32_t*)(nt + 0x8C);
            if (export_rva && export_size) {
                unsigned char* exp = module + export_rva;
                uint32_t names = *(uint32_t*)(exp + 0x18);
                uint32_t name_rva = *(uint32_t*)(exp + 0x20);
                uint32_t ordinal_rva = *(uint32_t*)(exp + 0x24);
                uint32_t function_rva = *(uint32_t*)(exp + 0x1C);
                uint32_t* name_table = (uint32_t*)(module + name_rva);
                uint16_t* ordinal_table = (uint16_t*)(module + ordinal_rva);
                uint32_t* function_table = (uint32_t*)(module + function_rva);
                for (uint32_t i = 0; i < names; ++i) {
                    if (!is_virtual_protect(module + name_table[i])) continue;
                    const uint32_t function_rva = function_table[ordinal_table[i]];
                    /*
                    * Lot of the time Kernel32  exports this as a forwarder string.
                    * Ignore rvas inside the export directory and continue to
                    * kernelbase whose export is a real callable address
                    */
                    if (function_rva >= export_rva &&
                        function_rva < export_rva + export_size)
                        continue;
                    protect = (virtual_protect_fn)(module + function_rva);
                    break;
                }
            }
        }
        if (protect) break;
        entry = *(unsigned char**)entry;
    }

    if (!protect || header_size == 0) return;
    uint32_t old_protect = 0;
    if (!protect(image, header_size, 0x04u, &old_protect)) return;
    /*
    * 
    * Preserve NT/section metadata and e_lfanew needed by CRT and exception
    * handling, but destroy the DOS MZ signature used by dump tooling.
    * I kind of like the comments like having an extra star thing at the top and bottom for spacing
    * anyway it it 2am writing this and hope this works
    * 
    */


    *(uint32_t*)(image + 0x00) = 0;
}
