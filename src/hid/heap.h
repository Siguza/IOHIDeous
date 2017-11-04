#ifndef HEAP_H
#define HEAP_H

#include <stddef.h>             // size_t
#include <stdint.h>             // uint32_t

#include <mach/mach.h>

#define HEAP_PAYLOAD_NUM_ARRAYS 0x100

extern uint32_t heap_payload[];
extern size_t heap_payload_len;

void heap_spray_init(size_t size);

bool heap_init(size_t memsize, size_t size);

kern_return_t heap_set(mach_port_t master, uint32_t id, void *dict, size_t len);

kern_return_t heap_spray(mach_port_t master, size_t startid, void *dict, size_t len, kern_return_t (*cb)(void*), void *arg);

#endif
