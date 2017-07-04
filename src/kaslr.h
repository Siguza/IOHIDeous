#ifndef KASLR_H
#define KASLR_H

#include <stdint.h>             // uint64_t

#define SLIDE_MAX   0x20000000 /* I heard the max is less, but better be a bit too generous */
#define SLIDE_STEP    0x100000

uint64_t get_kernel_slide(void *kernel);

#endif
