#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>              // printf, fprintf, stderr
#include <stdlib.h>             // pid_t

#include <mach/mach.h>
#include <mach-o/loader.h>      // mach_*

#define ERR(str, args...) do { fprintf(stderr, "[!] " str " [%s:%u]\n", ##args, __FILE__, __LINE__); } while(0)
#define LOG(str, args...) do { printf(str "\n", ##args); } while(0)

#define FOREACH_CMD(hdr, cmd) \
for(lc_t *cmd  = (lc_t *) (((hdr_t*) (hdr)) + 1), \
         *_end = (lc_t *) ((char *) cmd + ((hdr_t*) (hdr))->sizeofcmds); \
    cmd < _end; \
    cmd = (lc_t *) ((char *) cmd + cmd->cmdsize))

typedef struct mach_header_64 hdr_t;
typedef struct load_command lc_t;
typedef struct segment_command_64 seg_t;
typedef struct
{
    uint32_t nameoff;
    uint32_t flags;
    uint64_t addr;
} sym_t;

typedef struct
{
    void *buf;
    size_t len;
    int fd;
} filemap_t;

int map_file(filemap_t *map, const char *path);

int unmap_file(filemap_t *map);

pid_t pid_for_path(const char *path);

vm_size_t task_read(task_t task, vm_address_t addr, vm_size_t size, void *buf);

vm_size_t task_write(task_t task, vm_address_t addr, vm_size_t size, void *buf);

#endif
