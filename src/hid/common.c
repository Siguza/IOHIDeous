#include <errno.h>              // errno
#include <fcntl.h>              // open, O_RDONLY
#include <libproc.h>            // proc_*
#include <stddef.h>             // size_t
#include <stdlib.h>             // realpath, malloc, free
#include <string.h>             // strlen, strncmp, strerror
#include <unistd.h>             // close

#include <sys/mman.h>           // mmap, munmap, MAP_FAILED
#include <sys/stat.h>           // fstat, struct stat

#include <mach/mach.h>

#include "common.h"

int map_file(filemap_t *map, const char *path)
{
    int fd = open(path, O_RDONLY);
    if(fd == -1)
    {
        ERR("Failed to open %s for reading: %s", path, strerror(errno));
        return -1;
    }
    struct stat s;
    if(fstat(fd, &s) != 0)
    {
        ERR("Failed to stat(%s): %s", path, strerror(errno));
        return -1;
    }
    size_t len = s.st_size;
    void *buf = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
    if(buf == MAP_FAILED)
    {
        ERR("Failed to map %s to memory: %s", path, strerror(errno));
        return -1;
    }
    map->fd = fd;
    map->len = len;
    map->buf = buf;
    return 0;
}

int unmap_file(filemap_t *map)
{
    if(munmap(map->buf, map->len) != 0)
    {
        ERR("munmap() failed: %s", strerror(errno));
        return -1;
    }
    if(close(map->fd) != 0)
    {
        ERR("close() failed: %s", strerror(errno));
        return -1;
    }
    map->fd = 0;
    map->len = 0;
    map->buf = NULL;
    return 0;
}

pid_t pid_for_path(const char *path)
{
    // Resolve symlinks
    char *name = realpath(path, NULL);
    if(name == NULL)
    {
        ERR("realpath failed: %s", strerror(errno));
        return -1;
    }

    size_t namelen = strlen(name);
    if(namelen > PROC_PIDPATHINFO_MAXSIZE)
    {
        ERR("pid_for_path failed: argument longer than PROC_PIDPATHINFO_MAXSIZE");
        return -1;
    }

    int numprocs;
    size_t size = 0;
    pid_t *pids = NULL;

    do
    {
        if(size != 0)
        {
            pids = malloc(size);
            if(pids == NULL)
            {
                ERR("malloc failed: %s", strerror(errno));
                return -1;
            }
        }
        numprocs = proc_listallpids(pids, size);
        if(numprocs < 0)
        {
            ERR("proc_listallpids failed: %s", strerror(errno));
            free(pids);
            return -1;
        }
        size = numprocs * sizeof(pid_t);
    } while(pids == NULL);

    pid_t pid = -1;
    for(size_t i = 0; i < numprocs; ++i)
    {
        char buf[PROC_PIDPATHINFO_MAXSIZE];
        int len = proc_pidpath(pids[i], buf, sizeof(buf));
        if(len < 0)
        {
            ERR("proc_pidpath failed: %s", strerror(errno));
            pid = -1;
            break;
        }
        if(len == namelen && strncmp(name, buf, len) == 0)
        {
            if(pid == -1)
            {
                pid = pids[i];
            }
            else // return error for more than one pid per path
            {
                ERR("pid_for_path failed: found more than one pid");
                pid = -1;
                break;
            }
        }
    }
    free(pids);

    return pid;
}

#define MAX_CHUNK_SIZE 0xfff

vm_size_t task_read(task_t task, vm_address_t addr, vm_size_t size, void *buf)
{
    kern_return_t ret;
    vm_size_t remainder = size,
              bytes_read = 0;

    for(vm_address_t end = addr + size; addr < end; remainder -= size)
    {
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
        ret = vm_read_overwrite(task, addr, size, (vm_address_t)((char*)buf + bytes_read), &size);
        if(ret != KERN_SUCCESS || size == 0)
        {
            break;
        }
        bytes_read += size;
        addr += size;
    }

    return bytes_read;
}

vm_size_t task_write(task_t task, vm_address_t addr, vm_size_t size, void *buf)
{
    kern_return_t ret;
    vm_size_t remainder = size;
    vm_size_t bytes_written = 0;

    for(vm_address_t end = addr + size; addr < end; remainder -= size)
    {
        size = remainder > MAX_CHUNK_SIZE ? MAX_CHUNK_SIZE : remainder;
        ret = vm_write(task, addr, (vm_offset_t)((char*)buf + bytes_written), size);
        if(ret != KERN_SUCCESS)
        {
            break;
        }
        bytes_written += size;
        addr += size;
    }

    return bytes_written;
}
