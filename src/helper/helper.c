#include <stdio.h>              // perror
#include <unistd.h>             // setuid, execve

int main(int argc, char **argv)
{
    char **exec = argc < 2 ? (char*[]){ "/bin/bash", NULL } : &argv[1];
#define REQUIRE(expr) do { if(expr) { perror(#expr); return -1; } } while(0)
    REQUIRE(setuid(0));
    REQUIRE(execve(*exec, exec, (char*[]){ "EUID=0", "UID=0", "LOGNAME=root", NULL }));
}
