#ifndef OBTAIN_H
#define OBTAIN_H

#include <stdbool.h>            // bool

#include <IOKit/IOKitLib.h>     // io_*

io_connect_t steal_from_windowserver(void);

bool kill_loginwindow(void);

bool log_user_out(void);

#endif
