/*****************************************************************************
 *
 * limiter --
 *
 * A program that runs a child process, and kills it if it exceeds
 * a given memory usage or total CPU time.
 *
 * To be released under the GNU GPL v2.
 *
 * Uses Darwin's Mach APIs. Pieces of code liberally taken from htop
 * by Hisham H. Muhammad.
 * (http://htop.sourceforge.net/)
 *
 *****************************************************************************/

#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/task_info.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/sysctl.h>

#include "Hashtable.h"

#define kMegaByte           (1024*1024)
#define kMaxProcessMem      (100 * kMegaByte)
#define kMaxProcessSeconds  (60.0)

static Hashtable* gProcesses = (Hashtable*)NULL;
static pid_t      gPid       = -1;
static pid_t      gChildPid  = -1;
static vm_size_t  gPageSize  = 0;

static uint64_t   gMaxMemory = (1024 * 1024 * 1024);    /* in bytes, 1 GB default */
static uint64_t   gMaxCPU    = (1000000ull * 3600);     /* in microsec, 1 hour default */

static uint64_t   gMaxMemoryPerChild = (1024 * 1024 * 1024); /* in bytes, 1 GB default */
static uint64_t   gMaxCPUPerChild    = (1000000ull * 3600);  /* in microsec, 1 hour default */

static uint64_t   gInterval  = 100000;                  /* in microsec, 100 ms default  */
static int        gVerbose   = 0;

typedef struct ProcessInfo {
    pid_t       pid;
    pid_t       parent_pid;
    uint64_t    cpu_time;
    uint64_t    resident_memory;
} ProcessInfo;



void die(char *const msg)
{
    fprintf(stderr, "abort: %s\n", msg);
    if (gChildPid > 0) {
        kill(gChildPid, SIGTERM);
        kill(gChildPid, SIGKILL);
        wait(NULL);
    }
    exit(-1);
}


void start_child(int argc, char** argv)
{
    char**  nargv = (char**)NULL;
    int     res   = -1;
    int     k     = 0;
    
    setuid(getuid()); /* switch back to the correct UID */
    
    nargv = calloc(argc+1, sizeof(char*));
    memcpy(nargv, argv, argc * sizeof(char*));
    nargv[argc] = NULL;

    if (gVerbose>=1) {
        fprintf(stderr, "Child starting. Command line: ");
        for (k = 0; k<argc; ++k) {
            fprintf(stderr, " %s", argv[k]);
        }
        fprintf(stderr, "\n");
    }
    
    res = execvp(argv[0], nargv);
    perror("child could not be started");
    return;
}


void add_time_value(uint64_t* time, time_value_t tv)
{
    *time += (uint64_t)tv.seconds * (uint64_t)1000000 + (uint64_t)tv.microseconds;
}


/* update info in the local process table for <pid> */
void update_process_info(ProcessInfo* pinfo)
{
    kern_return_t           res          = KERN_SUCCESS;
    task_t                  task         = (task_t)-1;
    mach_msg_type_number_t  t_info_count = 0;
    struct task_basic_info          t_info;
    struct task_thread_times_info   t_time_info;

    res = task_for_pid(mach_task_self(), pinfo->pid, &task);
    if (res != KERN_SUCCESS) {
        if (gVerbose>=2) {
            fprintf(stderr, "warning: task_for_pid() failed for pid %d\n", pinfo->pid);
        }
        memset(pinfo, 0x00, sizeof(ProcessInfo));
        return;
    }
    pinfo->cpu_time = 0;

    t_info_count = TASK_BASIC_INFO_COUNT;
    res = task_info(task, TASK_BASIC_INFO, (task_info_t)&t_info, &t_info_count);
    if (res != KERN_SUCCESS) {
        if (gVerbose>=2) {
            fprintf(stderr, "warning: task_info(BASIC) failed for pid %d\n", pinfo->pid);
        }
        memset(pinfo, 0x00, sizeof(ProcessInfo));
        return;
        fprintf(stderr, "warning: task_info (basic) failed for pid %d\n", pinfo->pid);
    }

    pinfo->resident_memory = t_info.resident_size * gPageSize / 1024;
    add_time_value(&pinfo->cpu_time, t_info.user_time);
    add_time_value(&pinfo->cpu_time, t_info.system_time);
    
    t_info_count = TASK_THREAD_TIMES_INFO_COUNT;
    res = task_info(task, TASK_THREAD_TIMES_INFO, (task_info_t)&t_time_info, &t_info_count);
    if (res != KERN_SUCCESS) {
        if (gVerbose>=2) {
            fprintf(stderr, "warning: task_info(THREAD_TIMES) failed for pid %d\n", pinfo->pid);
        }
        memset(pinfo, 0x00, sizeof(ProcessInfo));
        return;
    }
    
    add_time_value(&pinfo->cpu_time, t_time_info.user_time);
    add_time_value(&pinfo->cpu_time, t_time_info.system_time);
    
    return;
}


void update_process_table()
{
    int                 res      = -1;
    struct kinfo_proc*  kprocbuf = NULL;
    size_t              bufSize  = 0;
    int                 mib[4]   = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
    int                 task_count = -1;
    ProcessInfo*        pinfo    = NULL;
    pid_t               pid      = -1;

    res = sysctl(mib, 4, NULL, &bufSize, NULL, 0);
    if (res < 0) die("failed to call sysctl");

    kprocbuf = (struct kinfo_proc*) malloc(bufSize);
    if (kprocbuf == NULL) die("memory allocation failure");

    res = sysctl(mib, 4, kprocbuf, &bufSize, NULL, 0);
    if (res < 0) die("failed to list processes");
    
    /* walk the full task table */
    task_count = bufSize / sizeof( struct kinfo_proc );
    for (int k=0; k<task_count; ++k) {
        pid = kprocbuf[k].kp_proc.p_pid;

        /* find or create pid info in global table */
        pinfo = (ProcessInfo*) Hashtable_get(gProcesses, pid);
    
        if (pinfo == NULL) {
            pinfo = (ProcessInfo*) malloc(sizeof(ProcessInfo));
            Hashtable_put(gProcesses, pid, pinfo);
        }
        pinfo->pid = pid;
        pinfo->parent_pid = kprocbuf[k].kp_eproc.e_ppid;
        
        update_process_info(pinfo);
    }
    
    free(kprocbuf);
    return;
}


/* return true if <child> is one of my descendants */
int is_descendant(pid_t child)
{
    ProcessInfo*    pinfo   = NULL;
    
    pinfo = (ProcessInfo*) Hashtable_get(gProcesses, child);
    if (pinfo == NULL) die("is_descendant: no such process");

    /* walk up the process tree */
    while(true) {
        if (pinfo->pid == gPid) return 1;
        if (pinfo->pid == 1)    return 0; /* init is probably not my descendant */
        if (pinfo->pid == 0)    return 0; /* root reached */
        
        assert(pinfo->pid != pinfo->parent_pid);
        pinfo = (ProcessInfo*) Hashtable_get(gProcesses, pinfo->parent_pid);
        if (pinfo == NULL) die("internal error: process table corrupt");
    }
    die("internal error in is_descendant");
    return 0;
}


/* kill a single child, by sending it SIGTERM then SIGKILL */
void kill_child(int pid, void* value, void* data)
{
    pid_t res = -1;
    int status = -1;

    /* don't kill other processes ! */
    if (!is_descendant(pid)) return;
    
    res = waitpid(pid, &status, WNOHANG);
    if (res < 0) return;
    
    if(gVerbose>=1) fprintf(stderr, "Sending TERM to %d...\n", pid);
    kill(pid, SIGTERM);
    usleep(10000);
    res = waitpid(pid, &status, WNOHANG);
    if (res == pid) {
        fprintf(stderr, "Process %d terminated.\n", pid);
        return;
    }
    
    if(gVerbose>=1) fprintf(stderr, "Sending KILL to %d...\n", pid);
    kill(pid, SIGKILL);
    usleep(10000);
    res = waitpid(pid, &status, 0);
    if (res == pid) {
        fprintf(stderr, "Process %d killed.\n", pid);
    } else {
        if(gVerbose>=1) fprintf(stderr, "Failed to kill process %d.\n", pid);
    }
    return;
}


/* callback for check_children() */
/* accumulates usage data in <data> and prints some process info. */
void check_child(int pid, void* value, void* data)
{
    ProcessInfo* accum =   (ProcessInfo*) data;
    ProcessInfo* pinfo =   (ProcessInfo*) value;
    bool         seppuku = false;
    
    if (!is_descendant(pid)) return;
    
    if (gVerbose>=2) {
        fprintf(stderr, "child: pid %-6d  ppid %-6d  mem %-10llu  time %-10llu\n", 
                pinfo->pid, pinfo->parent_pid, pinfo->resident_memory,
                pinfo->cpu_time / 1000);
    }

    /* check per-child limits */
    if (pinfo->cpu_time > gMaxCPUPerChild) {
        fprintf(stderr, "Per-child CPU time limit exceeded.\n");
        seppuku = true;
    }
    if (pinfo->resident_memory > gMaxMemoryPerChild) {
        fprintf(stderr, "Per-child Resident memory limit exceeded.\n");
        seppuku = true;
    }
    if (seppuku) kill_child(pid, NULL, NULL);
    
    /* accumulate child info */
    accum->cpu_time += pinfo->cpu_time;
    accum->resident_memory += pinfo->resident_memory;
    
    return;
}


/* callback for clear_process_table() */
void clear_process(int key, void* value, void* data)
{
    ProcessInfo* pinfo = (ProcessInfo*)value;
    memset(pinfo, 0x00, sizeof(ProcessInfo));
    return;
}


/* clear data (but not entries) in the process table */
void clear_process_table()
{
    Hashtable_foreach(gProcesses, clear_process, NULL);
    return;
}


/* accumulate data about my children */
void check_children()
{
    ProcessInfo accum;
    bool seppuku = false;
    
    clear_process(-1, &accum, NULL);
    Hashtable_foreach(gProcesses, check_child, (void*)&accum);
    
    /* check if we're still within bounds */
    if (accum.cpu_time > gMaxCPU) {
        fprintf(stderr, "Global CPU time limit exceeded.\n");
        seppuku = true;
    }
    if (accum.resident_memory > gMaxMemory) {
        fprintf(stderr, "Global Resident memory limit exceeded.\n");
        seppuku = true;
    }
    
    if (!seppuku) return;
    
    fprintf(stderr, "Killing all children.\n");
    Hashtable_foreach(gProcesses, kill_child, NULL);
    return;
}


/* main routine for the supervisor: monitor resource usage for the given <child> */
void monitor(pid_t child)
{
    int             status   = -1;
    pid_t           pid      = -1;
    
    if (gVerbose>=1) fprintf(stderr, "Monitor starting; child has PID %d\n", child);

    /* setup globals */
    gProcesses = Hashtable_new(255,true);
    gPid = getpid();
    gChildPid = child;
    host_page_size(mach_host_self(), &gPageSize);

    /* main loop */
    while(true) {
        usleep(gInterval);
        
        clear_process_table();
        update_process_table();
        check_children();

        pid = waitpid(gChildPid, &status, WNOHANG);
        if (pid != 0) break;
    }

    /* examine child termination */
    if (WIFEXITED(status)) {
        fprintf(stderr, "Child exited normally with status %d\n", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        fprintf(stderr, "Child was killed with signal %d\n", WTERMSIG(status));
    } else {
        fprintf(stderr, "Child exited abnormally.\n");
    }
    return;
}


void usage()
{
    printf("\nlimiter [options] program [args]\n\n"
        "    Run <program> and regularly check that it doesn't exceed\n"
        "    given CPU time and resident set size limits (taking all its\n"
        "    offspring into account)\n"
        "    Options:\n"
        "      -m <megabytes>     limit per-offspring memory usage (default 1GB)\n"
        "      -t <milliseconds>  limit per-offspring cpu time (default 1 hour)\n"
        "      -M <megabytes>     limit global memory usage (default 1GB)\n"
        "      -T <milliseconds>  limit global cpu time (default 1 hour)\n"
        "      -i <interval>      sampling interval (default 100ms)\n"
        );
}


int main(int argc, char** argv)
{
    pid_t   pid = -1;
    char    opt;

    /* parse command-line options */
    while ((opt = getopt(argc, argv, "i:m:t:v")) != -1) {
        switch (opt) {
            case 'i': {
                gInterval = atoi(optarg) * 1000;
                if (gInterval == 0) die("bad sampling interval specified");
                break;
            }
            case 'm': {
                gMaxMemoryPerChild = (uint64_t) atoi(optarg) * 1024 * 1024;
                if (gMaxMemoryPerChild == 0) die("bad max memory specified");
                break;
            }
            case 'M': {
                gMaxMemory = (uint64_t) atoi(optarg) * 1024 * 1024;
                if (gMaxMemory == 0) die("bad max memory specified");
                break;
            }
            case 't': {
                gMaxCPUPerChild = (uint64_t) atoi(optarg) * 1000;
                if (gMaxCPUPerChild == 0) die("bad max cpu time specified");
                break;
            }
            case 'T': {
                gMaxCPU = (uint64_t) atoi(optarg) * 1000;
                if (gMaxCPU == 0) die("bad max cpu time specified");
                break;
            }
            case 'v': {
                ++gVerbose;
                break;
            }
            case '?': {
                die("unknown option or missing argument.");
            }
            default: {
                usage();
                exit(1);
            }
        }
    }
    argc -= optind;
    argv += optind;
    
    if(argc<=0) {
        usage();
        exit(0);
    }
    
    /* show limits */
    if (gVerbose>=1) {
        fprintf(stderr, "Current limits : %llu MB memory, %llu CPU ms.\n", gMaxMemory/(1024*1024), gMaxCPU/1000);
    }

    /* fork child and monitor */
    pid = fork();
    if (pid == 0) {
        start_child(argc, argv);
    } else {
        monitor(pid);
    }
    return 1;
}
