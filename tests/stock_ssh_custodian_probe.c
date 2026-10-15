/* Explicit adversarial process-boundary test fixture, NOT stock OpenSSH.
 * Mounted only inside the disconnected integration-test namespace. */
#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sched.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef PROBE
#define PROBE "ordinary"
#endif
extern char **environ;

static void denied(int result) {
    if (result != -1 || (errno != EPERM && errno != EACCES)) _exit(93);
    dprintf(2, "blocked:%s\n", PROBE);
}
static void child_exit(void) {
    pid_t pid=fork();
    if (pid<0) _exit(90);
    if (!pid) _exit(0);
    if (waitpid(pid,0,0)!=pid) _exit(91);
}
static void execute(char **argv, const char *path) {
    argv[0]=(char *)path;
    execve(path,argv,environ);
    _exit(92);
}
int main(int argc,char **argv) {
    if (!strcmp(argv[0],"/tool/sshd")) {
        child_exit();
        if (!strcmp(PROBE,"extra_fork")) child_exit();
        char *next[8]={"/usr/lib/openssh/sshd-session","-i","-e","-f","/tool/data/sshd_config","-R",NULL};
        if (!strcmp(PROBE,"wrong_argv")) next[1]="-D";
        if (!strcmp(PROBE,"wrong_environment")) setenv("LD_PRELOAD","/forbidden",1);
        execute(next,next[0]);
    }
    if (!strcmp(argv[0],"/usr/lib/openssh/sshd-session")) {
        pid_t pid=fork();
        if (pid<0) _exit(90);
        if (!pid) execute(argv,"/usr/lib/openssh/sshd-auth");
        if (waitpid(pid,0,0)!=pid) _exit(91);
        return 0;
    }
    if (!strcmp(PROBE,"extra_exec")) execute(argv,argv[0]);
    if (!strcmp(PROBE,"auth_fork")) child_exit();
    if (!strcmp(PROBE,"socket")) denied(socket(AF_INET,SOCK_STREAM,0));
    if (!strcmp(PROBE,"socketpair")) { int fd[2]; denied(socketpair(AF_UNIX,SOCK_DGRAM,0,fd)); }
    if (!strcmp(PROBE,"connect")) { struct sockaddr_in address={.sin_family=AF_INET,.sin_port=htons(22),.sin_addr.s_addr=htonl(0x0a4d0063)}; denied(connect(0,(void *)&address,sizeof address)); }
    if (!strcmp(PROBE,"shared_mmap")) { void *value=mmap(0,4096,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0); denied(value==MAP_FAILED?-1:0); }
    if (!strcmp(PROBE,"sysv_shm")) denied(shmget(IPC_PRIVATE,4096,IPC_CREAT|0600));
    if (!strcmp(PROBE,"thread_clone")) denied(syscall(SYS_clone,0x01200011|CLONE_VM|CLONE_THREAD|CLONE_SIGHAND,0,0,0,0));
    if (!strcmp(PROBE,"ptrace")) denied(ptrace(PTRACE_TRACEME,0,0,0));
    if (!strcmp(PROBE,"pidfd_open")) denied(syscall(SYS_pidfd_open,1,0));
    if (!strcmp(PROBE,"pidfd_peer")) denied(syscall(SYS_pidfd_open,getppid(),0));
    /* EPERM, rather than EBADF, proves these paths stop before descriptor use. */
    if (!strcmp(PROBE,"pidfd_getfd")) denied(syscall(SYS_pidfd_getfd,-1,0,0));
    if (!strcmp(PROBE,"pidfd_send_signal")) denied(syscall(SYS_pidfd_send_signal,-1,0,NULL,0));
    if (!strcmp(PROBE,"execveat")) denied(syscall(SYS_execveat,AT_FDCWD,"/tool/sshd",argv,environ,0));
    if (!strcmp(PROBE,"host_interpreter")) denied(open("/usr/bin/python3",O_RDONLY));
    if (!strcmp(PROBE,"namespace")) denied(unshare(CLONE_NEWNET));
    return 0;
}
