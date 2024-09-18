#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>

#define SNAPSHOT_X 0x420F   // PTRACE_SNAPSHOT
#define RESTORE_X  0x4210   // PTRACE_RESTORE

void tracer(pid_t tracee) {
    // 等待 tracee 停止
    waitpid(tracee, NULL, 0);

    // 执行第一次快照
    printf("Taking snapshot X (before v1)...\n");
    if (ptrace(SNAPSHOT_X, tracee, 0x0, 0x1000) == -1) {
        perror("ptrace snapshot X failed");
        exit(EXIT_FAILURE);
    }

    // 继续 tracee 以写入 v1
    ptrace(PTRACE_CONT, tracee, 0, 0);
    waitpid(tracee, NULL, 0);

    // 执行第二次快照
    printf("Taking snapshot X again (before v2)...\n");
    if (ptrace(SNAPSHOT_X, tracee, 0x0, 0x1000) == -1) {
        perror("ptrace snapshot X failed");
        exit(EXIT_FAILURE);
    }

    // 继续 tracee 以写入 bad 数据
    ptrace(PTRACE_CONT, tracee, 0, 0);
    waitpid(tracee, NULL, 0);

    // 恢复之前的快照
    printf("Restoring snapshot X...\n");
    if (ptrace(RESTORE_X, tracee, 0x0, 0) == -1) {
        perror("ptrace restore X failed");
        exit(EXIT_FAILURE);
    }

    // 继续 tracee 以读取数据
    ptrace(PTRACE_CONT, tracee, 0, 0);
    waitpid(tracee, NULL, 0);

    ptrace(PTRACE_DETACH, tracee, 0, 0);
}

void tracee() {
    char *region = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    // 停止自己，等待 tracer 操作
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        perror("ptrace traceme failed");
        exit(EXIT_FAILURE);
    }

    raise(SIGSTOP);  // 让 tracer 开始跟踪

    // 写入 v1 到内存区域
    strcpy(region, "v1");
    printf("Tracee wrote v1 to memory\n");

    // 停止自己，让 tracer 执行快照
    raise(SIGSTOP);

    // 写入 v2 到内存区域
    strcpy(region, "v2");
    printf("Tracee wrote v2 to memory\n");

    // 停止自己，让 tracer 执行快照
    raise(SIGSTOP);

    // 写入 bad 数据到内存区域
    strcpy(region, "bad data");
    printf("Tracee wrote bad data to memory\n");

    // 停止自己，让 tracer 执行恢复操作
    raise(SIGSTOP);

    // 读取内存数据，检查是否已经恢复
    printf("Tracee reads memory: %s\n", region);

    exit(EXIT_SUCCESS);
}

int main() {
    pid_t pid = fork();
    if (pid == 0) {
        tracee();
    } else {
        tracer(pid);
    }
    return 0;
}
