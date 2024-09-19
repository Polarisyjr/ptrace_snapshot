#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>

#define SNAPSHOT_X 0x420f   // PTRACE_SNAPSHOT
#define GETSNAPSHOT 0x4211  // PTRACE_GETSNAPSHOT

void compare_snapshots(char *snapshot1, char *snapshot2, size_t size) {
    printf("Comparing snapshots...\n");
    for (size_t i = 0; i < size; i++) {
        if (snapshot1[i] != snapshot2[i]) {
            printf("Difference at byte %zu: snapshot1 = %c, snapshot2 = %c\n", i, snapshot1[i], snapshot2[i]);
            return;
        }
    }
    printf("Same!\n");
}

void tracer(pid_t tracee, char *region, size_t size) {
    char snapshot1[size];
    char snapshot2[size];

    waitpid(tracee, NULL, 0);

    printf("Taking snapshot X (after v1)...\n");
    if (ptrace(SNAPSHOT_X, tracee, region, size) == -1) {
        perror("ptrace snapshot X failed");
        exit(EXIT_FAILURE);
    }

    printf("Getting snapshot X (after v1)...\n");
    if (ptrace(GETSNAPSHOT, tracee, region, snapshot1) == -1) {
        perror("ptrace get snapshot X failed");
        exit(EXIT_FAILURE);
    }

    ptrace(PTRACE_CONT, tracee, 0, 0);
    waitpid(tracee, NULL, 0);

    printf("Taking snapshot X again (after v2)...\n");
    if (ptrace(SNAPSHOT_X, tracee, region, size) == -1) {
        perror("ptrace snapshot X failed");
        exit(EXIT_FAILURE);
    }

    printf("Getting snapshot X again (after v2)...\n");
    if (ptrace(GETSNAPSHOT, tracee, region, snapshot2) == -1) {
        perror("ptrace get snapshot X failed");
        exit(EXIT_FAILURE);
    }

    compare_snapshots(snapshot1, snapshot2, size);

    ptrace(PTRACE_CONT, tracee, 0, 0);
    waitpid(tracee, NULL, 0);

    ptrace(PTRACE_DETACH, tracee, 0, 0);
}

void tracee(char *region) {
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        perror("ptrace traceme failed");
        exit(EXIT_FAILURE);
    }

    strcpy(region, "v1");
    printf("Tracee wrote v1 to memory: %s\n", region);

    raise(SIGSTOP);

    strcpy(region, "v2");
    printf("Tracee wrote v2 to memory: %s\n", region);

    raise(SIGSTOP);

    exit(EXIT_SUCCESS);
}

int main() {
    size_t size = 0x100;
    char *region = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    pid_t pid = fork();
    if (pid == 0) {
        tracee(region);
    } else {
        sleep(1);  
        tracer(pid, region, size);
    }

    return 0;
}
