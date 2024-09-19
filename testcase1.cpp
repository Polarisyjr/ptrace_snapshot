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
#define RESTORE_X  0x4210   // PTRACE_RESTORE

void tracer(pid_t tracee, char *region) {
    // wait for tracee
    waitpid(tracee, NULL, 0);

    // let tracee continue to write "v1"
    ptrace(PTRACE_CONT, tracee, 0, 0);
    waitpid(tracee, NULL, 0);

    // take the first snapshot
    printf("Taking snapshot X (after v1)...\n");
    if (ptrace(SNAPSHOT_X, tracee, region, 0x100) == -1) {
        perror("ptrace snapshot X failed");
        exit(EXIT_FAILURE);
    }

    // let the tracee continue writing "v2"
    ptrace(PTRACE_CONT, tracee, 0, 0);
    waitpid(tracee, NULL, 0);

    // take the second snapshot, and the snapshot should now be overwritten with "v2"
    printf("Taking snapshot X again (after v2)...\n");
    if (ptrace(SNAPSHOT_X, tracee, region, 0x100) == -1) {
        perror("ptrace snapshot X failed");
        exit(EXIT_FAILURE);
    }

    // let tracee continue to write "bad data"
    ptrace(PTRACE_CONT, tracee, 0, 0);
    waitpid(tracee, NULL, 0);

    // restore the snapshot
    printf("Restoring snapshot X (restoring v2)...\n");
    if (ptrace(RESTORE_X, tracee, region, 0x100) == -1) {
        perror("ptrace restore X failed");
        exit(EXIT_FAILURE);
    }

    // let tracee read the data from snapshot
    ptrace(PTRACE_CONT, tracee, 0, 0);
    waitpid(tracee, NULL, 0);

    ptrace(PTRACE_DETACH, tracee, 0, 0);
}

void tracee(char *region) {
    // stop itself，wait for tracer
    if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
        perror("ptrace traceme failed");
        exit(EXIT_FAILURE);
    }

    raise(SIGSTOP);  // tracer start to trace

    // write v1 into region mem
    strcpy(region, "v1");
    printf("Tracee wrote v1 to memory: %s\n", region);

    // stop itself，let tracer execute the first snapshot
    raise(SIGSTOP);

    // write v2 into region mem
    strcpy(region, "v2");
    printf("Tracee wrote v2 to memory: %s\n", region);

    // stop itself，let tracer execute the second snapshot
    raise(SIGSTOP);

    // write baddata into region mem
    strcpy(region, "bad data");
    printf("Tracee wrote bad data to memory: %s\n", region);

    // stop itself，let tracer execute the store operation
    raise(SIGSTOP);

    // read the memory data and check if it has been restored
    printf("Tracee reads memory: %s\n", region);

    exit(EXIT_SUCCESS);
}

int main() {
    // shared memory
    char *region = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (region == MAP_FAILED) {
        perror("mmap failed");
        exit(EXIT_FAILURE);
    }

    pid_t pid = fork();
    if (pid == 0) {
        tracee(region);
    } else {
        sleep(1);  // Ensure the tracee runs first
        tracer(pid, region);
    }

    return 0;
}
