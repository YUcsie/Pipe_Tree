#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>

#include "hw2.h"

#define ERR_EXIT(s) perror(s), exit(errno);
#define MAX_ARGC 3

#define MAX_CHILDREN 8

typedef struct
{
    pid_t pid;
    int read_fd;
    int write_fd;
    char friend_name[MAX_FRIEND_NAME_LEN];
    int friend_value;
} Child;

static char root[MAX_FRIEND_INFO_LEN] = "Not_Tako";
static char friend_info[MAX_FRIEND_INFO_LEN];
static char friend_name[MAX_FRIEND_NAME_LEN];
static int friend_value;
FILE *read_fp = NULL;

Child children[MAX_CHILDREN];
int num_children = 0;

char *inputbuf = NULL;
size_t inputbufsize = MAX_CMD_LEN;
char *input_argv[MAX_ARGC];

static inline bool is_Not_Tako()
{
    return (strcmp(friend_name, root) == 0);
}

void print_direct_meet(char *child_friend_name)
{
    fprintf(stdout, "Not_Tako has met %s by himself\n", child_friend_name);
}

void print_indirect_meet(char *parent_friend_name, char *child_friend_name)
{
    fprintf(stdout, "Not_Tako has met %s through %s\n", child_friend_name, parent_friend_name);
}

void print_fail_meet(char *parent_friend_name, char *child_friend_name)
{
    fprintf(stdout, "Not_Tako does not know %s to meet %s\n", parent_friend_name, child_friend_name);
}

void print_fail_check(char *parent_friend_name)
{
    fprintf(stdout, "Not_Tako has checked, he doesn't know %s\n", parent_friend_name);
}

void print_success_adopt(char *parent_friend_name, char *child_friend_name)
{
    fprintf(stdout, "%s has adopted %s\n", parent_friend_name, child_friend_name);
}

void print_fail_adopt(char *parent_friend_name, char *child_friend_name)
{
    fprintf(stdout, "%s is a descendant of %s\n", parent_friend_name, child_friend_name);
}

void print_compare_gtr(char *friend_name)
{
    fprintf(stdout, "Not_Tako is still friends with %s\n", friend_name);
}

void print_compare_leq(char *friend_name)
{
    fprintf(stdout, "%s is dead to Not_Tako\n", friend_name);
}

void print_final_graduate()
{
    fprintf(stdout, "Congratulations! You've finished Not_Tako's annoying tasks!\n");
}

void fully_write(int write_fd, void *write_buf, int write_len)
{
    int total_written = 0;
    while (total_written < write_len)
    {
        int bytes_written = write(write_fd, write_buf + total_written, write_len - total_written);
        if (bytes_written <= 0)
        {
            perror("write error");
            exit(EXIT_FAILURE);
        }
        total_written += bytes_written;
    }
}

int read_line(int fd, char *buf, int size)
{
    int n = 0;
    while (n < size - 1)
    {
        char c;
        int bytes = read(fd, &c, 1);
        if (bytes == 1)
        {
            buf[n++] = c;
            if (c == '\n')
            {
                break;
            }
        }
        else if (bytes == 0)
        {
            break;
        }
        else
        {
            perror("read error");
            exit(EXIT_FAILURE);
        }
    }
    buf[n] = '\0';
    return n;
}

int input(int fd)
{
    ssize_t rbytes = 0;
    if (inputbuf == NULL)
    {
        inputbuf = (char *)malloc(inputbufsize);
        if (inputbuf == NULL)
        {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
    }

    if (fd == STDIN_FILENO)
    {
        rbytes = getline(&inputbuf, &inputbufsize, stdin);
        if (rbytes < 0)
        {
            exit(0);
        }
        else if (rbytes > 1)
        {
            inputbuf[rbytes - 1] = '\0';
        }
        else
        {
            return 0;
        }
    }
    else
    {
        rbytes = read_line(fd, inputbuf, inputbufsize);
        if (rbytes <= 0)
        {
            exit(0);
        }
    }

    char *start = inputbuf;
    while (*start == ' ')
        start++;
    char *end = start + strlen(start) - 1;
    while (end > start && (*end == ' ' || *end == '\n'))
        *end-- = '\0';

    if (strlen(start) == 0)
    {
        return 0;
    }

    int argumentcount = 0;
    char *ptr = strtok(start, " ");
    while (ptr != NULL && argumentcount < MAX_ARGC)
    {
        input_argv[argumentcount++] = ptr;
        ptr = strtok(NULL, " ");
    }
    return argumentcount;
}

void write_response(const char *response)
{
    if (!is_Not_Tako())
    {
        fully_write(PARENT_WRITE_FD, (void *)response, strlen(response));
    }
}

void handle_meet(char *parent_friend_name, char *child_friend_info)
{
    if (strcmp(parent_friend_name, friend_name) == 0)
    {
        char child_friend_name[MAX_FRIEND_NAME_LEN];
        int child_friend_value;
        char name_value[MAX_FRIEND_INFO_LEN];
        strcpy(name_value, child_friend_info);
        char *underscore = strchr(name_value, '_');
        if (underscore != NULL)
        {
            *underscore = '\0';
            strncpy(child_friend_name, name_value, MAX_FRIEND_NAME_LEN);
            child_friend_value = atoi(underscore + 1);
        }
        else
        {
            write_response("Failure\n");
            return;
        }
        if (num_children >= MAX_CHILDREN)
        {
            write_response("Failure\n");
            return;
        }
        int parent_to_child[2];
        int child_to_parent[2];
        if (pipe(parent_to_child) == -1 || pipe(child_to_parent) == -1)
        {
            perror("pipe");
            write_response("Failure\n");
            return;
        }
        pid_t pid = fork();
        if (pid == -1)
        {
            perror("fork");
            write_response("Failure\n");
            return;
        }
        if (pid == 0)
        {

            close(parent_to_child[1]);
            close(child_to_parent[0]);

            if (parent_to_child[0] != PARENT_READ_FD)
            {
                if (dup2(parent_to_child[0], PARENT_READ_FD) == -1)
                {
                    perror("dup2 PARENT_READ_FD");
                    exit(EXIT_FAILURE);
                }
                close(parent_to_child[0]);
            }
            if (child_to_parent[1] != PARENT_WRITE_FD)
            {
                if (dup2(child_to_parent[1], PARENT_WRITE_FD) == -1)
                {
                    perror("dup2 PARENT_WRITE_FD");
                    exit(EXIT_FAILURE);
                }
                close(child_to_parent[1]);
            }

            int flags;

            flags = fcntl(PARENT_READ_FD, F_GETFD);
            if (flags == -1)
            {
                perror("fcntl F_GETFD PARENT_READ_FD");
            }
            else
            {
                flags &= ~FD_CLOEXEC;
                if (fcntl(PARENT_READ_FD, F_SETFD, flags) == -1)
                {
                    perror("fcntl F_SETFD PARENT_READ_FD");
                }
            }

            flags = fcntl(PARENT_WRITE_FD, F_GETFD);
            if (flags == -1)
            {
                perror("fcntl F_GETFD PARENT_WRITE_FD");
            }
            else
            {
                flags &= ~FD_CLOEXEC;
                if (fcntl(PARENT_WRITE_FD, F_SETFD, flags) == -1)
                {
                    perror("fcntl F_SETFD PARENT_WRITE_FD");
                }
            }

            execl("./friend", "./friend", child_friend_info, NULL);
            perror("execl");
            exit(EXIT_FAILURE);
        }
        else
        {

            close(parent_to_child[0]);
            close(child_to_parent[1]);
            children[num_children].pid = pid;
            children[num_children].read_fd = child_to_parent[0];
            children[num_children].write_fd = parent_to_child[1];
            strncpy(children[num_children].friend_name, child_friend_name, MAX_FRIEND_NAME_LEN);
            children[num_children].friend_value = child_friend_value;
            num_children++;
            write_response("Success\n");
            if (is_Not_Tako())
            {
                print_direct_meet(child_friend_name);
            }
            else
            {
                print_indirect_meet(friend_name, child_friend_name);
            }
            return;
        }
    }
    else
    {
        int found = 0;
        for (int i = 0; i < num_children; i++)
        {
            dprintf(children[i].write_fd, "Meet %s %s\n", parent_friend_name, child_friend_info);
            char response[16];
            int n = read_line(children[i].read_fd, response, sizeof(response));
            if (n <= 0)
            {
                continue;
            }
            if (strncmp(response, "Success", 7) == 0)
            {
                found = 1;
                break;
            }
        }
        if (found)
        {
            write_response("Success\n");
        }
        else
        {

            if (is_Not_Tako())
            {

                char child_friend_name[MAX_FRIEND_NAME_LEN];
                char name_value[MAX_FRIEND_INFO_LEN];
                strcpy(name_value, child_friend_info);
                char *underscore = strchr(name_value, '_');
                if (underscore != NULL)
                {
                    *underscore = '\0';
                    strncpy(child_friend_name, name_value, MAX_FRIEND_NAME_LEN);
                }
                else
                {
                    strncpy(child_friend_name, child_friend_info, MAX_FRIEND_NAME_LEN);
                }
                print_fail_meet(parent_friend_name, child_friend_name);
            }
            write_response("Failure\n");
        }
    }
}

void check_subtree(bool is_root)
{
    char buffer[1024];
    if (strcmp(friend_name, root) == 0)
    {
        snprintf(buffer, sizeof(buffer), "%s\n", friend_name);
    }
    else
    {
        snprintf(buffer, sizeof(buffer), "%s_%02d\n", friend_name, friend_value);
    }

    if (!is_root)
    {
        write_response(buffer);
    }
    else
    {
        printf("%s", buffer);
    }

    if (num_children > 0)
    {
        for (int i = 0; i < num_children; i++)
        {
            dprintf(children[i].write_fd, "Check_subtree\n");
        }

        int num_active_children = num_children;
        char *child_buffers[MAX_CHILDREN] = {0};
        int child_done[MAX_CHILDREN] = {0};

        while (num_active_children > 0)
        {
            int any_line = 0;

            for (int i = 0; i < num_children; i++)
            {
                if (!child_done[i] && child_buffers[i] == NULL)
                {
                    char child_buffer[1024];
                    int n = read_line(children[i].read_fd, child_buffer, sizeof(child_buffer));
                    if (n > 0)
                    {
                        if (strcmp(child_buffer, "Done\n") == 0)
                        {
                            child_done[i] = 1;
                            num_active_children--;
                        }
                        else
                        {
                            size_t len = strlen(child_buffer);
                            if (len > 0 && child_buffer[len - 1] == '\n')
                                child_buffer[len - 1] = '\0';
                            child_buffers[i] = strdup(child_buffer);
                        }
                    }
                }
            }

            buffer[0] = '\0';
            for (int i = 0; i < num_children; i++)
            {
                if (child_buffers[i] != NULL)
                {
                    if (buffer[0] == '\0')
                    {
                        snprintf(buffer, sizeof(buffer), "%s", child_buffers[i]);
                    }
                    else
                    {
                        strncat(buffer, " ", sizeof(buffer) - strlen(buffer) - 1);
                        strncat(buffer, child_buffers[i], sizeof(buffer) - strlen(buffer) - 1);
                    }
                    free(child_buffers[i]);
                    child_buffers[i] = NULL;
                    any_line = 1;
                }
            }

            if (any_line)
            {
                strncat(buffer, "\n", sizeof(buffer) - strlen(buffer) - 1);
                if (!is_root)
                {
                    write_response(buffer);
                }
                else
                {
                    printf("%s", buffer);
                }
            }
        }

        if (!is_root)
        {
            write_response("Done\n");
        }
    }
    else
    {
        if (!is_root)
        {
            write_response("Done\n");
        }
    }
}

void check_subtree_for_adopt(bool is_root)
{
    char buffer[1024];
    if (strcmp(friend_name, root) == 0)
    {
        snprintf(buffer, sizeof(buffer), "%s\n", friend_name);
    }
    else
    {
        snprintf(buffer, sizeof(buffer), "%s_%02d\n", friend_name, friend_value);
    }

    if (!is_root)
    {
        write_response(buffer);
    }
    else
    {
        printf("%s", buffer);
    }

    if (num_children > 0)
    {
        fprintf(stderr, "Number of children: %d\n", num_children);
        for (int i = 0; i < num_children; i++)
        {
            dprintf(children[i].write_fd, "Check_subtree_for_Adopt\n");
            fprintf(stderr, "Sent Check_subtree_for_Adopt to child %s\n", children[i].friend_name);
        }

        int num_active_children = num_children;
        char *child_buffers[MAX_CHILDREN] = {0};
        int child_done[MAX_CHILDREN] = {0};

        while (num_active_children > 0)
        {
            int any_line = 0;

            for (int i = 0; i < num_children; i++)
            {
                if (!child_done[i] && child_buffers[i] == NULL)
                {
                    char child_buffer[1024];
                    int n = read_line(children[i].read_fd, child_buffer, sizeof(child_buffer));
                    if (n > 0)
                    {
                        fprintf(stderr, "Received from child %s: %s\n", children[i].friend_name, child_buffer);
                        if (strcmp(child_buffer, "Done\n") == 0)
                        {
                            child_done[i] = 1;
                            num_active_children--;
                            fprintf(stderr, "Child %s is done\n", children[i].friend_name);
                        }
                        else
                        {
                            size_t len = strlen(child_buffer);
                            if (len > 0 && child_buffer[len - 1] == '\n')
                                child_buffer[len - 1] = '\0';
                            child_buffers[i] = strdup(child_buffer);
                            fprintf(stderr, "Collected buffer from child %s: %s\n", children[i].friend_name, child_buffers[i]);
                        }
                    }
                }
            }

            buffer[0] = '\0';
            for (int i = 0; i < num_children; i++)
            {
                if (child_buffers[i] != NULL)
                {
                    if (buffer[0] == '\0')
                    {
                        snprintf(buffer, sizeof(buffer), "%s", child_buffers[i]);
                    }
                    else
                    {
                        strncat(buffer, "\n", sizeof(buffer) - strlen(buffer) - 1);
                        strncat(buffer, child_buffers[i], sizeof(buffer) - strlen(buffer) - 1);
                    }
                    fprintf(stderr, "Aggregated from child %s: %s\n", children[i].friend_name, child_buffers[i]);
                    free(child_buffers[i]);
                    child_buffers[i] = NULL;
                    any_line = 1;
                }
            }

            if (any_line)
            {
                strncat(buffer, "\n", sizeof(buffer) - strlen(buffer) - 1);
                if (!is_root)
                {
                    write_response(buffer);
                    fprintf(stderr, "Wrote response: %s\n", buffer);
                }
                else
                {
                    // 根節點可以選擇是否需要在此處輸出
                }
            }
            printf("%s", buffer);
        }

        if (!is_root)
        {
            write_response("Done\n");
            fprintf(stderr, "Wrote Done\n");
        }
    }
    else
    {
        if (!is_root)
        {
            write_response("Done\n");
            fprintf(stderr, "Wrote Done\n");
        }
    }
}

void handle_check(char *target_friend_name)
{
    if (strcmp(target_friend_name, friend_name) == 0)
    {
        if (!is_Not_Tako())
        {
            write_response("Found\n");
        }
        check_subtree(true);
        if (!is_Not_Tako())
        {
            write_response("Done\n");
        }
    }
    else
    {
        int found = 0;
        for (int i = 0; i < num_children; i++)
        {
            dprintf(children[i].write_fd, "Check %s\n", target_friend_name);
            char response[16];
            int n = read_line(children[i].read_fd, response, sizeof(response));
            if (n <= 0)
            {
                continue;
            }
            if (strncmp(response, "Found", 5) == 0)
            {
                found = 1;
                if (!is_Not_Tako())
                {
                    write_response("Found\n");
                }

                char buffer[1024];
                while ((n = read_line(children[i].read_fd, buffer, sizeof(buffer))) > 0)
                {
                    if (strcmp(buffer, "Done\n") == 0)
                    {
                        break;
                    }
                    if (is_Not_Tako())
                    {
                        printf("%s", buffer);
                    }
                    else
                    {
                        write_response(buffer);
                    }
                }
                if (!is_Not_Tako())
                {
                    write_response("Done\n");
                }
                break;
            }
            else if (strncmp(response, "NotFound", 8) == 0)
            {
                continue;
            }
            else
            {

                fprintf(stderr, "Unexpected response: %s\n", response);
            }
        }
        if (!found && is_Not_Tako())
        {
            print_fail_check(target_friend_name);
        }
        if (!found && !is_Not_Tako())
        {
            write_response("NotFound\n");
        }
    }
}

void handle_check_for_adopt(char *target_friend_name)
{
    if (strcmp(target_friend_name, friend_name) == 0)
    {
        if (!is_Not_Tako())
        {
            write_response("Found\n");
        }
        check_subtree_for_adopt(true);
        if (!is_Not_Tako())
        {
            write_response("Done\n");
        }
    }
    else
    {
        int found = 0;
        for (int i = 0; i < num_children; i++)
        {
            dprintf(children[i].write_fd, "Check_Adopt %s\n", target_friend_name);
            char response[16];
            int n = read_line(children[i].read_fd, response, sizeof(response));
            if (n <= 0)
            {
                continue;
            }
            if (strncmp(response, "Found", 5) == 0)
            {
                found = 1;
                if (!is_Not_Tako())
                {
                    write_response("Found\n");
                }

                char buffer[1024];
                while ((n = read_line(children[i].read_fd, buffer, sizeof(buffer))) > 0)
                {
                    if (strcmp(buffer, "Done\n") == 0)
                    {
                        break;
                    }
                    if (is_Not_Tako())
                    {
                    }
                    else
                    {
                        write_response(buffer);
                    }
                }
                if (!is_Not_Tako())
                {
                    write_response("Done\n");
                }
                break;
            }
            else if (strncmp(response, "NotFound", 8) == 0)
            {
                continue;
            }
            else
            {

                fprintf(stderr, "Unexpected response: %s\n", response);
            }
        }
        if (!found && is_Not_Tako())
        {
            write_response("NotFound\n");
        }
        if (!found && !is_Not_Tako())
        {
            write_response("NotFound\n");
        }
    }
}

void terminate_subtree()
{
    for (int i = 0; i < num_children; i++)
    {
        dprintf(children[i].write_fd, "Graduate %s\n", children[i].friend_name);
        waitpid(children[i].pid, NULL, 0);
        close(children[i].read_fd);
        close(children[i].write_fd);
    }
    num_children = 0;
}

void handle_graduate(char *target_friend_name)
{
    if (strcmp(target_friend_name, friend_name) == 0)
    {
        if (!is_Not_Tako())
        {
            write_response("Found\n");
        }

        if (!is_Not_Tako())
        {
            write_response("Done\n");
        }

        terminate_subtree();
        if (is_Not_Tako())
        {
            print_final_graduate();
            exit(0);
        }
        else
        {
            exit(0);
        }
    }
    else
    {
        int found = 0;
        for (int i = 0; i < num_children; i++)
        {
            dprintf(children[i].write_fd, "Graduate %s\n", target_friend_name);
            char response[16];
            int n = read_line(children[i].read_fd, response, sizeof(response));
            if (n <= 0)
            {
                continue;
            }
            if (strncmp(response, "Found", 5) == 0)
            {
                found = 1;

                char buffer[1024];
                while ((n = read_line(children[i].read_fd, buffer, sizeof(buffer))) > 0)
                {
                    if (strcmp(buffer, "Done\n") == 0)
                    {
                        break;
                    }
                    if (is_Not_Tako())
                    {
                        printf("%s", buffer);
                    }
                    else
                    {
                        write_response(buffer);
                    }
                }

                waitpid(children[i].pid, NULL, 0);
                close(children[i].read_fd);
                close(children[i].write_fd);

                for (int j = i; j < num_children - 1; j++)
                {
                    children[j] = children[j + 1];
                }
                num_children--;
                i--;
                break;
            }
            else if (strncmp(response, "NotFound", 8) == 0)
            {
                continue;
            }
            else
            {

                fprintf(stderr, "Unexpected response: %s\n", response);
            }
        }
        if (!found && !is_Not_Tako())
        {
            write_response("NotFound\n");
        }
        if (found && !is_Not_Tako())
        {
            write_response("Done\n");
        }
    }
}

bool check_descendant(char *child_friend_name, char *parent_friend_name)
{
    fprintf(stderr, "Checking if %s is a descendant of %s\n", parent_friend_name, child_friend_name);

    // 首先，在當前節點的直接子節點中查找 child_friend_name
    int target_child = -1;
    for (int i = 0; i < num_children; i++)
    {
        if (strcmp(children[i].friend_name, child_friend_name) == 0)
        {
            target_child = i;
            break;
        }
    }

    if (target_child == -1)
    {
        // 如果在直接子節點中沒有找到，則向所有子節點發送 "Check <child_friend_name>" 命令
        for (int i = 0; i < num_children; i++)
        {
            dprintf(children[i].write_fd, "Check_Adopt %s\n", child_friend_name);
            fprintf(stderr, "Sent Check command to child %s\n", children[i].friend_name);

            char response[16];
            int n = read_line(children[i].read_fd, response, sizeof(response));
            if (n > 0 && strncmp(response, "Found", 5) == 0)
            {
                target_child = i;
                break;
            }
        }
    }

    if (target_child == -1)
    {
        // 如果找不到 child_friend_name，則返回 false
        fprintf(stderr, "Child %s not found under %s\n", child_friend_name, friend_name);
        return false;
    }

    // 現在，向找到的 child_friend_name 節點發送 "Check <parent_friend_name>" 命令
    dprintf(children[target_child].write_fd, "Check_Adopt %s\n", parent_friend_name);
    fprintf(stderr, "Sent Check command to child %s to verify descendant relationship\n", children[target_child].friend_name);

    char res[16];
    int m = read_line(children[target_child].read_fd, res, sizeof(res));
    if (m > 0 && strncmp(res, "Found", 5) == 0)
    {
        fprintf(stderr, "%s is a descendant of %s\n", parent_friend_name, child_friend_name);
        return true;
    }

    fprintf(stderr, "%s is not a descendant of %s\n", parent_friend_name, child_friend_name);
    return false;
}

void write_subtree(const char *fifo_name)
{
    // 打開 FIFO 進行寫入
    fprintf(stderr, "Attempting to open FIFO for writing: %s\n", fifo_name);
    int fifo_fd = open(fifo_name, O_WRONLY);
    if (fifo_fd == -1)
    {
        perror("open fifo for writing");
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "Successfully opened FIFO for writing: %s\n", fifo_name);

    // 重定向 stdout 到 FIFO
    if (dup2(fifo_fd, STDOUT_FILENO) == -1)
    {
        perror("dup2");
        close(fifo_fd);
        exit(EXIT_FAILURE);
    }
    close(fifo_fd); // 關閉原始的 FIFO 文件描述符

    // 調用 check_subtree_for_adopt 並將子樹信息寫入 FIFO
    fprintf(stderr, "Child process executing check_subtree_for_adopt(true)\n");
    check_subtree_for_adopt(true); // is_root 為 true，將子樹信息寫入 stdout (FIFO)

    fprintf(stderr, "Child process finished check_subtree_for_adopt(true)\n");

    // 關閉 stdout 並退出
    close(STDOUT_FILENO);
    exit(0);
}

int find_friend_value_in_buffer(const char *buffer, const char *target_friend_name)
{
    // 複製緩衝區以避免修改原始數據
    char *buffer_copy = strdup(buffer);
    if (buffer_copy == NULL)
    {
        perror("strdup");
        exit(EXIT_FAILURE);
    }

    char *line = strtok(buffer_copy, "\n");
    while (line != NULL)
    {
        // 檢查行是否以目標朋友名稱開頭，且後面跟著 '_'
        if (strncmp(line, target_friend_name, strlen(target_friend_name)) == 0 && line[strlen(target_friend_name)] == '_')
        {
            int value;
            if (sscanf(line, "%*[^_]_%d", &value) == 1)
            {
                free(buffer_copy);
                return value;
            }
        }
        line = strtok(NULL, "\n");
    }

    free(buffer_copy);
    return -1; // 未找到
}

void handle_adopt(char *parent_friend_name, char *child_friend_name)
{
    // 1. 檢查是否存在循環引用
    if (check_descendant(child_friend_name, parent_friend_name))
    {
        // 打印錯誤信息
        fprintf(stdout, "%s is a descendant of %s\n", parent_friend_name, child_friend_name);
        return;
    }

    // 2. 創建唯一的 FIFO 名稱
    char fifo_name[256];
    snprintf(fifo_name, sizeof(fifo_name), "/tmp/Adopt_%d.fifo", getpid());

    fprintf(stderr, "Creating FIFO: %s\n", fifo_name); // 調試輸出
    if (mkfifo(fifo_name, 0666) == -1 && errno != EEXIST)
    {
        perror("mkfifo");
        exit(EXIT_FAILURE);
    }

    // 3. 打開 FIFO 進行讀取，使用非阻塞模式避免阻塞
    fprintf(stderr, "Opening FIFO for reading: %s\n", fifo_name); // 調試輸出
    int fifo_fd = open(fifo_name, O_RDONLY | O_NONBLOCK);
    if (fifo_fd == -1)
    {
        perror("open fifo for reading");
        unlink(fifo_name);
        exit(EXIT_FAILURE);
    }
    fprintf(stderr, "Successfully opened FIFO for reading: %s\n", fifo_name); // 調試輸出

    // 4. 發送 "Write_subtree <fifo_name>\n" 命令給 child_friend_name
    bool child_found = false;
    for (int i = 0; i < num_children; i++)
    {
        if (strcmp(children[i].friend_name, child_friend_name) == 0)
        {
            // 構造命令字符串
            char cmd[512];
            snprintf(cmd, sizeof(cmd), "Write_subtree %s\n", fifo_name);
            fprintf(stderr, "Sending Write_subtree command to child %s with FIFO %s\n", child_friend_name, fifo_name); // 調試輸出

            // 使用 write 發送命令到子進程的 write_fd
            if (write(children[i].write_fd, cmd, strlen(cmd)) == -1)
            {
                perror("write to child");
                close(fifo_fd);
                unlink(fifo_name);
                exit(EXIT_FAILURE);
            }

            child_found = true;
            break;
        }
    }

    if (!child_found)
    {
        fprintf(stderr, "Child %s not found to adopt\n", child_friend_name);
        close(fifo_fd);
        unlink(fifo_name);
        exit(EXIT_FAILURE);
    }

    // 5. 設置 FIFO 文件描述符為阻塞模式
    int flags = fcntl(fifo_fd, F_GETFL, 0);
    if (flags == -1)
    {
        perror("fcntl F_GETFL");
        close(fifo_fd);
        unlink(fifo_name);
        exit(EXIT_FAILURE);
    }
    flags &= ~O_NONBLOCK;
    if (fcntl(fifo_fd, F_SETFL, flags) == -1)
    {
        perror("fcntl F_SETFL");
        close(fifo_fd);
        unlink(fifo_name);
        exit(EXIT_FAILURE);
    }

    // 6. 讀取子樹信息
    fprintf(stderr, "Reading subtree information from FIFO: %s\n", fifo_name); // 調試輸出
    char buffer[4096];
    ssize_t bytes;
    buffer[0] = '\0';
    while ((bytes = read(fifo_fd, buffer + strlen(buffer), sizeof(buffer) - strlen(buffer) - 1)) > 0)
    {
        buffer[strlen(buffer) + bytes] = '\0';
    }

    if (bytes == -1)
    {
        perror("read fifo");
        close(fifo_fd);
        unlink(fifo_name);
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Received data from FIFO:\n%s\n", buffer); // 調試輸出
    close(fifo_fd);

    // 7. 等待子進程終止並從 children 中移除
    // 不需要再等待，因為已經移除了 waitpid 呼叫

    // 8. 將子樹信息按行分割並處理每一行
    // 首先，找到 parent_friend_value
    int parent_value = 0;
    if (strcmp(parent_friend_name, root) == 0)
    {
        parent_value = 100; // 根節點的值
    }
    else
    {
        parent_value = find_friend_value_in_buffer(buffer, parent_friend_name);
        if (parent_value == -1)
        {
            fprintf(stderr, "Parent friend name %s not found in subtree\n", parent_friend_name);
            unlink(fifo_name);
            exit(EXIT_FAILURE);
        }
    }

    // 現在，處理每一行
    char *line = strtok(buffer, "\n");
    while (line != NULL)
    {
        // 跳過 "Done" 行
        if (strcmp(line, "Done") == 0)
        {
            line = strtok(NULL, "\n");
            continue;
        }

        // 解析 <friend_name>_<friend_value>
        char name[MAX_FRIEND_NAME_LEN];
        int value;
        if (sscanf(line, "%[^_]_%d", name, &value) != 2)
        {
            fprintf(stderr, "Invalid subtree info format: %s\n", line);
            exit(EXIT_FAILURE);
        }

        // 計算新的值
        value %= parent_value;

        // 構造新的 child_friend_info
        char new_friend_info[MAX_FRIEND_INFO_LEN];
        snprintf(new_friend_info, sizeof(new_friend_info), "%s_%02d", name, value);
        fprintf(stderr, "Recreating child: %s with value %d\n", new_friend_info, value); // 調試輸出

        // 使用 Meet 命令重新創建節點
        handle_meet(parent_friend_name, new_friend_info);

        line = strtok(NULL, "\n");
    }

    // 9. 刪除 FIFO 文件
    unlink(fifo_name);
    fprintf(stderr, "Deleted FIFO: %s\n", fifo_name); // 調試輸出

    // 10. 打印成功信息
    fprintf(stdout, "%s has adopted %s\n", parent_friend_name, child_friend_name);
}

int main(int argc, char *argv[])
{
    pid_t process_pid = getpid();
    if (argc != 2)
    {
        fprintf(stderr, "Usage: ./friend [friend_info]\n");
        return 0;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    strncpy(friend_info, argv[1], MAX_FRIEND_INFO_LEN);

    if (strcmp(argv[1], root) == 0)
    {
        strncpy(friend_name, friend_info, MAX_FRIEND_NAME_LEN);
        friend_name[MAX_FRIEND_NAME_LEN - 1] = '\0';
        friend_value = 100;
    }
    else
    {
        char name_value[MAX_FRIEND_INFO_LEN];
        strcpy(name_value, friend_info);
        char *underscore = strchr(name_value, '_');
        if (underscore != NULL)
        {
            *underscore = '\0';
            strncpy(friend_name, name_value, MAX_FRIEND_NAME_LEN);
            friend_value = atoi(underscore + 1);
        }
        else
        {
            fprintf(stderr, "Invalid friend_info format\n");
            exit(EXIT_FAILURE);
        }
    }

    inputbuf = (char *)malloc(inputbufsize);
    if (inputbuf == NULL)
    {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        int fd = is_Not_Tako() ? STDIN_FILENO : PARENT_READ_FD;
        int argc = input(fd);
        if (argc == 0)
        {
            continue;
        }
        char *cmd = input_argv[0];
        if (strcmp(cmd, "Meet") == 0)
        {
            if (argc == 3)
            {
                handle_meet(input_argv[1], input_argv[2]);
            }
            else
            {
                fprintf(stderr, "Invalid command: %s\n", cmd);
            }
        }
        else if (strcmp(cmd, "Check") == 0)
        {
            if (argc == 2)
            {
                handle_check(input_argv[1]);
            }
            else
            {
                fprintf(stderr, "Invalid command: %s\n", cmd);
            }
        }
        else if (strcmp(cmd, "Check_Adopt") == 0)
        {
            if (argc == 2)
            {
                handle_check_for_adopt(input_argv[1]);
            }
            else
            {
                fprintf(stderr, "Invalid command: %s\n", cmd);
            }
        }
        else if (strcmp(cmd, "Write_subtree") == 0)
        {
            if (argc == 2)
            {
                char *fifo_name = input_argv[1];
                fprintf(stderr, "Received Write_subtree command with FIFO: %s\n", fifo_name); // 調試輸出
                write_subtree(fifo_name);
            }
            else
            {
                fprintf(stderr, "Invalid command: %s\n", cmd);
            }
        }
        else if (strcmp(cmd, "Check_subtree") == 0)
        {
            if (argc == 1)
            {
                // 處理 "Check_subtree" 命令（不帶參數）
                check_subtree(false);
            }
            else
            {
                fprintf(stderr, "Invalid command: %s\n", cmd);
            }
        }
        else if (strcmp(cmd, "Adopt") == 0)
        {
            if (argc == 3)
            {
                handle_adopt(input_argv[1], input_argv[2]);
            }
            else
            {
                fprintf(stderr, "Invalid command: %s\n", cmd);
            }
        }
        else if (strcmp(cmd, "Graduate") == 0)
        {
            if (argc == 2)
            {
                if (is_Not_Tako())
                {
                    handle_check(input_argv[1]);
                }
                handle_graduate(input_argv[1]);
            }
            else
            {
                fprintf(stderr, "Invalid command: %s\n", cmd);
            }
        }
        else if (strcmp(cmd, "Check_subtree") == 0)
        {
            check_subtree(false);
        }
        else if (strcmp(cmd, "Check_subtree_for_Adopt") == 0)
        {
            check_subtree_for_adopt(false);
        }
        else
        {
            fprintf(stderr, "Invalid command: %s\n", cmd);
        }
        int status;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
        {
            // 找到對應的子進程並從 children 陣列中移除
            for (int i = 0; i < num_children; i++)
            {
                if (children[i].pid == pid)
                {
                    close(children[i].read_fd);
                    close(children[i].write_fd);
                    // 移除子進程
                    for (int j = i; j < num_children - 1; j++)
                    {
                        children[j] = children[j + 1];
                    }
                    num_children--;
                    break;
                }
            }
        }

        if (pid == -1 && errno != ECHILD)
        {
            perror("waitpid");
            exit(EXIT_FAILURE);
        }
    }
    return 0;
}
