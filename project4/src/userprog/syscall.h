#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/thread.h"

#define STACK_HEURISTIC 32
#define MIN_ADDR 0x8048000
#define MAX_ADDR 0xc0000000

struct lock f_lock;

void check_address(void *addr, void *esp);
void syscall_init (void);

int sys_wait(tid_t pid);
void sys_exit(int status);

int fibonacci(int n);
int max_of_four_int(int a, int b, int c, int d);

int sys_open (const char *file_name);

bool sys_create (const char *file, unsigned initial_size);
bool sys_remove (const char *file);

bool is_fd_NULL(struct thread *t, int check);
void sys_close(int fd);

int sys_filesize(int fd);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
bool fd_positive(int check);

int sys_mmap(int fd, void *addr);
void sys_munmap(int mapping);

#endif /* userprog/syscall.h */
