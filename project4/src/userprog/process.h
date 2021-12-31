#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#define MAX_STACK_SIZE (1 << 23)

#include "threads/thread.h"
#include "vm/page.h"
#include "filesys/off_t.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
bool handle_mm_fault(struct page_entry *vme);
bool grow_stack(void *addr);


#endif /* userprog/process.h */
