#ifndef FRAME_H
#define FRAME_H
#include "vm/page.h"
#include "lib/kernel/list.h"
#include <threads/palloc.h>

void lru_init(void);
void lru_add_page(struct page *page);
void lru_del_page(struct page *page);
struct page *alloc_page(enum palloc_flags flag);
void free_page(void *kaddr);
struct list_elem* get_next_lru_clock(void);
void check_free_pages(void);
struct file *file_get(int fd);
#endif 

