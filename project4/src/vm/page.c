#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <threads/malloc.h>
#include <threads/palloc.h>
#include "filesys/file.h"
#include "vm/page.h"
#include "vm/frame.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "lib/kernel/list.h"
#include "filesys/off_t.h"

static bool pg_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED);
static unsigned pg_hash_func(const struct hash_elem *e, void *aux UNUSED);
static void pg_destroy_func(struct hash_elem *e, void *aux UNUSED);

void insert_inform(struct page_entry* pg_entry, struct file *file, off_t ofs, uint8_t *upage,
                   uint32_t page_read_bytes, uint32_t page_zero_bytes, bool writable)
{
      pg_entry->file       = file;
	  pg_entry->offset     = ofs;
	  pg_entry->vaddr      = upage;
	  pg_entry->read_bytes = page_read_bytes;
	  pg_entry->zero_bytes = page_zero_bytes;
	  pg_entry->writable    = writable;
}

void update_inform(struct page_entry* pg_entry, bool is_loaded, uint8_t type, bool pinned)
{
    pg_entry->is_loaded = is_loaded;
    pg_entry->type      = type;
    pg_entry->pinned    = pinned;
}

static bool pg_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED)
{
	struct page_entry *vme_a = hash_entry(a, struct page_entry, elem);
	struct page_entry *vme_b = hash_entry(b, struct page_entry, elem);

	if(vme_a->vaddr < vme_b->vaddr)
		return true;
	else 
		return false;
}

static unsigned pg_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
	struct page_entry *vme = hash_entry(e, struct page_entry, elem);
	return hash_int((int)vme->vaddr);
}

static void pg_destroy_func(struct hash_elem *e, void *aux UNUSED)
{
	struct page_entry *vme = hash_entry(e, struct page_entry, elem);
	void *physical_address;
	if(vme->is_loaded)
	{
		physical_address = pagedir_get_page(thread_current()->pagedir, vme->vaddr);
		free_page(physical_address);
		pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
	}
	free(vme);
}

void page_init(struct hash *vm)
{
	hash_init(vm, pg_hash_func, pg_less_func, NULL);
}

void page_destroy(struct hash *vm)
{
	hash_destroy(vm, pg_destroy_func);
}

struct page_entry *search_page_entry(void *vaddr)
{
	struct page_entry vme;
	struct hash_elem *element;
	
	vme.vaddr = pg_round_down(vaddr); 
	element = hash_find(&thread_current()->vm, &vme.elem);
	
	if(element != NULL)
		return hash_entry(element, struct page_entry, elem);
		
	return NULL;
}

bool insert_page_entry(struct hash *vm, struct page_entry *vme)
{
	bool result = false;
	if(hash_insert(vm, &vme->elem) == NULL)
		result = true;
	return result;
}

bool delete_page_entry(struct hash *vm, struct page_entry *vme)
{
	bool result = false;
	if(hash_delete(vm, &vme->elem) != NULL)
		result = true;
	free(vme);
	return result;   
}

bool load_file(void *kaddr, struct page_entry *vme)
{
	bool result = false;   
	if((int)vme->read_bytes == file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset))
	{
		result = true;
		memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
	} 
	return result;
}

