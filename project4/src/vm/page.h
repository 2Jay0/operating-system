#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>
#include "threads/thread.h"
#include "filesys/off_t.h"

#define VM_BIN 1 
#define VM_FILE 2
#define VM_ANON 3
#define CLOSE_ALL 9999
/* struct for vm_entry */
struct page_entry{
	uint8_t type;                      // VM_BIN, VM_FILE, VM_ANON
	void *vaddr;                       // virtual address 
	bool writable;                     
	bool is_loaded;                    // if true, physical memory is loaded
	bool pinned;
	struct file *file;
	struct list_elem mmap_elem;        // list_elem for mmap_file's vm_list
	size_t offset;
	size_t read_bytes;                   
	size_t zero_bytes;
	size_t swap_slot;
	struct hash_elem elem;             // hash elem for thread's vm
};

/* struct for mmap_file*/
struct mmap_file{
	int mapid;
	struct file *file;
	struct list_elem elem;             // list_elem for thread's mmap_list
};

struct page{
	void *kaddr;
	struct page_entry *vme;
	struct thread *pg_thread;
	struct list_elem lru;
};

void insert_inform(struct page_entry* pg_entry, struct file *file, off_t ofs, uint8_t *upage,
                   uint32_t page_read_bytes, uint32_t page_zero_bytes, bool writable);
void update_inform(struct page_entry* pg_entry, bool is_loaded, uint8_t type, bool pinned);
void page_init(struct hash *vm);
void page_destroy(struct hash *vm);
struct page_entry *search_page_entry(void *vaddr);
bool insert_page_entry(struct hash *vm, struct page_entry *vme);
bool delete_page_entry(struct hash *vm, struct page_entry *vme);
bool load_file(void *kaddr, struct page_entry *vme);
int file_mmap(int fd, void *addr);
void do_munmap(struct mmap_file *mmap_file);
#endif
