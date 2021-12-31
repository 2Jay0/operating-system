#include "vm/frame.h"
#include "vm/swap.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include <threads/malloc.h>
#include <stdio.h>
#include "userprog/syscall.h"

void lru_add_page(struct page *page)
{
	if(page != NULL)
	{
     	lock_acquire(&lru_list_lock);
		list_push_back(&lru_list, &page->lru);
		lock_release(&lru_list_lock);
	}
}

void lru_del_page(struct page* page)
{
	if(page != NULL)
	{
		if(lru_clock == page)
			lru_clock = list_entry(list_remove(&page->lru), struct page, lru);
		else
			list_remove(&page->lru);
	}
}

struct page *alloc_page(enum palloc_flags flags)
{
	struct page *new_page;
	void *kaddr;
	if((flags & PAL_USER) == 0)
		return NULL;

	kaddr = palloc_get_page(flags);
	while(kaddr == NULL)
	{
		check_free_pages();
		kaddr = palloc_get_page(flags);
	}
	new_page = malloc(sizeof(struct page));
	if(new_page == NULL)
	{
		palloc_free_page(kaddr);
		return NULL;
	}
	new_page->kaddr  = kaddr;
	new_page->pg_thread = thread_current();

	lru_add_page(new_page);
	return new_page;
}

void free_page(void *kaddr)
{
	struct list_elem *element;
	struct page *lru_page;
	//lock_acquire(&lru_list_lock);

	for(element = list_begin(&lru_list); element != list_end(&lru_list); element = list_next(element))
	{
		lru_page = list_entry(element, struct page, lru);
		if(lru_page->kaddr == kaddr)
		{
			palloc_free_page(lru_page->kaddr);
			lru_del_page(lru_page);
			free(lru_page);
			break;
		}
	}
	//lock_release(&lru_list_lock);
}

struct list_elem* get_next_lru_clock(void)
{
	struct list_elem *elem;

	if(lru_clock == NULL)
	{
		elem = list_begin(&lru_list);
		if(elem != list_end(&lru_list))
		{
			lru_clock = list_entry(elem, struct page, lru);
			return elem;
		}

		return NULL;
	}

	elem = list_next(&lru_clock->lru);
	if(elem == list_end(&lru_list))
	{
		if(&lru_clock->lru == list_begin(&lru_list))
			return NULL;

		else
			elem = list_begin(&lru_list);
	}
	lru_clock = list_entry(elem, struct page, lru);
	return elem;
}

void check_free_pages(void)
{
	struct thread *page_thread;
	struct list_elem *elem;
	struct page *lru_page;
	
	lock_acquire(&lru_list_lock);
	if(list_empty(&lru_list) == true)
	{
		lock_release(&lru_list_lock);
		return;
	}
	while(1)
	{
		elem = get_next_lru_clock();
		if(elem == NULL)
			break;

		lru_page = list_entry(elem, struct page, lru);
		if(lru_page->vme->pinned == true)
			continue;
		page_thread = lru_page->pg_thread;
		if(pagedir_is_accessed(page_thread->pagedir, lru_page->vme->vaddr))
		{
			pagedir_set_accessed(page_thread->pagedir, lru_page->vme->vaddr, false);
			continue;
		}
		if(pagedir_is_dirty(page_thread->pagedir, lru_page->vme->vaddr) || lru_page->vme->type == VM_ANON)
		{
			if(lru_page->vme->type == VM_FILE)
			{
				lock_acquire(&f_lock);
				file_write_at(lru_page->vme->file, lru_page->kaddr ,lru_page->vme->read_bytes, lru_page->vme->offset);
				lock_release(&f_lock);
			}
			else
			{
				lru_page->vme->type = VM_ANON;
				lru_page->vme->swap_slot = swap_out(lru_page->kaddr);
 			}
		}
		lru_page->vme->is_loaded = false;
		pagedir_clear_page(page_thread->pagedir, lru_page->vme->vaddr);

		palloc_free_page(lru_page->kaddr);
		lru_del_page(lru_page);
		free(lru_page);
		break;
	}
    lock_release(&lru_list_lock);
	return;
}
