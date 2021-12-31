#include <debug.h>
#include <string.h>
#include "filesys/buffer_cache.h"
#include "filesys/filesys.h"
#include "threads/synch.h"
#include "userprog/syscall.h"

static struct buffer_cache_entry cache[NUM_CACHE];

static struct lock buffer_cache_lock;

void
buffer_cache_init (void)
{
  lock_init (&buffer_cache_lock);

  for (int i = 0; i < NUM_CACHE; ++ i)
    cache[i].valid_bit = false;
}

static void
buffer_cache_flush (struct buffer_cache_entry *entry)
{
  if(!(entry != NULL && entry->valid_bit == true))
    sys_exit(-1);

  if (entry->dirty) {
    block_write (fs_device, entry->disk_sector, entry->buffer);
    entry->dirty = false;
  }
}

void
buffer_cache_flush_all(void)
{
	lock_acquire (&buffer_cache_lock);
	for (size_t i= 0; i < NUM_CACHE; ++ i)
	{
		if(cache[i].valid_bit)
			buffer_cache_flush(&(cache[i]));
	}
	lock_release(&buffer_cache_lock);
}

void
buffer_cache_terminate (void)
{
  buffer_cache_flush_all();
}

static struct buffer_cache_entry*
buffer_cache_lookup (block_sector_t sector)
{
  for (size_t i = 0; i < NUM_CACHE; ++ i)
  {
	if(cache[i].valid_bit)
	{
		if(cache[i].disk_sector == sector)
			return &(cache[i]);	
	}
  }
  return NULL;
}

static struct buffer_cache_entry*
buffer_cache_select_victim (void)
{
  size_t clock = 0;

  while (1) {
    if (cache[clock].valid_bit==false)
	  return &(cache[clock]);
	
    if (cache[clock].reference_bit)
      cache[clock].reference_bit = false;	
    else
      break;

    clock ++;
    clock %= NUM_CACHE;
  }

  struct buffer_cache_entry *slot = &cache[clock];
  if (slot->dirty) {
    buffer_cache_flush (slot);
  }

  slot->valid_bit = false;
  return slot;
}

void
buffer_cache_read (block_sector_t sector, void *target)
{
  lock_acquire (&buffer_cache_lock);

  struct buffer_cache_entry *slot = buffer_cache_lookup (sector);
  if (slot == NULL) {
    slot = buffer_cache_select_victim ();

    update_cache(slot,true,sector,false);
    block_read (fs_device, sector, slot->buffer);
  }

  cache_access(slot,true,true,1);
  memcpy (target, slot->buffer, BLOCK_SECTOR_SIZE);

  lock_release (&buffer_cache_lock);
}

void
buffer_cache_write (block_sector_t sector, const void *source)
{
  lock_acquire (&buffer_cache_lock);

  struct buffer_cache_entry *slot = buffer_cache_lookup (sector);
  if (slot == NULL) {
    slot = buffer_cache_select_victim ();

    update_cache(slot,true,sector,false);
    block_read (fs_device, sector, slot->buffer);
  }

  cache_access(slot,true,true,2);
  memcpy (slot->buffer, source, BLOCK_SECTOR_SIZE);

  lock_release (&buffer_cache_lock);
}

void update_cache(struct buffer_cache_entry *slot, bool valid, block_sector_t sector, bool dirty)
{
    slot->valid_bit = valid;
    slot->disk_sector = sector;
    slot->dirty = dirty;   
}

void cache_access(struct buffer_cache_entry *slot, bool reference_bit, bool dirty, int mode)
{
  if(mode==1)
  {
    slot->reference_bit = reference_bit;
  }
  else if(mode==2)
  {
    slot->reference_bit = reference_bit;
    slot->dirty = dirty;
  }
}
