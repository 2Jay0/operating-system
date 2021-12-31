#ifndef FILESYS_BUFFER_CACHE_H
#define FILESYS_BUFFER_CACHE_H

#include "devices/block.h"
#include <stdbool.h>
#define NUM_CACHE 64

struct buffer_cache_entry {
  bool valid_bit;  
  bool reference_bit;
  bool dirty;

  block_sector_t disk_sector;
  uint8_t buffer[BLOCK_SECTOR_SIZE];
};

void buffer_cache_init (void);
void buffer_cache_terminate (void);
void buffer_cache_read (block_sector_t sector, void *target);
void buffer_cache_write (block_sector_t sector, const void *source);
void update_cache(struct buffer_cache_entry *slot, bool valid, block_sector_t sector, bool dirty);
void cache_access(struct buffer_cache_entry *slot, bool reference_bit, bool dirty, int mode);

#endif
