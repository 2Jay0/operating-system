#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/syscall.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "lib/kernel/list.h"

static void syscall_handler (struct intr_frame *);

static void check_user (const uint8_t *uaddr);
static int32_t get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static int memread_user (void *src, void *des, size_t bytes);

enum fd_search_filter { FD_FILE = 1, FD_DIRECTORY = 2 };
static struct file_desc* find_file_desc(struct thread *, int fd, enum fd_search_filter flag);


void sys_exit (int);
pid_t sys_exec (const char *cmdline);
int sys_wait (pid_t pid);

bool sys_create(const char* filename, unsigned initial_size);
bool sys_remove(const char* filename);
int sys_open(const char* file);
int sys_filesize(int fd);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void *buffer, unsigned size);

bool sys_chdir(const char *filename);
bool sys_mkdir(const char *filename);
bool sys_readdir(int fd, char *filename);
bool sys_isdir(int fd);
int sys_inumber(int fd);

struct lock filesys_lock;

void
syscall_init (void)
{
  lock_init (&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

// in case of invalid memory access, fail and exit.
static void fail_invalid_access(void) {
  if (lock_held_by_current_thread(&filesys_lock))
    lock_release (&filesys_lock);

  sys_exit (-1);
  NOT_REACHED();
}

static void
check_user (const uint8_t *uaddr) {
  // check uaddr range or segfaults
  if(get_user (uaddr) == -1)
    fail_invalid_access();
}

/*******************Pintos Manual********************/
static int32_t
get_user (const uint8_t *uaddr) {
  // check that a user pointer `uaddr` points below PHYS_BASE
  if (! ((void*)uaddr < PHYS_BASE)) {
    return -1;
  }

  // as suggested in the reference manual, see (3.1.5)
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
      : "=&a" (result) : "m" (*uaddr));
  return result;
}

static bool
put_user (uint8_t *udst, uint8_t byte) {
  // check that a user pointer `udst` points below PHYS_BASE
  if (! ((void*)udst < PHYS_BASE)) {
    return false;
  }

  int error_code;

  // as suggested in the reference manual, see (3.1.5)
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}


static int
memread_user (void *src, void *dst, size_t bytes)
{
  int32_t value;
  size_t i;
  for(i=0; i<bytes; i++) {
    value = get_user(src + i);
    if(value == -1) // segfault or invalid memory access
      fail_invalid_access();

    *(char*)(dst + i) = value & 0xff;
  }
  return (int)bytes;
}

static void
syscall_handler (struct intr_frame *f)
{
  thread_current()->current_esp = f->esp;

  switch(*(uint32_t*)(f->esp)) 
  {
    case SYS_HALT:
      shutdown_power_off();
		  break;

    case SYS_EXIT:
    {
     
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

	  sys_exit(*(uint32_t*)(f->esp+4));
      break;
    }

  case SYS_EXEC:
  {
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

      f->eax = process_execute((const char*)*(uint32_t*)(f->esp+4));
      break;
  }

  case SYS_WAIT: 
  { 
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

      f->eax = sys_wait((tid_t)*(uint32_t*)(f->esp+4));
      break;
    }

  case SYS_CREATE: 
  {
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);
	  if(!is_user_vaddr(f->esp+8))
		  sys_exit(-1);

	  f->eax = sys_create((const char*)*(uint32_t*)(f->esp+4),(unsigned)*(uint32_t*)(f->esp+8));
	  break;
  }

  case SYS_REMOVE: 
  {
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

	  f->eax = sys_remove((const char*)*(uint32_t*)(f->esp+4));
	  break;
  }

  case SYS_OPEN: 
    { 
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);
	  f->eax = sys_open((const char*)*(uint32_t*)(f->esp+4));
	  break;
    }

  case SYS_FILESIZE: 
  { 
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

	  f->eax = sys_filesize((int)*(uint32_t*)(f->esp+4));
	  break;
  }

  case SYS_READ: 
  { 	  
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);
	  if(!is_user_vaddr(f->esp+8))
		  sys_exit(-1);
	  if(!is_user_vaddr(f->esp+12))
		  sys_exit(-1);

	  f->eax = sys_read((int)*(uint32_t*)(f->esp+4),(const void*)*(uint32_t*)(f->esp+8),(unsigned)*(uint32_t*)(f->esp+12));
      break;
  }

  case SYS_WRITE: 
  { 
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);
	  if(!is_user_vaddr(f->esp+8))
		  sys_exit(-1);
	  if(!is_user_vaddr(f->esp+12))
		  sys_exit(-1);

	  f->eax = sys_write((int)*(uint32_t*)(f->esp+4),(const void*)*(uint32_t*)(f->esp+8),(unsigned)*(uint32_t*)(f->esp+12));
	  break;
  }

  case SYS_SEEK:
  {
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);
	  if(!is_user_vaddr(f->esp+8))
		  sys_exit(-1);

	  sys_seek((int)*(uint32_t*)(f->esp+4),(unsigned)*(uint32_t*)(f->esp+8));
	  break;
  }

  case SYS_TELL: 
  {
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

	  f->eax = sys_tell((int)*(uint32_t*)(f->esp+4));
	  break;
  }

  case SYS_CLOSE: 
  {
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

	  sys_close((int)*(uint32_t*)(f->esp+4));
	  break;
  }

  case SYS_CHDIR:
  {
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

	  f->eax = sys_chdir((const char*)*(uint32_t*)(f->esp+4));
      break;
  }

  case SYS_MKDIR: 
  {
      const char* filename;
      int return_code;

      memread_user(f->esp + 4, &filename, sizeof(filename));

      return_code = sys_mkdir(filename);
      f->eax = return_code;
	  
	  /*if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

	  f->eax = sys_mkdir((const char*)*(uint32_t*)(f->esp+4));*/
      break;
  }

  case SYS_READDIR:
  {
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

	  if(!is_user_vaddr(f->esp+8))
		  sys_exit(-1);

	  f->eax = sys_readdir((int)*(uint32_t*)(f->esp+4),(char*)*(uint32_t*)(f->esp+8));
      break;
  }
  case SYS_ISDIR: 
  {
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

	  f->eax = sys_isdir((int)*(uint32_t*)(f->esp+4));
      break;
  }
  case SYS_INUMBER:
  {
	  if(!is_user_vaddr(f->esp+4))
		  sys_exit(-1);

	  f->eax = sys_inumber((int)*(uint32_t*)(f->esp+4));
      break;
  }

  default:
    break;
  }

}

void sys_exit(int status) {
  printf("%s: exit(%d)\n", thread_current()->name, status);

  thread_current()->exit_status = status;
  thread_exit();
}

pid_t sys_exec(const char *cmdline) {
  
  lock_acquire (&filesys_lock); 
  pid_t pid = process_execute(cmdline);
  lock_release (&filesys_lock);
  return pid;
}

int sys_wait(tid_t pid)
{
	return process_wait(pid);
}

bool sys_create (const char *file_name, unsigned size)
{
	if(file_name==NULL)
		sys_exit(-1);

	lock_acquire(&filesys_lock);
	bool res = filesys_create(file_name,size,false);
	lock_release(&filesys_lock);
	return res;
}

bool sys_remove(const char* filename) {
  lock_acquire (&filesys_lock);
  bool res = filesys_remove(filename);
  lock_release (&filesys_lock);
  return res;
}

int sys_open(const char* file) {
  struct file* file_opened;
  struct file_desc* fd = palloc_get_page(0);
  if (!fd) {
    return -1;
  }

  lock_acquire (&filesys_lock);
  file_opened = filesys_open(file);
  if (!file_opened) {
    palloc_free_page (fd);
    lock_release (&filesys_lock);
    return -1;
  }

  fd->file = file_opened; 

  struct inode *inode = file_get_inode(fd->file);
  if(inode != NULL && inode_is_directory(inode)) {
    fd->dir = dir_open( inode_reopen(inode) );
  }
  else fd->dir = NULL;

  struct list* fd_list = &thread_current()->file_descriptors;
  if (list_empty(fd_list)) {
    fd->id = 3;
  }
  else {
    fd->id = (list_entry(list_back(fd_list), struct file_desc, elem)->id) + 1;
  }
  list_push_back(fd_list, &(fd->elem));

  lock_release (&filesys_lock);
  return fd->id;
}

int sys_filesize(int fd) {
  struct file_desc* file_d;

  lock_acquire (&filesys_lock);
  file_d = find_file_desc(thread_current(), fd, FD_FILE);

  if(file_d == NULL) {
    lock_release (&filesys_lock);
    return -1;
  }

  int ret = file_length(file_d->file);
  lock_release (&filesys_lock);
  return ret;
}

void sys_seek(int fd, unsigned position) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

  if(file_d && file_d->file) {
    file_seek(file_d->file, position);
  }
  else
    return; 

  lock_release (&filesys_lock);
}

unsigned sys_tell(int fd) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

  unsigned ret;
  if(file_d && file_d->file) {
    ret = file_tell(file_d->file);
  }
  else
    ret = -1; 

  lock_release (&filesys_lock);
  return ret;
}

void sys_close(int fd) {
  lock_acquire (&filesys_lock);
  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);

  if(file_d && file_d->file) {
    file_close(file_d->file);
    if(file_d->dir) dir_close(file_d->dir);
    list_remove(&(file_d->elem));
    palloc_free_page(file_d);
  }
  lock_release (&filesys_lock);
}

int sys_read(int fd, void *buffer, unsigned size) {

  if(!is_user_vaddr(buffer))
	  sys_exit(-1);

  lock_acquire (&filesys_lock);
  int ret;

  if(fd == 0) { 
    unsigned i;
    for(i = 0; i < size; ++i) {
      if(! put_user(buffer + i, input_getc()) ) {
        lock_release (&filesys_lock);
        sys_exit(-1); 
      }
    }
    ret = size;
  }
  else {
    struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

    if(file_d && file_d->file) {
      ret = file_read(file_d->file, buffer, size);
    }
    else 
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}

int sys_write(int fd, const void *buffer, unsigned size) {

  lock_acquire (&filesys_lock);
  int ret;

  if(fd == 1) { 
    putbuf(buffer, size);
    ret = size;
  }
  else {
    struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE);

    if(file_d && file_d->file) {
      ret = file_write(file_d->file, buffer, size);
    }
    else 
      ret = -1;
  }

  lock_release (&filesys_lock);
  return ret;
}


static struct file_desc*
find_file_desc(struct thread *t, int fd, enum fd_search_filter flag)
{
  ASSERT (t != NULL);

  if (fd < 3) {
    return NULL;
  }

  struct list_elem *e;

  if (! list_empty(&t->file_descriptors)) {
    for(e = list_begin(&t->file_descriptors);
        e != list_end(&t->file_descriptors); e = list_next(e))
    {
      struct file_desc *desc = list_entry(e, struct file_desc, elem);
      if(desc->id == fd) {
        if (desc->dir != NULL && (flag & FD_DIRECTORY) )
          return desc;
        else if (desc->dir == NULL && (flag & FD_FILE) )
          return desc;
      }
    }
  }

  return NULL; 
}

bool sys_chdir(const char *filename)
{
  lock_acquire (&filesys_lock);
  bool ret = filesys_chdir(filename);
  lock_release (&filesys_lock);

  return ret;
}

bool sys_mkdir(const char *filename)
{
  check_user((const uint8_t*) filename);

  lock_acquire (&filesys_lock);
  bool return_code = filesys_create(filename, 0, true);
  lock_release (&filesys_lock);

  return return_code;
}

bool sys_readdir(int fd, char *name)
{
  struct file_desc* file_d;
  bool ret = false;

  lock_acquire (&filesys_lock);
  file_d = find_file_desc(thread_current(), fd, FD_DIRECTORY);
  if (file_d == NULL) 
  {
    lock_release (&filesys_lock);
    return ret;
  }

  struct inode *inode;
  inode = file_get_inode(file_d->file); 
  if(inode == NULL) 
  {
    lock_release (&filesys_lock);
    return ret;
  }

  if(! inode_is_directory(inode)) 
  {
    lock_release (&filesys_lock);
    return ret;
  }

  ret = dir_readdir (file_d->dir, name);

  lock_release (&filesys_lock);
  return ret;
}

bool sys_isdir(int fd)
{
  lock_acquire (&filesys_lock);

  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);
  bool ret = inode_is_directory (file_get_inode(file_d->file));

  lock_release (&filesys_lock);
  return ret;
}

int sys_inumber(int fd)
{
  lock_acquire (&filesys_lock);

  struct file_desc* file_d = find_file_desc(thread_current(), fd, FD_FILE | FD_DIRECTORY);
  int ret = (int) inode_get_inumber (file_get_inode(file_d->file));

  lock_release (&filesys_lock);
  return ret;
}

