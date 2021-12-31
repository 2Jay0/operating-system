#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdlib.h>
#include <string.h>
#include "filesys/filesys.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "filesys/off_t.h"
#include "threads/malloc.h"
#include "userprog/process.h"
#include "vm/page.h"
#include "vm/frame.h"

static void syscall_handler (struct intr_frame *);

void
check_address(void *addr, void *esp)
{
	struct page_entry *vm_entry;
	uint32_t address=(unsigned int)addr;
	if(address >= MIN_ADDR && address < MAX_ADDR) //if address is user_address
	{
		vm_entry = search_page_entry(addr); //find vm_entry if can't find vm_entry, exit the process
		if(vm_entry == NULL) //if can't find vm_entry
		{
			if(addr >= esp - STACK_HEURISTIC){
				if(!grow_stack(addr))
					sys_exit(-1);
			}
			else
				sys_exit(-1);
		}
	}
	else
		sys_exit(-1);
}

void check_buf(void *buffer, unsigned size, void *esp, bool to_write)
{
	struct page_entry *vme;
	unsigned i;
	char *check_buffer = (char *)buffer;

	for(i=0; i<size; i++)
	{
		check_address((void *)check_buffer, esp);
		vme = search_page_entry((void *)check_buffer);
		if(vme != NULL)
		{
			if(to_write == true)
			{
				if(vme->writable == false)
					sys_exit(-1);
			}
		}

		check_buffer++;
	}
}

void check_str(const void *str, void *esp)
{
	char *check_str = (char *)str;
	check_address((void *)check_str,esp);
	while(*check_str != 0)
	{
		check_str += 1;
		check_address(check_str, esp);
	}
}

void
syscall_init (void) 
{
  lock_init(&f_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void* esp = f->esp;
  check_address(esp,f->esp);
  switch(*(uint32_t*)(f->esp))
  {
	  case SYS_HALT:
		  shutdown_power_off();
		  break;
	  case SYS_EXIT:
	  {
		  check_address((void*)(f->esp+4), f->esp);
		  sys_exit(*(uint32_t*)(f->esp+4));
		  break;
	  }
	  case SYS_EXEC:
	  {
		  check_address((void*)(f->esp+4), f->esp);
		  check_str((const char*)*(uint32_t*)(f->esp+4), f->esp);
		  f->eax = process_execute((const char*)*(uint32_t*)(f->esp+4));
		  break;
	  }
	  case SYS_WAIT:
	  {
		  check_address((void*)(f->esp+4), f->esp);
		  f->eax = sys_wait((tid_t)*(uint32_t*)(f->esp+4));
		  break;
	  }
	  case SYS_WRITE:
	  {
		  check_address((void*)(f->esp+4), f->esp);
		  check_address((void*)(f->esp+8), f->esp);
		  check_address((void*)(f->esp+12), f->esp);
		  check_buf((void*)*(uint32_t*)(f->esp+8), (unsigned)*((uint32_t*)(f->esp+12)), f->esp, false);
		  lock_acquire(&f_lock);

		  int fd = (int)*(uint32_t*)(f->esp+4);
		  if(fd_positive(fd))
		  {
			  if(fd == 1)
			  {
				  putbuf((void*)*(uint32_t*)(f->esp+8),(unsigned)*((uint32_t*)(f->esp+12)));
				  f->eax = (unsigned)*((uint32_t*)(f->esp+12));
			  }
			  else if(fd>=3)
			  {
				  struct thread* cur = thread_current();
				  if(is_fd_NULL(cur,fd))
				  {
					  lock_release(&f_lock);
					  sys_exit(-1);
				  }
				  f->eax = file_write(cur->file_des[fd],(void*)*(uint32_t*)(f->esp+8),(unsigned)*((uint32_t*)(f->esp+12)));
			  }
			  lock_release(&f_lock);
		  }
		  else
		  {
			  sys_exit(-1);
		  }
		  break;
	  }
	  case SYS_READ:
	  {
		  check_address((void*)(f->esp+4), f->esp);
		  check_address((void*)(f->esp+8), f->esp);
		  check_address((void*)(f->esp+12), f->esp);
		  check_buf((void*)*(uint32_t*)(f->esp+8), (unsigned)*((uint32_t*)(f->esp+12)), f->esp, false);

		  int read_buf=0;
		  int fd = (int)*(uint32_t*)(f->esp+4);
		  void* buf = (void*)*(uint32_t*)(f->esp+8);
			  
		  if(fd_positive(fd))
		  {
			  lock_acquire(&f_lock);
			  if(fd==0)
			  {
				  while(1)
				  {
					  ((char*)(void*)*(uint32_t*)(f->esp+8))[read_buf]=input_getc();

					  if(((char*)(void*)*(uint32_t*)(f->esp+8))[read_buf++] == '\0')
						  break;
				  }
				  f->eax=read_buf;
			  } 
			  else if(fd>=3)
			  {
				  struct thread* cur = thread_current();
				  if(is_fd_NULL(cur,fd))
				  {
					  lock_release(&f_lock);
					  sys_exit(-1);
				  }
				  f->eax = file_read(cur->file_des[fd],(void*)*(uint32_t*)(f->esp+8),(unsigned)*((uint32_t*)(f->esp+12)));
			  }
			  lock_release(&f_lock);
		  }
		  else
		  {
			  sys_exit(-1);
		  }
		  break;
	  }
	  case SYS_FIBO:
			f->eax = fibonacci(*(uint32_t*)(f->esp+4));
			break;
	  case SYS_MAX:
			f->eax=max_of_four_int(*(uint32_t*)(f->esp+4),*(uint32_t*)(f->esp+8),*(uint32_t*)(f->esp+12),*(uint32_t*)(f->esp+16));
			break;
	  case SYS_OPEN:
		    check_address((void*)(f->esp+4), f->esp);
			check_str((const char*)*(uint32_t*)(f->esp+4), f->esp);
			f->eax = sys_open((const char*)*(uint32_t*)(f->esp+4));
			break;
	  case SYS_CREATE:
			check_address((void*)(f->esp+4), f->esp);
			check_address((void*)(f->esp+8), f->esp);
			check_str((const char*)*(uint32_t*)(f->esp+4), f->esp);
			f->eax = sys_create((const char*)*(uint32_t*)(f->esp+4),(unsigned)*(uint32_t*)(f->esp+8));
			break;
	  case SYS_REMOVE:
			check_address((void*)(f->esp+4), f->esp);
			check_str((const char*)*(uint32_t*)(f->esp+4), f->esp);
			f->eax = sys_remove((const char*)*(uint32_t*)(f->esp+4));
			break;
	  case SYS_CLOSE:
			check_address((void*)(f->esp+4), f->esp);
			sys_close((int)*(uint32_t*)(f->esp+4));
			break;
	  case SYS_FILESIZE:
			check_address((void*)(f->esp+4), f->esp);
			f->eax = sys_filesize((int)*(uint32_t*)(f->esp+4));
			break;
	  case SYS_SEEK:
			check_address((void*)(f->esp+4), f->esp);
			check_address((void*)(f->esp+8), f->esp);
			sys_seek((int)*(uint32_t*)(f->esp+4),(unsigned)*(uint32_t*)(f->esp+8));
			break;
	  case SYS_TELL:
			check_address((void*)(f->esp+4), f->esp);
			f->eax = sys_tell((int)*(uint32_t*)(f->esp+4));
			break;
	  default:
		  break;
  }
}

int sys_wait(tid_t pid)
{
	return process_wait(pid);
}

void sys_exit(int status)
{
	struct thread *current = thread_current();
	current->exit_status = status;

	int index=3;

	for(index=3; index<131; index++){
		if(!is_fd_NULL(current,index))
		{
			sys_close(index);
		}
	}
	printf("%s: exit(%d)\n",current->name,status);
	thread_exit();

}

int fibonacci(int n)
{
	int *fibo = (int*)malloc(sizeof(int)*n);
	int ret_fibo;

	fibo[0]=0;
	fibo[1]=1;

	for(int i=2;i<=n;i++)
		fibo[i]=fibo[i-2]+fibo[i-1];

	ret_fibo = fibo[n];

	free(fibo);

	return ret_fibo;
}

int max_of_four_int(int a, int b, int c, int d)
{
	int max = a;
	if(b>max)
		max = b;
	if(c>max)
		max = c;
	if(d>max)
		max = d;

	return max;
}

int sys_open(const char *file_name)
{
  if(file_name==NULL)
	  return -1;

  struct file* f=NULL;
  struct thread* cur=thread_current();

  int fd_cnt=3;
  
  lock_acquire(&f_lock);

  f = filesys_open(file_name);
  if(f==NULL)
  {
	  lock_release(&f_lock);
	  return -1; //file descriptor = -1
  }
  while(fd_cnt<131)
  { 
	  if(is_fd_NULL(cur,fd_cnt))
	  {
		  if(strcmp(cur->name,file_name)==0)
		  {
		  	  file_deny_write(f);
		  }

		  //cur->curfd=fd_cnt;
		  cur->file_des[fd_cnt]=f;
		  thread_current()->next_fd = fd_cnt+1;
		  lock_release(&f_lock);
		  return fd_cnt;
	  }
	  fd_cnt++;
  }
 
  lock_release(&f_lock);
  return -1;
}

bool sys_create (const char *file_name, unsigned size)
{
  if(file_name==NULL)
	  sys_exit(-1);

  lock_acquire(&f_lock);
  bool res = filesys_create(file_name,size);
  lock_release(&f_lock);

  return res;
}

bool sys_remove (const char *file_name)
{
  lock_acquire(&f_lock);
  bool res = filesys_remove(file_name);
  lock_release(&f_lock);
  return res;
}


bool is_fd_NULL(struct thread *t, int check)
{
	if(t->file_des[check]==NULL)
		return true;
	else
		return false;
}

bool fd_positive(int check)
{
	if(check<0)
		return false;
	else
		return true;
}

void sys_close(int fd)
{	
	struct thread* cur = thread_current();
	struct file* temp;

	if(is_fd_NULL(cur,fd))
		sys_exit(-1);

	temp = thread_current()->file_des[fd];
	file_close(temp);
	thread_current()->file_des[fd]=NULL;
}

int sys_filesize(int fd)
{
	struct thread* cur = thread_current();
	if(is_fd_NULL(cur,fd))
		sys_exit(-1);

	return file_length(cur->file_des[fd]);
}

void sys_seek(int fd, unsigned loc)
{
	struct thread* cur = thread_current();
	if(is_fd_NULL(cur,fd))
		sys_exit(-1);

	file_seek(cur->file_des[fd],loc);
}

unsigned sys_tell(int fd)
{
	struct thread* cur = thread_current();
	if(is_fd_NULL(cur,fd))
		sys_exit(-1);
	
	return file_tell(cur->file_des[fd]);
}
