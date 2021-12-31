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

struct lock f_lock;
static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  lock_init(&f_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
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
	  case SYS_WRITE:
	  {
		  if(!is_user_vaddr(f->esp+4))
			  sys_exit(-1);

		  if(!is_user_vaddr(f->esp+8))
			  sys_exit(-1);

		  if(!is_user_vaddr(f->esp+12))
			  sys_exit(-1);

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
		  if(!is_user_vaddr(f->esp+4))
			  sys_exit(-1);

		  if(!is_user_vaddr(f->esp+8))
			  sys_exit(-1);

		  if(!is_user_vaddr(f->esp+12))
			  sys_exit(-1); 

		  int read_buf=0;
		  int fd = (int)*(uint32_t*)(f->esp+4);
		  void* buf = (void*)*(uint32_t*)(f->esp+8);


		  if(!is_user_vaddr(buf))
			  sys_exit(-1); 
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
			if(!is_user_vaddr(f->esp+4))
				sys_exit(-1);

			f->eax = sys_open((const char*)*(uint32_t*)(f->esp+4));
			break;
	  case SYS_CREATE:
			if(!is_user_vaddr(f->esp+4))
				sys_exit(-1);

			if(!is_user_vaddr(f->esp+8))
				sys_exit(-1);

			f->eax = sys_create((const char*)*(uint32_t*)(f->esp+4),(unsigned)*(uint32_t*)(f->esp+8));
			break;
	  case SYS_REMOVE:
			if(!is_user_vaddr(f->esp+4))
				sys_exit(-1);

			f->eax = sys_remove((const char*)*(uint32_t*)(f->esp+4));
			break;
	  case SYS_CLOSE:
			if(!is_user_vaddr(f->esp+4))
				sys_exit(-1);

			sys_close((int)*(uint32_t*)(f->esp+4));
			break;
	  case SYS_FILESIZE:
			if(!is_user_vaddr(f->esp+4))
				sys_exit(-1);

			f->eax = sys_filesize((int)*(uint32_t*)(f->esp+4));
			break;
	  case SYS_SEEK:
			if(!is_user_vaddr(f->esp+4))
				sys_exit(-1);

			if(!is_user_vaddr(f->esp+8))
				sys_exit(-1);

			sys_seek((int)*(uint32_t*)(f->esp+4),(unsigned)*(uint32_t*)(f->esp+8));
			break;
	  case SYS_TELL:
			if(!is_user_vaddr(f->esp+4))
				sys_exit(-1);

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

		  cur->curfd=fd_cnt;
		  cur->file_des[fd_cnt]=f;
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


