#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <stdlib.h>

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
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
	  case SYS_READ:
	  {
		  
		  if(!is_user_vaddr(f->esp+4))
			  sys_exit(-1);

		  int read_buf=0;
		  if(((int)*(uint32_t*)(f->esp+4))==0){
			  while(1){
				  ((char*)(void*)*(uint32_t*)(f->esp+8))[read_buf]=input_getc();

				  if(((char*)(void*)*(uint32_t*)(f->esp+8))[read_buf++] == '\0')
					 break;
			  }
		  }
		  f->eax=read_buf;
		  break;
	  }
	  case SYS_WRITE:
	  {
		  
		  if(!is_user_vaddr(f->esp+4))
			  sys_exit(-1);

		  if((int)*(uint32_t*)(f->esp+4) == 1){
			  putbuf((void*)*(uint32_t*)(f->esp+8),(unsigned)*((uint32_t*)(f->esp+12)));
			  f->eax = (unsigned)*((uint32_t*)(f->esp+12));
		  }
		  else
			  sys_exit(-1);

		  break;
	  }
	  case SYS_FIBO:
			f->eax = fibonacci(*(uint32_t*)(f->esp+4));
			break;
	  case SYS_MAX:
			f->eax=max_of_four_int(*(uint32_t*)(f->esp+4),*(uint32_t*)(f->esp+8),*(uint32_t*)(f->esp+12),*(uint32_t*)(f->esp+16));
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
