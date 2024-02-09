#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"

#define MAXIMUM_ARGS_COUNT 3
#define STD_INPUT 0
#define STD_OUTPUT 1

// decleration
int get_page(const void *vaddr);
void children_remove(void);
struct file *get_file(int filedes);
struct child_process *find_child(int pid);

int add_file(struct file *file_name);
bool create(const char *file_name, unsigned starting_size);
bool remove(const char *file_name);
int open(const char *file_name);
int read(int filedes, void *buffer, unsigned length);
int write(int filedes, const void *buffer, unsigned byte_size);
void seek(int filedes, unsigned new_position);
void pointer_validator(const void *vaddr);
void buffer_validator(const void *buf, unsigned byte_size);
void string_validator(const void *str);

void close_file(int file_descriptor);
void exit(int status);
static void syscall_handler(struct intr_frame *);
void stack_access(struct intr_frame *f, int *arg, int num_of_args);
bool IS_FILE_LOCKED = false;

void syscall_init(void){
    intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler(struct intr_frame *f UNUSED)
{
  if (!IS_FILE_LOCKED)
  {
    lock_init(&fs_lock);
    IS_FILE_LOCKED = true;
  }
  int arg[MAXIMUM_ARGS_COUNT];
  int esp = get_page((const void *)f->esp);

  int syscall_num = *(int *)esp;

  switch (syscall_num)
  {

  case SYS_READ:
    stack_access(f, &arg[0], 3);
    buffer_validator((const void *)arg[1], (unsigned)arg[2]);
    arg[1] = get_page((const void *)arg[1]);
    f->eax = read(arg[0], (void *)arg[1], (unsigned)arg[2]);
    break;

  case SYS_WRITE:
    stack_access(f, &arg[0], 3);
    buffer_validator((const void *)arg[1], (unsigned)arg[2]);
    arg[1] = get_page((const void *)arg[1]);
    f->eax = write(arg[0], (const void *)arg[1], (unsigned)arg[2]);
    break;



  case SYS_CREATE:

    stack_access(f, &arg[0], 2);
    string_validator((const void *)arg[0]);
    arg[0] = get_page((const void *)arg[0]);
    f->eax = create((const char *)arg[0], (unsigned)arg[1]);
    break;

  case SYS_REMOVE:
    stack_access(f, &arg[0], 1);
    string_validator((const void *)arg[0]);
    arg[0] = get_page((const void *)arg[0]);
    f->eax = remove((const char *)arg[0]);
    break;

  case SYS_SEEK:
    stack_access(f, &arg[0], 2);
    seek(arg[0], (unsigned)arg[1]);
    break;

  case SYS_OPEN:
    stack_access(f, &arg[0], 1);
    string_validator((const void *)arg[0]);
    arg[0] = get_page((const void *)arg[0]);
    f->eax = open((const char *)arg[0]);
    break;

  case SYS_CLOSE:
    stack_access(f, &arg[0], 1);
    lock_acquire(&fs_lock);
    close_file(arg[0]);
    lock_release(&fs_lock);
    break;

  case SYS_EXIT:
    stack_access(f, &arg[0], 1);
    exit(arg[0]);
    break;

  default:
    break;
  }
}

void stack_access(struct intr_frame *f, int *args, int num_of_args)
{
  int *ptr;
  for (int i = 0; i < num_of_args; i++)
  {
    ptr = (int *)f->esp + i + 1;
    pointer_validator((const void *)ptr);
    args[i] = *ptr;
  }
}

void exit(int status)
{
  // Get the current thread
  struct thread *curr_thread = thread_current();
  if (check_thread_active(curr_thread->parent) && curr_thread->child_process)
  {
    if (status < 0)
      status = -1;
    curr_thread->child_process->status = status;
  }
  printf("%s: exit(%d)\n", curr_thread->name, status);
  thread_exit();
}

bool create(const char *file_name, unsigned initial_size)
{
  lock_acquire(&fs_lock);
  bool success = filesys_create(file_name, initial_size);
  lock_release(&fs_lock);
  return success;
}

bool remove(const char *file_name)
{
  lock_acquire(&fs_lock);
  bool success = filesys_remove(file_name);
  lock_release(&fs_lock);
  return success;
}

int open(const char *file_name)
{
  lock_acquire(&fs_lock);
  struct file *file_ptr = filesys_open(file_name);
  if (!file_ptr)
  {
    lock_release(&fs_lock);
    return SYS_ERROR;
  }
  int file_des = add_file(file_ptr);
  lock_release(&fs_lock);
  return file_des;
}

int add_file(struct file *file_ptr)
{
  struct process_file *file_struct = malloc(sizeof(struct process_file));
  if (!file_struct)
    return SYS_ERROR;

  file_struct->file = file_ptr;
  file_struct->fd = thread_current()->fd;
  thread_current()->fd++;
  list_push_back(&thread_current()->file_name_list, &file_struct->elem);
  return file_struct->fd;
}

int read(int filedes, void *buffer, unsigned length)
{
  if (length <= 0)
    return 0;

  if (filedes == STD_INPUT)
  {
    uint8_t *buf = (uint8_t *)buffer;
    for (unsigned i = 0; i < length; i++)
      buf[i] = input_getc();

    return length;
  }

  // Acquire lock to access file system
  lock_acquire(&fs_lock);

  // Get file pointer using filedes
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    lock_release(&fs_lock);
    return SYS_ERROR;
  }

  // Read data from the file
  int size = file_read(file_ptr, buffer, length);

  // Release lock and return the number of bytes read
  lock_release(&fs_lock);
  return size;
}

// write function implementation
int write(int filedes, const void *buffer, unsigned byte_size)
{
  // Return 0 if byte_size is 0 or negative
  if (byte_size <= 0)
    return 0;

  // Write to standard output if filedes is STD_OUTPUT
  if (filedes == STD_OUTPUT)
  {
    putbuf(buffer, byte_size);
    return byte_size;
  }

  lock_acquire(&fs_lock);
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    lock_release(&fs_lock);
    return SYS_ERROR;
  }

  // Write data to the file
  int size = file_write(file_ptr, buffer, byte_size);
  lock_release(&fs_lock);
  return size;
}

struct file *
get_file(int filedes)
{
  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->file_name_list);

  // Iterate over the list of process files
  for (; e != list_end(&t->file_name_list); e = next)
  {
    next = list_next(e);
    struct process_file *ptr_processing_file = list_entry(e, struct process_file, elem);
    if (filedes == ptr_processing_file->fd)
      return ptr_processing_file->file;
  }

  // Return NULL if file not found
  return NULL;
}

/* function to change the position of the file pointer */
void seek(int filedes, unsigned new_position)
{
  lock_acquire(&fs_lock);
  struct file *file_ptr = get_file(filedes);
  if (!file_ptr)
  {
    lock_release(&fs_lock);
    return;
  }
  file_seek(file_ptr, new_position);
  lock_release(&fs_lock);
}

void pointer_validator(const void *vaddr)
{
  if (vaddr < USER_VADDR_BOTTOM || !is_user_vaddr(vaddr))
  {
    exit(SYS_ERROR);
  }
}
void string_validator(const void *str)
{
  for (; *(char *)get_page(str) != 0; str = (char *)str + 1)
  {
    /*Empty body */
  }
}

void buffer_validator(const void *buf, unsigned byte_size)
{
  unsigned i = 0;
  char *local_buffer = (char *)buf;
  for (; i < byte_size; i++)
  {
    pointer_validator((const void *)local_buffer);
    local_buffer++;
  }
}

int get_page(const void *vaddr)
{
  void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
  if (!ptr)
  {
    exit(SYS_ERROR);
  }
  return (int)ptr;
}

/* Find a child process with given PID */
struct child_process *find_child(int pid)
{
  struct thread *t = thread_current();
  struct list_elem *e, *next;

  /* Iterate through the child process list */
  for (e = list_begin(&t->child_process_list); e != list_end(&t->child_process_list); e = next)
  {
    next = list_next(e);
    struct child_process *child_process = list_entry(e, struct child_process, elem);
    if (pid == child_process->pid)
    {
      return child_process;
    }
  }

  /* If not found, return NULL */
  return NULL;
}

/* Remove all child processes */
void children_remove(void)
{
  struct thread *t = thread_current();
  struct list_elem *e, *next;
  for (e = list_begin(&t->child_process_list); e != list_end(&t->child_process_list); e = next)
  {
    next = list_next(e);
    struct child_process *child_process = list_entry(e, struct child_process, elem);
    list_remove(&child_process->elem);
    free(child_process);
  }
}

// Function to close a file given a file descriptor
void close_file(int file_descriptor)
{
  // Get the current thread
  struct thread *t = thread_current();
  struct list_elem *next;
  struct list_elem *e = list_begin(&t->file_name_list);

  for (; e != list_end(&t->file_name_list); e = next)
  {
    next = list_next(e);
    struct process_file *ptr_processing_file = list_entry(e, struct process_file, elem);
    if (file_descriptor == ptr_processing_file->fd || file_descriptor == ALL_FDESC_CLOSE)
    {
      file_close(ptr_processing_file->file);
      list_remove(&ptr_processing_file->elem);
      free(ptr_processing_file);
      if (file_descriptor != ALL_FDESC_CLOSE)
        return;
    }

  }
}
