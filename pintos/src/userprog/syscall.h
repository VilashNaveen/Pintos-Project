/*
Refactored code with added comments

This header file defines the necessary variables, structures and functions
required for system calls in the userprog module.
*/

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

// Include necessary libraries
#include "threads/synch.h"
#include "threads/thread.h"


// Define error macros
#define SYS_ERROR -1
#define NOT_LOADED 0
#define LOAD_FAILED 2
#define LOADED 1
#define ALL_FDESC_CLOSE -1
#define USER_VADDR_BOTTOM ((void*) 0x08048000)

// Global lock for file system
struct lock fs_lock;

// Structure to store the process file information
struct process_file {
  struct file *file;
  int fd;
  struct list_elem elem;
};

// Structure to store the child process information
struct child_process {
  int pid, load_status, wait, exit, status;
  struct semaphore load_semaphore, exit_sema;
  struct list_elem elem;
};

// Initialize the syscall module
void syscall_init (void);

#endif /* userprog/syscall.h */