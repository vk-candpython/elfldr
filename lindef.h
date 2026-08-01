/*
 * https://github.com/vk-candpython/elfldr/blob/main/lindef.h
 * lindef.h - Freestanding Linux x86_64 core declarations
 *
 * Standalone header providing:
 *   1. Types
 *   2. Aliases
 *   3. Constants
 *   4. Kernel structures
 *   5. ELF64 declarations
 *   6. System call interfaces
 *
 * Optimized for libc-free development.
 */


#pragma once


/*****************************
 *     TYPE-DECLARATIONS     *
 *****************************/


typedef void                 VOID;

typedef char                 CHAR;
typedef unsigned char        BYTE;

typedef _Bool                BOOLEAN;

typedef __INT8_TYPE__        INT8;
typedef __INT16_TYPE__       INT16;
typedef __INT32_TYPE__       INT32;
typedef __INT64_TYPE__       INT64;

typedef __UINT8_TYPE__       UINT8;
typedef __UINT16_TYPE__      UINT16;
typedef __UINT32_TYPE__      UINT32;
typedef __UINT64_TYPE__      UINT64;

typedef signed   long int    LONG;
typedef unsigned long int    ULONG;

typedef __PTRDIFF_TYPE__     SSIZE_T;
typedef __SIZE_TYPE__        SIZE_T;




/*****************************
 *     ALIASES & HELPERS     *
 *****************************/


/* Signature of the loaded
   executable entry point */
typedef VOID EntryPoint_t(VOID);



/* Compiler attribute wrapper helper */
#define _GCC_ATTR(...) \
    __attribute__((__VA_ARGS__))

/* Compiler builtin shortcut */
#define _GCC_FUNC(name) \
    __builtin_##name



/* Stack buffer alignment helper */
#define DEC_ALIGN_BUF \
    _GCC_ATTR(aligned(XMM_REGISTER_SIZE))


/* Inform compiler that
   this code path is never reached */
#define _UNREACHABLE \
    _GCC_FUNC(unreachable)()



/* Assembly block shorthand */
#define DEC_ASM \
    __asm__ volatile


/* Register declaration helper */
#define DEC_REG(TYPE, reg, val) \
    register TYPE reg __asm__(#reg) = (TYPE)(val)




/*********************************
 *     CONSTANT-DECLARATIONS     *
 *********************************/


/* A null pointer constant */

#define NULL ((VOID*)0)


/* Boolean definitions */

#define FALSE 0
#define TRUE  1


/* Exit status codes */

#define EXIT_CODE_SUCCESS 0
#define EXIT_CODE_ENOEXEC 8
#define EXIT_CODE_ENOMEM  12


/* 128-bit XMM register size in bytes */

#define XMM_REGISTER_SIZE 16


/* Mman protection flags */

#define PROT_NONE            0x0
#define PROT_READ            0x1
#define PROT_WRITE           0x2
#define PROT_EXEC            0x4
#define PROT_READ_WRITE      (PROT_READ|PROT_WRITE)
#define PROT_READ_EXEC       (PROT_READ|PROT_EXEC)
#define PROT_WRITE_EXEC      (PROT_WRITE|PROT_EXEC)
#define PROT_READ_WRITE_EXEC (PROT_READ|PROT_WRITE|PROT_EXEC)


/* Mman mapping flags */

#define MAP_NO_FD     -1
#define MAP_NO_OFFSET 0x00
#define MAP_PRIVATE	  0x02
#define MAP_FIXED	  0x10
#define MAP_ANONYMOUS 0x20
#define MAP_PAGE_SIZE 0x1000


/* Fcntl open flags */

#define AT_FDCWD    -100
#define O_RDONLY    00
#define O_DIRECTORY 0200000


/* System x64 call numbers */

#define SYS_read       0
#define SYS_write      1
#define SYS_openat     257
#define SYS_close      3
#define SYS_mmap       9
#define SYS_mprotect   10
#define SYS_munmap     11
#define SYS_ptrace     101
#define SYS_getdents64 217
#define SYS_exit_group 231


/* Ptrace request number */

#define PTRACE_TRACEME 0




/*****************************************
 *     KERNEL-STRUCTURE-DECLARATIONS     *
 *****************************************/


struct linux_dirent64 {
    UINT64    d_ino;
    INT64     d_off;
    UINT16    d_reclen;
    UINT8     d_type;
    CHAR      d_name[];
};




/****************************
 *     ELF-DECLARATIONS     *
 ****************************/


/*=====TYPES=====*/

typedef UINT16 Elf64_Half;

typedef UINT32 Elf64_Word;
typedef	INT32  Elf64_Sword;

typedef UINT64 Elf64_Xword;
typedef	INT64  Elf64_Sxword;

typedef UINT64 Elf64_Addr;
typedef UINT64 Elf64_Off;


/*=====CONSTANTS=====*/

#define EI_NIDENT 16

#define ET_DYN 3

#define PT_LOAD 1

#define PF_R   (1 << 2)
#define PF_W   (1 << 1)
#define PF_X   (1 << 0)
#define PF_RWX (PF_R|PF_W|PF_X)


/*=====STRUCTURES=====*/

typedef struct {
    Elf64_Addr    min_va;
    Elf64_Addr    max_va;
} Elf64_VA;

typedef struct {
    BYTE          e_ident[EI_NIDENT];
    Elf64_Half    e_type;
    Elf64_Half    e_machine;
    Elf64_Word    e_version;
    Elf64_Addr    e_entry;
    Elf64_Off     e_phoff;
    Elf64_Off     e_shoff;
    Elf64_Word    e_flags;
    Elf64_Half    e_ehsize;
    Elf64_Half    e_phentsize;
    Elf64_Half    e_phnum;
    Elf64_Half    e_shentsize;
    Elf64_Half    e_shnum;
    Elf64_Half    e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    Elf64_Word     p_type;
    Elf64_Word     p_flags;
    Elf64_Off      p_offset;
    Elf64_Addr     p_vaddr;
    Elf64_Addr     p_paddr;
    Elf64_Xword    p_filesz;
    Elf64_Xword    p_memsz;
    Elf64_Xword    p_align;
} Elf64_Phdr;




/************************************
 *     SYSTEM-CALL-DECLARATIONS     *
 ************************************/


#define _SYS_CALL_ENTRY(nm, ...) ({       \
    DEC_REG(LONG, rax, nm);               \
                                          \
    DEC_ASM ("syscall\n\t"                \
        : "+a"(rax)                       \
        : __VA_ARGS__                     \
        : "memory", "cc", "rcx", "r11"    \
    );                                    \
                                          \
    rax;                                  \
})

#define _SYS_CALL_0(nm, ...) \
    _SYS_CALL_ENTRY(nm, ##__VA_ARGS__)


#define _SYS_CALL_1(nm, a1, ...) ({              \
    DEC_REG(LONG, rdi, a1);                      \
    _SYS_CALL_0(nm, "r"(rdi), ##__VA_ARGS__);    \
})

#define _SYS_CALL_2(nm, a1, a2, ...) ({              \
    DEC_REG(LONG, rsi, a2);                          \
    _SYS_CALL_1(nm, a1, "r"(rsi), ##__VA_ARGS__);    \
})

#define _SYS_CALL_3(nm, a1, a2, a3, ...) ({              \
    DEC_REG(LONG, rdx, a3);                              \
    _SYS_CALL_2(nm, a1, a2, "r"(rdx), ##__VA_ARGS__);    \
})

#define _SYS_CALL_4(nm, a1, a2, a3, a4, ...) ({              \
    DEC_REG(LONG, r10, a4);                                  \
    _SYS_CALL_3(nm, a1, a2, a3, "r"(r10), ##__VA_ARGS__);    \
})

#define _SYS_CALL_5(nm, a1, a2, a3, a4, a5, ...) ({             \
    DEC_REG(LONG, r8, a5);                                      \
    _SYS_CALL_4(nm, a1, a2, a3, a4, "r"(r8), ##__VA_ARGS__);    \
})

#define _SYS_CALL_6(nm, a1, a2, a3, a4, a5, a6, ...) ({             \
    DEC_REG(LONG, r9, a6);                                          \
    _SYS_CALL_5(nm, a1, a2, a3, a4, a5, "r"(r9), ##__VA_ARGS__);    \
})


#define _SYSCALL_SELECTOR(_0, _1, _2, _3, _4, _5, _6, N, ...) \
    _SYS_CALL_##N




/**************************************
 *     UNIX-FUNCTION-DECLARATIONS     *
 **************************************/


#define syscall(nm, ...)                           \
    _SYSCALL_SELECTOR(nm, ##__VA_ARGS__,           \
        6, 5, 4, 3, 2, 1, 0)(nm, ##__VA_ARGS__)


#define read(fd, buf, count) \
    syscall(SYS_read, (fd), (buf), (count))


#define write(fd, buf, count) \
    syscall(SYS_write, (fd), (buf), (count))


#define openat(dfd, filename, flags, ...) \
    syscall(SYS_openat, (dfd), (filename), (flags), ##__VA_ARGS__)


#define open(filename, flags, ...) \
    openat(AT_FDCWD, (filename), (flags), ##__VA_ARGS__)


#define close(fd) \
    syscall(SYS_close, (fd))


#define mmap(addr, len, prot, flags, fd, offset) \
    syscall(SYS_mmap, (addr), (len), (prot), (flags), (fd), (offset))


#define mprotect(start, len, prot) \
    syscall(SYS_mprotect, (start), (len), (prot))


#define munmap(addr, len) \
    syscall(SYS_munmap, (addr), (len))


#define ptrace(request, pid, addr, data) \
    syscall(SYS_ptrace, (request), (pid), (addr), (data))


#define getdents64(fd, dirent, count) \
    syscall(SYS_getdents64, (fd), (dirent), (count))


#define _exit_group(status) do {          \
    syscall(SYS_exit_group, (status));    \
    _UNREACHABLE;                         \
} while (0)
