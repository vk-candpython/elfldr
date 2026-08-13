/*
 * Author   : Vladislav Khudash
 * Source   : https://github.com/vk-candpython/elflhr/blob/main/lindef.h
 * Compiler : GCC
 * Platform : Linux x86_64 (ELF64)
 * Summary  : Standalone declarations and basic utilities.
*/


#pragma once


/*************************************
 *     BUILD-TIME FEATURE CONFIG     *
 *************************************/


#define USING_ANTI_VM      FALSE
#define USING_ANTI_SANDBOX FALSE
#define USING_ANTI_DEBUG   FALSE




/*********************************
 *     CONSTANT-DECLARATIONS     *
 *********************************/


#define DAT_KEY_SZ sizeof(BYTE)   // Size of key size field (BYTE)
#define DAT_LEN_SZ sizeof(UINT32) // Size of length fields (UINT32)

#define RLE_MAX_RUN 127 // Maximum encoded run length
#define RLE_FLG_RUN 128 // High-bit marker for run blocks




/*******************************
 *     ANTI-VM DEFINITIONS     *
 *******************************/


/* Stack initializer for HWMON2 sysfs path,
   Packed as Little-endian UINT64 (CHAR):
   "/sys/class/hwmon/hwmon2/name\0" */
#define HWMON2_INIT_SYSFS_PATH(pBuf) do {            \
    volatile UINT64 *_p = (UINT64*)(pBuf);           \
    *_p++ = 0x616C632F7379732FULL; /* /sys/cla */    \
    *_p++ = 0x6E6F6D77682F7373ULL; /* ss/hwmon */    \
    *_p++ = 0x2F326E6F6D77682FULL; /* /hwmon2/ */    \
    *_p   = 0x00000000656D616EULL; /* name\0   */    \
} while (0)

/* Length of the HWMON2 sysfs path in bytes
   (including null-terminator and UINT64 alignment) */
#define HWMON2_SYSFS_PATH_LEN 32



/* Stack initializer for PCI sysfs path,
   Packed as Little-endian UINT64 (CHAR):
   "/sys/bus/pci/devices/\0" */
#define PCI_INIT_SYSFS_PATH(pBuf) do {               \
    volatile UINT64 *_p = (UINT64*)(pBuf);           \
    *_p++ = 0x7375622F7379732FULL; /* /sys/bus */    \
    *_p++ = 0x7665642F6963702FULL; /* /pci/dev */    \
    *_p   = 0x0000002F73656369ULL; /* ices/\0  */    \
} while (0)

/* Length of the PCI sysfs path in bytes
   (including null-terminator and UINT64 alignment) */
#define PCI_SYSFS_PATH_LEN 24


/* Config file name suffix inside PCI device directory,
   Packed as Little-endian UINT64 (CHAR): "/config\0" */
#define PCI_CONFIG_SUFF 0x006769666E6F632FULL


/* PCI device ID length in bytes
   for the "0000:00:00.0" identifier DBDF format */
#define PCI_ID_LEN 12

/* Size of a dirent64 entry holding
   a identifier DBDF format */
#define PCI_ID_ENTRY_SZ \
    (OFFSETOF(struct linux_dirent64, d_name) + (PCI_ID_LEN + 1))

/* Buffer size for getdents64 entries */
#define PCI_BUF_SIZE \
    (16 * PCI_ID_ENTRY_SZ)


/* PCI vendor IDs packed as UINT16 */

#define PCI_VENID_VBOX      ((UINT16)0x80EE) // Oracle Corporation (VirtualBox)
#define PCI_VENID_VMWARE    ((UINT16)0x15AD) // VMware, Inc.

#define PCI_VENID_QEMU      ((UINT16)0x1AF4) // Red Hat (QEMU VirtIO)
#define PCI_VENID_QEMU_BRG  ((UINT16)0x1B36) // Red Hat (QEMU PCI Bridge)
#define PCI_VENID_QEMU_VGA  ((UINT16)0x1234) // QEMU Virtual VGA

#define PCI_VENID_XEN       ((UINT16)0x5853) // XenSource, Inc.
#define PCI_VENID_HYPER_V   ((UINT16)0x1414) // Microsoft Corporation (Hyper-V)
#define PCI_VENID_PARALLELS ((UINT16)0x1AB8) // Parallels International GmbH




/************************************
 *     ANTI-SANDBOX DEFINITIONS     *
 ************************************/


/* Stack initializer for cgroup procfs path,
   Packed as Little-endian UINT64 (CHAR):
   "/proc/1/cgroup\0" */
#define CGROUP1_INIT_PROCFS_PATH(pBuf) do {          \
    volatile UINT64 *_p = (UINT64*)(pBuf);           \
    *_p++ = 0x2F312F636F72702FULL; /* /proc/1/ */    \
    *_p   = 0x000070756F726763ULL; /* cgroup\0 */    \
} while (0)

/* Length of the cgroup procfs path in bytes
   (including null-terminator and UINT64 alignment) */
#define CGROUP1_PROCFS_PATH_LEN 16


/* Little-endian UINT64 representation of "::/init." */
#define CGROUP1_SYSTEMD_PREF 0x2E74696E692F3A3AULL



/* Stack initializer for mounts procfs path,
   Packed as Little-endian UINT64 (CHAR):
   "/proc/self/mounts\0" */
#define MOUNTS_INIT_PROCFS_PATH(pBuf) do {           \
    volatile UINT64 *_p = (UINT64*)(pBuf);           \
    *_p++ = 0x65732F636F72702FULL; /* /proc/se */    \
    *_p++ = 0x746E756F6D2F666CULL; /* lf/mount */    \
    *_p   = 0x0000000000000073ULL; /* s\0      */    \
} while (0)

/* Length of the mounts procfs path in bytes
   (including null-terminator and UINT64 alignment) */
#define MOUNTS_PROCFS_PATH_LEN 24


/* Little-endian UINT32 representation of "/dev" */
#define MOUNTS_DEV_PREF 0x7665642FU




/**********************************
 *     ANTI-DEBUG DEFINITIONS     *
 **********************************/


/* Stack initializer for status procfs path,
   Packed as Little-endian UINT64 (CHAR):
   "/proc/self/status\0" */
#define STATUS_INIT_PROCFS_PATH(pBuf) do {           \
    volatile UINT64 *_p = (UINT64*)(pBuf);           \
    *_p++ = 0x65732F636F72702FULL; /* /proc/se */    \
    *_p++ = 0x75746174732F666CULL; /* lf/statu */    \
    *_p   = 0x0000000000000073ULL; /* s\0      */    \
} while (0)

/* Length of the status procfs path in bytes
   (including null-terminator and UINT64 alignment) */
#define STATUS_PROCFS_PATH_LEN 24


/* Byte offset from "TracerPid" to the value past ':' */
#define STATUS_TRACERPID_OFFSET_SZ 9

/* Little‑endian UINT32 representation of ":\t0\n" */
#define STATUS_ZERO_TRACERPID 0x0A30093AU




/*****************************
 *     TYPE-DECLARATIONS     *
 *****************************/


typedef void                 VOID;

typedef _Bool                BOOLEAN;

typedef char                 CHAR;
typedef unsigned char        BYTE;

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




/*****************************************
 *     GENERAL-CONSTANT-DECLARATIONS     *
 *****************************************/


#define NULL           ((VOID*)0)
#define INVALID_HANDLE ((LONG)-1)


#define XMM_REGISTER_SIZE 16

#define BUF_SIZE_1KB  1024
#define BLK_SIZE_16KB (16 * BUF_SIZE_1KB)


#define FALSE 0
#define TRUE  1

#define EXIT_SUCCESS 0
#define EXIT_FAILURE 1


/* Mman mapping flags */

#define PROT_READ  0x1
#define PROT_WRITE 0x2

#define MAP_PRIVATE	  0x02
#define MAP_ANONYMOUS 0x20

#define MAP_FAILED ((VOID*)-1)


/* Fcntl flags */

#define O_RDONLY    00
#define O_DIRECTORY 0200000

#define AT_FDCWD      -100
#define AT_EMPTY_PATH 0x1000

#define SEEK_SET 0
#define SEEK_CUR 1
#define SEEK_END 2

#define F_ADD_SEALS 1033
#define F_SEALS_ALL 0x3F // F_SEAL_SEAL|F_SEAL_SHRINK|F_SEAL_GROW|F_SEAL_WRITE|F_SEAL_FUTURE_WRITE|F_SEAL_EXEC


/* Memfd open flags */

#define MFD_NAME ""

#define MFD_CLOEXEC       0x0001U
#define MFD_ALLOW_SEALING 0x0002U


/* System x64 call numbers */

#define SYS_read         0
#define SYS_write        1
#define SYS_openat       257
#define SYS_close        3
#define SYS_lseek        8
#define SYS_mmap         9
#define SYS_munmap       11
#define SYS_fcntl        72
#define SYS_getdents64   217
#define SYS_exit_group   231
#define SYS_memfd_create 319
#define SYS_execveat     322


struct linux_dirent64 {
    UINT64    d_ino;
    INT64     d_off;
    UINT16    d_reclen;
    UINT8     d_type;
    CHAR      d_name[];
};




/*****************************
 *     ALIASES & HELPERS     *
 *****************************/


/* Compiler attribute wrapper helper */
#define _GCC_ATTR(...) \
    __attribute__((__VA_ARGS__))

/* Compiler builtin shortcut */
#define _GCC_FUNC(name) \
    __builtin_##name


/* Assembly block shorthand */
#define DEC_ASM \
    __asm__ volatile



/* Stack buffer alignment helper */
#define DEC_ALIGN_BUF \
    _GCC_ATTR(aligned(XMM_REGISTER_SIZE))


/* Register declaration helper */
#define DEC_REG(TYPE, reg, val) \
    register TYPE reg __asm__(#reg) = (TYPE)(val)

/* Const-qualified pointer helper
   (const data and const pointer) */
#define CONST_PTR(TYPE) \
    const TYPE *const

/* Restrict-qualified pointer helper
   (guarantees no memory aliasing) */
#define RESTR_PTR(TYPE) \
    TYPE *restrict



/* Branch prediction hints for compiler optimization */

#define _CONSTANT_P(x) _GCC_FUNC(constant_p)((x))  // Compile‑time constant check
#define _UNLIKELY(x)   _GCC_FUNC(expect)(!!(x), 0) // Cold path
#define _LIKELY(x)     _GCC_FUNC(expect)(!!(x), 1) // Hot path


/* Check for Linux syscall failure */
#define SYS_FAIL(status) \
    _UNLIKELY((LONG)(status) < 0)


/* Optimized branch control macros */

#define IF_CONSTANT(expr)  if (_CONSTANT_P(expr))
#define IF_LIKE(expr)      if (_LIKELY(expr))
#define IF_UNLIKE(expr)    if (_UNLIKELY(expr))
#define IF_SYSFAIL(status) if (SYS_FAIL(status))


/* Optimized loop control macros */

#define WHILE_LIKE(expr) \
    while (_LIKELY(expr))

#define FOR_LIKE(init, cond, post) \
    for (init; _LIKELY(cond); post)



/* Function declaration helper */
#define DEC_FUNC(TYPE) \
    static inline _GCC_ATTR(always_inline) TYPE




/*****************************
 *     GENERAL-UTILITIES     *
 *****************************/


/* Stack initializer for procfs executable path,
   Packed as Little-endian UINT64 (CHAR):
   "/proc/self/exe\0" */
#define EXE_INIT_PROCFS_PATH(pBuf) do {              \
    volatile UINT64 *_p = (UINT64*)(pBuf);           \
    *_p++ = 0x65732F636F72702FULL; /* /proc/se */    \
    *_p   = 0x00006578652F666CULL; /* lf/exe\0 */    \
} while (0)

/* Length of the procfs executable path in bytes
   (including null-terminator and UINT64 alignment) */
#define EXE_PROCFS_PATH_LEN 16



/* Inform compiler that
   this code path is never reached */
#define _UNREACHABLE() \
    _GCC_FUNC(unreachable)()


/* Compile-time offset calculation for a struct member */
#define OFFSETOF(TYPE, field) \
    _GCC_FUNC(offsetof)(TYPE, field)


/* Copy memory block with compile-time dispatch */
#define MEMCPY(dst, src, sz) do {                \
    IF_CONSTANT (sz) _GCC_FUNC(memcpy)(          \
        (VOID*)(dst),                            \
        (const VOID*)(src),                      \
        (SIZE_T)(sz)                             \
    );                                           \
    else {                                       \
        DEC_REG(VOID*,       rdi, (dst));        \
        DEC_REG(const VOID*, rsi, (src));        \
        DEC_REG(SIZE_T,      rcx, (sz) );        \
                                                 \
        DEC_ASM ("rep movsb\n\t"                 \
            : "+D"(rdi), "+S"(rsi), "+c"(rcx)    \
            : : "memory"                         \
        );                                       \
    }                                            \
} while (0)




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


#define _SYS_CALL_SELECTOR(_0, _1, _2, _3, _4, _5, _6, N, ...) \
    _SYS_CALL_##N




/**************************************
 *     UNIX-FUNCTION-DECLARATIONS     *
 **************************************/


#define syscall(nm, ...)                           \
    _SYS_CALL_SELECTOR(nm, ##__VA_ARGS__,          \
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

#define lseek(fd, offset, whence) \
    syscall(SYS_lseek, (fd), (offset), (whence))

#define mmap(addr, len, prot, flags, fd, offset) \
    syscall(SYS_mmap, (addr), (len), (prot), (flags), (fd), (offset))

#define munmap(addr, len) \
    syscall(SYS_munmap, (addr), (len))

#define fcntl(fd, cmd, arg) \
    syscall(SYS_fcntl, (fd), (cmd), (arg))

#define getdents64(fd, dirent, count) \
    syscall(SYS_getdents64, (fd), (dirent), (count))

#define exit_group(status) do {           \
    syscall(SYS_exit_group, (status));    \
    _UNREACHABLE();                       \
} while (0)

#define memfd_create(uname_ptr, flags) \
    syscall(SYS_memfd_create, (uname_ptr), (flags))

#define execveat(dfd, filename, argv, envp, flags) \
    syscall(SYS_execveat, (dfd), (filename), (argv), (envp), (flags))
