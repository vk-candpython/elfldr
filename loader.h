/*
 * Author   : Vladislav Khudash
 * Source   : https://github.com/vk-candpython/elfldr/blob/main/loader.h
 * Compiler : GCC
 * Platform : Linux x64 (ELF64)
 * Summary  : Core configuration header, custom structures, and basic utilities.
*/


#pragma once


/********************
 *     INCLUDES     *
 ********************/


/* https://github.com/vk-candpython/elfldr/blob/main/lindef.h

INTERNAL LINUX x86_64 DECLARATIONS */
#include "lindef.h"




/*************************************
 *     BUILD-TIME FEATURE CONFIG     *
 *************************************/


#define USING_ANTI_VM           FALSE
#define USING_ANTI_SANDBOX      FALSE
#define USING_ANTI_DEBUG        FALSE
#define USING_ERASE_ELF_HEADERS FALSE




/*********************************
 *     CONSTANT-DECLARATIONS     *
 *********************************/


#define DAT_KEY_SZ sizeof(BYTE)   // Size of key size field (BYTE)
#define DAT_LEN_SZ sizeof(UINT32) // Size of length fields (UINT32)

#define RLE_MAX_RUN 127 // Maximum encoded run length
#define RLE_FLG_RUN 128 // High-bit marker for run blocks


#define BUF_SIZE_1KB 1024 // General-purpose page-aligned buffer size


#if (USING_ANTI_DEBUG)
    /* Enable memory protection trap,
       The first page is reserved as a guard page
       before the mapped image */
    #define PAGE_GUARD_SIZE MAP_PAGE_SIZE
#else
    /* Disable memory protection trap */
    #define PAGE_GUARD_SIZE 0
#endif




/*****************************
 *     ALIASES & HELPERS     *
 *****************************/


/* Const-qualified pointer helper
   (const data and const pointer) */
#define CONST_PTR(TYPE) \
    const TYPE *const

/* Restrict-qualified pointer helper
   (guarantees no memory aliasing) */
#define RESTR_PTR(TYPE) \
    TYPE *restrict



/* Branch prediction hints for compiler optimization */

#define _CONSTANT_P(x) _GCC_FUNC(constant_p)(x)    // Compile‑time constant check
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




/*******************************
 *     ELF-IMAGE UTILITIES     *
 *******************************/


/* Convert RVA to typed pointer */
#define RVA(TYPE, base, addr) \
    ((TYPE)((BYTE*)(base) + (addr)))


/* Safe minimum and maximum value helpers */

#define MIN(a, b) ({         \
    typeof((a)) _a = (a);    \
    typeof((b)) _b = (b);    \
                             \
    (_a < _b)? _a : _b;      \
})

#define MAX(a, b) ({         \
    typeof((a)) _a = (a);    \
    typeof((b)) _b = (b);    \
                             \
    (_a > _b)? _a : _b;      \
})


/* Alignment helpers using a precalculated mask */

#define ALIGN_DOWN(val, msk) ((val) & ~(msk))
#define ALIGN_UP(val, msk)   (((val) + (msk)) & ~(msk))


/* Extract protection index from ELF segment flags */
#define SEGMENT_PROT_IDX(flags) \
    ((BYTE)((flags) & PF_RWX))



/* Compile-time offset calculation for a struct member */
#define OFFSETOF(TYPE, field) \
    _GCC_FUNC(offsetof)(TYPE, field)


/* Copy memory block with compile-time dispatch */
#define MEMCPY(dst, src, sz) do {                                             \
    IF_CONSTANT (sz) {                                                        \
        _GCC_FUNC(memcpy)((VOID*)(dst), (const VOID*)(src), (SIZE_T)(sz));    \
    }                                                                         \
    else {                                                                    \
        DEC_REG(VOID*,       rdi, dst);                                       \
        DEC_REG(const VOID*, rsi, src);                                       \
        DEC_REG(SIZE_T,      rcx, sz );                                       \
                                                                              \
        DEC_ASM ("rep movsb\n\t"                                              \
            : "+D"(rdi), "+S"(rsi), "+c"(rcx)                                 \
            : : "memory"                                                      \
        );                                                                    \
    }                                                                         \
} while (0)

/* Fill memory with zeros with compile-time dispatch */
#define ZEROS(dst, sz) do {                                  \
    IF_CONSTANT (sz) {                                       \
        _GCC_FUNC(memset)((VOID*)(dst), 0, (SIZE_T)(sz));    \
    }                                                        \
    else {                                                   \
        DEC_REG(VOID*,  rdi, dst);                           \
        DEC_REG(SIZE_T, rcx, sz );                           \
        DEC_REG(SIZE_T, rax, 0  );                           \
                                                             \
        DEC_ASM ("rep stosb\n\t"                             \
            : "+D"(rdi), "+c"(rcx)                           \
            : "a"(rax)                                       \
            : "memory"                                       \
        );                                                   \
    }                                                        \
} while (0)




/*******************************
 *     ANTI-VM DEFINITIONS     *
 *******************************/


/* Stack initializer for PCI sysfs path,
   Packed as Little-endian UINT64 (CHAR):
   "/sys/bus/pci/devices/\0" */
#define PCI_INIT_SYS_PATH(pBuf) do {                 \
    volatile UINT64 *_p = (UINT64*)(pBuf);           \
    *_p++ = 0x7375622F7379732FULL; /* /sys/bus */    \
    *_p++ = 0x7665642F6963702FULL; /* /pci/dev */    \
    *_p   = 0x0000002F73656369ULL; /* ices/\0  */    \
} while (0)

/* Length of the PCI sysfs path in bytes
   (including null-terminator
    and padding to UINT64 alignment) */
#define PCI_SYS_PATH_LEN 24


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

#define PCI_VENID_VBOX      ((UINT16)0x80EE) // "80EE"
#define PCI_VENID_VMWARE    ((UINT16)0x15AD) // "15AD"

#define PCI_VENID_QEMU      ((UINT16)0x1AF4) // "1AF4"
#define PCI_VENID_QEMU_BRG  ((UINT16)0x1B36) // "1B36"
#define PCI_VENID_QEMU_VGA  ((UINT16)0x1234) // "1234"

#define PCI_VENID_XEN       ((UINT16)0x5853) // "5853"
#define PCI_VENID_HYPER_V   ((UINT16)0x1414) // "1414"
#define PCI_VENID_PARALLELS ((UINT16)0x1AB8) // "1AB8"




/************************************
 *     ANTI-SANDBOX DEFINITIONS     *
 ************************************/


/* Stack initializer for cgroup procfs path,
   Packed as Little-endian UINT64 (CHAR):
   "/proc/1/cgroup\0" */
#define SANDBOX_INIT_CGROUP_PATH(pBuf) do {          \
    volatile UINT64 *_p = (UINT64*)(pBuf);           \
    *_p++ = 0x2F312F636F72702FULL; /* /proc/1/ */    \
    *_p   = 0x000070756F726763ULL; /* cgroup\0 */    \
} while (0)

/* Length of the cgroup procfs path in bytes
   (including null-terminator
    and padding to UINT64 alignment) */
#define SANDBOX_CGROUP_PATH_LEN 16


/* Little-endian UINT64 representation of "::/init." */
#define SANDBOX_CGROUP_INIT_PREF 0x2E74696E692F3A3AULL



/* Stack initializer for mounts procfs path,
   Packed as Little-endian UINT64 (CHAR):
   "/proc/self/mounts\0" */
#define SANDBOX_INIT_MOUNTS_PATH(pBuf) do {          \
    volatile UINT64 *_p = (UINT64*)(pBuf);           \
    *_p++ = 0x65732F636F72702FULL; /* /proc/se */    \
    *_p++ = 0x746E756F6D2F666CULL; /* lf/mount */    \
    *_p   = 0x0000000000000073ULL; /* s\0      */    \
} while (0)

/* Length of the mounts procfs path in bytes
   (including null-terminator
    and padding to UINT64 alignment) */
#define SANDBOX_MOUNTS_PATH_LEN 24


/* Little-endian UINT32 representation of "/dev" */
#define SANDBOX_MOUNTS_DEV_PREF 0x7665642FU




/**********************************
 *     ANTI-DEBUG DEFINITIONS     *
 **********************************/


/* Stack initializer for status procfs path,
   Packed as Little-endian UINT64 (CHAR):
   "/proc/self/status\0" */
#define DEBUG_INIT_STATUS_PATH(pBuf) do {            \
    volatile UINT64 *_p = (UINT64*)(pBuf);           \
    *_p++ = 0x65732F636F72702FULL; /* /proc/se */    \
    *_p++ = 0x75746174732F666CULL; /* lf/statu */    \
    *_p   = 0x0000000000000073ULL; /* s\0      */    \
} while (0)

/* Length of the status procfs path in bytes
   (including null-terminator
    and padding to UINT64 alignment) */
#define DEBUG_STATUS_PATH_LEN 24


/* Byte offset from "TracerPid" to the value past ':' */
#define DEBUG_STATUS_TRACERPID_OFFSET_SZ 9

/* Little‑endian UINT32 representation of ":\t0\n" */
#define DEBUG_STATUS_TRACERPID_ZERO 0x0A30093AU
