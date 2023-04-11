// Simple command-line kernel monitor useful for
// controlling the kernel and exploring the system interactively.

#include <inc/stdio.h>
#include <inc/string.h>
#include <inc/memlayout.h>
#include <inc/assert.h>
#include <inc/x86.h>

#include <kern/console.h>
#include <kern/monitor.h>
#include <kern/kdebug.h>
#include <kern/trap.h>
#include <kern/pmap.h>

#define CMDBUF_SIZE	80	// enough for one VGA text line


struct Command {
	const char *name;
	const char *desc;
	// return -1 to force monitor to exit
	int (*func)(int argc, char** argv, struct Trapframe* tf);
};

static struct Command commands[] = {
	{ "help", "Display this list of commands", mon_help },
	{ "kerninfo", "Display information about the kernel", mon_kerninfo },
	{ "backtrace", "Display backtrace information", mon_backtrace },
	{ "showpages", "Display pages mapped situation between addr1 and addr2", map_showpages },
	{ "step", "Step the program", mon_step },
	{ "continue", "Continue the program", mon_continue },
};

/***** Implementations of basic kernel monitor commands *****/

int
mon_help(int argc, char **argv, struct Trapframe *tf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(commands); i++)
		cprintf("%s - %s\n", commands[i].name, commands[i].desc);
	return 0;
}

int
mon_kerninfo(int argc, char **argv, struct Trapframe *tf)
{
	extern char _start[], entry[], etext[], edata[], end[];

	cprintf("Special kernel symbols:\n");
	cprintf("  _start                  %08x (phys)\n", _start);
	cprintf("  entry  %08x (virt)  %08x (phys)\n", entry, entry - KERNBASE);
	cprintf("  etext  %08x (virt)  %08x (phys)\n", etext, etext - KERNBASE);
	cprintf("  edata  %08x (virt)  %08x (phys)\n", edata, edata - KERNBASE);
	cprintf("  end    %08x (virt)  %08x (phys)\n", end, end - KERNBASE);
	cprintf("Kernel executable memory footprint: %dKB\n",
		ROUNDUP(end - entry, 1024) / 1024);
	return 0;
}

int map_showpages(int argc, char **argv, struct Trapframe *tf) {
	// 参数检查
	// strat_addr、end_addr 查看起始地址和终止地址之间的页map情况
    if (argc != 3) {
        cprintf("Requir 2 virtual address as arguments.\n");
        return -1;
    }

    char *errChar;
    uintptr_t start_addr = strtol(argv[1], &errChar, 16);
    if (*errChar) {
        cprintf("Invalid virtual address: %s.\n", argv[1]);
        return -1;
    }

    uintptr_t end_addr = strtol(argv[2], &errChar, 16);
    if (*errChar) {
        cprintf("Invalid virtual address: %s.\n", argv[2]);
        return -1;
    }
    if (start_addr > end_addr) {
        cprintf("Address 1 must be lower than address 2\n");
        return -1;
    }
	
	// 按页对齐
    start_addr = ROUNDDOWN(start_addr, PGSIZE);
    end_addr = ROUNDUP(end_addr, PGSIZE);
	uintptr_t cur_addr = start_addr;
	while (cur_addr <= end_addr){
		pte_t *cur_pte = pgdir_walk(kern_pgdir, (void*)cur_addr, 0);
		if (!cur_pte || !(*cur_pte & PTE_P)) cprintf("Virtual address [%08x] - not mapped\n", cur_addr);
		else {
			cprintf( "Virtual address [%08x] - physical address [%08x], permission: ", cur_addr, PTE_ADDR(*cur_pte));
            char perm_PS = (*cur_pte & PTE_PS) ? 'S':'-';
            char perm_W = (*cur_pte & PTE_W) ? 'W':'-';
            char perm_U = (*cur_pte & PTE_U) ? 'U':'-';
            // 进入 else 分支说明 PTE_P 肯定为真了
            cprintf( "-%c----%c%cP\n", perm_PS, perm_U, perm_W);
		}
		cur_addr += PGSIZE;
	}
	return 0;
}

int
mon_backtrace(int argc, char **argv, struct Trapframe *tf)
{
	// Your code here.
	// ebp指针指向的地址中存着的是父函数的ebp指针
    uint32_t ebp, eip, arg;
    struct Eipdebuginfo info;

    cprintf("Stack backtrace:\n");

	// backtrace the ebp chain
    for(ebp = read_ebp(); ebp != 0; ebp = *(uint32_t*)(ebp)) {
        cprintf("  ebp %08x", ebp);
        eip = *((uint32_t*)ebp + 1);
        cprintf("  eip %08x", eip);
        cprintf("  args");
        for(int i = 0; i < 5; ++i) {
            arg = *((uint32_t*)ebp + 2 + i);
            cprintf(" %08x", arg);
        }
        cprintf("\n");

		// get eip info
        debuginfo_eip(eip, &info);
        cprintf("         %s:%d: %.*s+%u\n", 
            info.eip_file, 
            info.eip_line, 
            info.eip_fn_namelen, info.eip_fn_name, 
            eip - info.eip_fn_addr);
    }
	return 0;
}

int mon_continue(int argc, char **argv, struct Trapframe *tf) {
    if (!(tf && (tf->tf_trapno == T_DEBUG || tf->tf_trapno == T_BRKPT) && 
          ((tf->tf_cs & 3) == 3)))
        return 0;
    tf->tf_eflags &= ~FL_TF;
    return -1;
}

int mon_step(int argc, char **argv, struct Trapframe *tf) {
    if (!(tf && (tf->tf_trapno == T_DEBUG || tf->tf_trapno == T_BRKPT) && 
          ((tf->tf_cs & 3) == 3)))
        return 0;
    tf->tf_eflags |= FL_TF;
    return -1;
}


/***** Kernel monitor command interpreter *****/

#define WHITESPACE "\t\r\n "
#define MAXARGS 16

static int
runcmd(char *buf, struct Trapframe *tf)
{
	int argc;
	char *argv[MAXARGS];
	int i;

	// Parse the command buffer into whitespace-separated arguments
	argc = 0;
	argv[argc] = 0;
	while (1) {
		// gobble whitespace
		while (*buf && strchr(WHITESPACE, *buf))
			*buf++ = 0;
		if (*buf == 0)
			break;

		// save and scan past next arg
		if (argc == MAXARGS-1) {
			cprintf("Too many arguments (max %d)\n", MAXARGS);
			return 0;
		}
		argv[argc++] = buf;
		while (*buf && !strchr(WHITESPACE, *buf))
			buf++;
	}
	argv[argc] = 0;

	// Lookup and invoke the command
	if (argc == 0)
		return 0;
	for (i = 0; i < ARRAY_SIZE(commands); i++) {
		if (strcmp(argv[0], commands[i].name) == 0)
			return commands[i].func(argc, argv, tf);
	}
	cprintf("Unknown command '%s'\n", argv[0]);
	return 0;
}

void
monitor(struct Trapframe *tf)
{
	char *buf;

	cprintf("Welcome to the JOS kernel monitor!\n");
	cprintf("Type 'help' for a list of commands.\n");

	if (tf != NULL)
		print_trapframe(tf);
	cprintf("6828 decimal is %o octal!\n", 6828);

	while (1) {
		buf = readline("K> ");
		if (buf != NULL)
			if (runcmd(buf, tf) < 0)
				break;
	}
}
