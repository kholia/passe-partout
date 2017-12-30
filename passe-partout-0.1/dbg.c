/* this use /proc/<pid>/maps + ptrace(2) */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifndef DBG_WIN
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>

#if defined(DBG_PTRACE) && !defined(DBG_SOLARIS)
#include <sys/ptrace.h>
#elif defined(DBG_HPUX)
#include <sys/ttrace.h>
#endif

#ifndef _NSIG
#ifndef NSIG
#error "_NSIG and NSIG are not defined !"
#endif
#define _NSIG NSIG
#endif

#if defined(DBG_LINUX)
#define PROC_MAPS_FMT "/proc/%s/maps"
#elif defined(DBG_NETBSD)
#define PROC_MAPS_FMT "/proc/%s/maps"
#define PROC_MAPS_FMT2 "pmap -l -p %s"
#elif defined(DBG_FREEBSD)
#define PROC_MAPS_FMT "/proc/%s/map"
#elif defined(DBG_OPENBSD)
#define PROC_MAPS_FMT "procmap -l -p %s"
#elif defined(DBG_SOLARIS)
#define PROC_MAPS_FMT "/proc/%s/map"
#define PTRACE_PEEKDATA 2
#define PTRACE_ATTACH 9
#define PTRACE_DETACH 7
#include <procfs.h>
#elif defined(DBG_DARWIN)
#include <mach/task_info.h>
#include <mach/host_info.h>
#include <mach/mach_host.h>
#include <mach/shared_region.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

#else /* DBG_WIN */
#include <windows.h>
#endif

#include "dbg.h"

// FIXME
#define MIN_USER_PTR          ((void *) 0x00010000)
#define MAX_USER_PTR          ((void *) 0xc0000000)

int dbg_verbose = 0;

/* parse maps {{{ */
#if !defined(DBG_SOLARIS) && !defined(DBG_DARWIN)
static mapping_t *parse_line(char *str)
{
	char *file, *end;
	mapping_t *map;
	unsigned long from, to;
	int flags;
	size_t len;

	end = strchr(str, '\n');
	if (end)
		*end = 0;

	/* parse mapping name */
	file = strrchr(str, ' ');
	if (!file) {
		fprintf(stderr, "invalid mapping line: %s\n", str);
		return NULL;
	}

	if (!file[1] || !file[2]) {
		*file = 0;
		file = "anonymous";
	} else {
		*file++ = 0;
	}

	len = strlen(file) + 1;
	map = malloc(sizeof(*map) + len);
	if (!map) return NULL;

	/* parse start address */
	end = NULL;
	from = strtoul(str, &end, 16);
	if ((from < 0x1000) || (from & 0xfff) || !end || !end[1]
#if defined(DBG_LINUX) || defined(DBG_NETBSD) || defined(DBG_OPENBSD)
		|| (*end != '-')
#elif defined(DBG_FREEBSD)
		|| (*end != ' ')
#endif
	   ) {
		fprintf(stderr, "invalid mapping start address 0x%lx\n", from);
		return NULL;
	}

	str = end + 1;
	end = NULL;
	to = strtoul(str, &end, 16);
	if ((to < 0x1000) || (to & 0xfff) || (to <= from)
			|| !end || (*end != ' ') || !end[1]) {
		fprintf(stderr, "invalid mapping end address 0x%lx\n", to);
		return NULL;
	}

	str = end + 1;
#ifdef DBG_FREEBSD
	flags = 0;
	while ((*str != ' ') || (flags < 2)) {
		if (*str == ' ')
			++flags;
		++str;
	}
	++str;
#endif
	flags = 0;
	if (str[0] == 'r') flags |= DBGMAP_READ;
	if (str[1] == 'w') flags |= DBGMAP_WRITE;
	if (str[2] == 'x') flags |= DBGMAP_EXEC;
#if defined(DBG_LINUX) || defined(DBG_NETBSD) || defined(DBG_OPENBSD)
	if (str[3] == 's') flags |= DBGMAP_SHARED;
#endif
	printf("=> 0x%lx 0x%lx %s\n", from, to, str);

	map->next    = NULL;
	map->data    = NULL;
	map->address = from;
	map->size    = (unsigned int) (to - from);
	map->flags   = flags;
	map->name    = (const char *) memcpy(map+1, file, len);
	map->proc    = NULL;

	if (dbg_verbose > 2)
		fprintf(stdout, ">\t%24s 0x%lx 0x%x\n", file, map->address, map->size);

	return map;
}
#elif defined(DBG_SOLARIS)
static mapping_t *parse_sunos_map(prmap_t *info)
{
	int flags;
	mapping_t *map;

	map = malloc(sizeof(*map) + PRMAPSZ + 1);
	if (!map) return NULL;

	flags = 0;
	if (info->pr_mflags & MA_READ) flags |= DBGMAP_READ;
	if (info->pr_mflags & MA_WRITE) flags |= DBGMAP_WRITE;
	if (info->pr_mflags & MA_EXEC) flags |= DBGMAP_EXEC;
	if (info->pr_mflags & MA_SHARED) flags |= DBGMAP_SHARED;

	map->next    = NULL;
	map->data    = NULL;
	map->address = info->pr_vaddr;
	map->size    = info->pr_size;
	map->flags   = flags;
	map->name    = (const char *) memcpy(map+1, info->pr_mapname, PRMAPSZ);
	((char *)map->name)[PRMAPSZ] = 0;
	map->proc    = NULL;

	return map;
}
#endif

#if defined(DBG_DARWIN)
static mapping_t * parse_darwin_maps(proc_t *p) {
   mapping_t *head, *prev, *tmp;
   head = NULL;

   kern_return_t res;
   task_t task;
   struct task_basic_info_64 taskinfo;
   mach_msg_type_number_t count;
   mach_vm_size_t size;
   mach_vm_address_t address;
   mach_port_t object_name;

   if ( task_for_pid(current_task(), p->pid, &task) != KERN_SUCCESS ) {
      printf("task_for_pid error\n");
      return NULL;
   }
   count = TASK_BASIC_INFO_64_COUNT;
   res = task_info(task, TASK_BASIC_INFO_64, (task_info_t)&taskinfo, &count);

   if (res != KERN_SUCCESS) {
      return NULL;
   }

   for (address = 0; ; address += size) {
      count = VM_REGION_BASIC_INFO_COUNT_64;

      vm_region_basic_info_data_64_t info;
      res = mach_vm_region(task, &address, &size, VM_REGION_BASIC_INFO,
            (vm_region_info_t)&info, &count, &object_name);

      switch(res) {
         case KERN_SUCCESS:
            tmp = malloc(sizeof(mapping_t));
            if ( tmp == NULL )
               return NULL;
            if ( head )
               prev->next = tmp;
            else
               head = tmp;
            prev = tmp;
            tmp->next    = NULL;
            tmp->address = address;
            tmp->size    = size;
            tmp->flags   = 0; // to be written
            tmp->name    = NULL;
            tmp->proc    = p;
            break;
         case KERN_INVALID_ADDRESS:
            return head;
            break;
         default:
            printf("unknown return value %d\n", res);
      }
      if ( !(info.protection & VM_PROT_READ) ) {
         continue;
      }

      if (info.protection & VM_PROT_READ)    tmp->flags |= DBGMAP_READ;
      if (info.protection & VM_PROT_WRITE)   tmp->flags |= DBGMAP_WRITE;
      if (info.protection & VM_PROT_EXECUTE) tmp->flags |= DBGMAP_EXEC;
      if (info.shared)                       tmp->flags |= DBGMAP_SHARED;

   }
   // we shouldn't reach this
   return NULL;
}
#endif

static int parse_maps(proc_t *p)
{
	mapping_t *head;
#ifndef DBG_DARWIN
	mapping_t *tail, *tmp;
	FILE *fp;
  char path[64];
#endif
#if !defined(DBG_SOLARIS) && !defined(DBG_DARWIN)
	char line[128];
#endif
#ifdef DBG_SOLARIS
	prmap_t sunos_map;
#endif

#ifndef DBG_DARWIN
	snprintf(path, 63, PROC_MAPS_FMT, p->pid_str);
	path[63] = 0;
#endif

#if defined(DBG_DARWIN)
	head = parse_darwin_maps(p);
		if ( !head ) {
				return -1;
		}
#else

#if defined(DBG_OPENBSD)
	fp = popen(path, "r");
	if (!fp) {
	      perror("popen");
		return -1;
	}
#else
	errno = 0;
	fp = fopen(path, "rb");
	if (!fp) {
#if defined(DBG_NETBSD)
		if (errno == ENOENT) {
			// /proc not mounted => try pmap
			snprintf(path, 63, PROC_MAPS_FMT2, p->pid_str);
			path[63] = 0;
			fp = popen(path, "r");
			if (!fp) {
				perror("popen");
				return -1;
			}
		}
#endif
		if (!fp) {
			perror("open");
			return -1;
		}
	}
#endif
	head = NULL;
	tail = NULL;

#if defined(DBG_SOLARIS)
	while (fread(&sunos_map, sizeof(sunos_map), 1, fp)) {
		tmp = parse_sunos_map(&sunos_map);
#else
	while (fgets(line, sizeof(line), fp)) {
		tmp = parse_line(line);
#endif
		if (tmp) {
			tmp->proc = p;
			if (head)
				tail->next = tmp;
			else
				head = tmp;
			tail = tmp;
		}
	}


	fclose(fp);
#endif

	p->maps = head;
	return 0;
}

/* }}} */

/* maps helpers {{{ */

mapping_t *dbg_map_lookup_by_address(
						proc_t *p,
						xaddr_t addr,
						unsigned int *off)
{
	mapping_t *map;

	/* FIXME too slow ... */
	for (map=p->maps; map; map=map->next) {
		if (map->address > addr)
			break;
		if (addr < (map->address + map->size)) {
			if (off)
				*off = addr - map->address;
			return map;
		}
	}

	return NULL;
}

int dbg_maps_lookup(
					proc_t *p,
					int flags,
					const char *name,
					mapping_t ***mappings)
{
	int c;
	mapping_t **maps, *map, **bak;

	*mappings = NULL;

	//fprintf(stderr, "maps_lookup(flags=%i, name=%s)\n",
	//					flags, name ? name : "NULL");

	for (map=p->maps, c=0, maps=NULL; map; map=map->next) {
		//if ((map->flags & flags) != flags)
		//	continue;
		//fprintf(stderr, "%i %i %s\n", map->flags, flags, map->name);
		if (flags && (map->flags != flags))
			continue;
		if (name && !strstr(map->name, name))
			continue;
		if (0) {
		fprintf(stderr, "==> %s %s %s\n", map->name, name,
				strstr(map->name, name) ?
				strstr(map->name, name) : "NULL");
	}

		bak = maps;
		maps = realloc(maps, (c+1)*sizeof(mapping_t *));
		if (!maps) {
			if (bak)
				free(bak);
			return DBGERR_ENOMEM;;
		}
		maps[c] = map;
		++c;
	}

	*mappings = maps;

	return c;
}

mapping_t *dbg_map_lookup(proc_t *p, int flags, const char *name)
{
	int ret;
	mapping_t **maps, *map;

	ret = dbg_maps_lookup(p, flags, name, &maps);
	fprintf(stderr, "retcount: %i\n", ret);
	map = (ret == 1 ? *maps : NULL);

	if (ret > 0)
		free(maps);

	return map;
}


mapping_t *dbg_map_get_stack(proc_t *p)
{
#if defined(DBG_LINUX)
	mapping_t *map;
	map = dbg_map_lookup(p, DBGMAP_READ|DBGMAP_WRITE, "[stack]");
	if (!map)
		map = dbg_map_lookup(p, DBGMAP_READ|DBGMAP_WRITE|DBGMAP_EXEC, "[stack]");
	return map;
#else
	return NULL;
#endif
}

int dbg_map_cache(mapping_t *map)
{
	void *buf;
	int ret;

	if (map->data) // already mapped
		return 1;

	buf = malloc(map->size);
	if (!buf) {
		fprintf(stderr, "error: failed to alloc %u bytes\n", map->size);
		return DBGERR_ENOMEM;;
	}

	ret = dbg_read(map->proc, map->address, buf, map->size);
	if (!ret) {
		map->data = buf;
	} else {
		fprintf(stderr, "error: failed to read %u bytes\n", map->size);
		free(buf);
	}

	return ret;
}

/* }}} */

/* open/close {{{ */

static proc_t *ptraced_proc = NULL;

static void killme(int sig, siginfo_t *si, void *bla)
{
	/*
	const char *signames[33] = {
		"0",
		"SIGHUP",
		"SIGINT",
		"SIGQUIT",
		"SIGILL",
		"SIGTRAP", // 5
		"SIGABRT",
		"SIGBUS",
		"SIGFPE",
		"SIGKILL",
		"SIGUSR1", // 10
		"SIGSEGV",
		"SIGUSR2",
		"SIGPIPE",
		"SIGALRM",
		"SIGTERM", // 15
		"SIGSTKFLT",
		"SIGCHLD",
		"SIGCONT",
		"SIGSTOP",
		"SIGTSTP", // 20
		"SIGTTIN",
		"SIGTTOU",
		"SIGURG",
		"SIGXCPU",
		"SIGXFSZ", // 25
		"SIGVTALRM",
		"SIGPROF",
		"SIGWINCH",
		"SIGIO",
		"SIGPWR", // 30
		"SIGSYS",
	};

	if (sig < 32)
		printf("on_signal(%d - %s) from %u\n", sig, signames[sig], si->si_pid);
	else
		printf("on_signal(%d)\n", sig);
	*/

	if (sig == SIGCHLD) {
		if (dbg_verbose)
			fprintf(stderr, "dbg: attached to process %u\n", si->si_pid);
		return;
	}
	dbg_detach(ptraced_proc);
	ptraced_proc = NULL;
	fprintf(stderr, "killed\n");
	exit(0);
}



int dbg_init(proc_t *p, pid_t pid)
{
	int ret;
	unsigned int i;
	struct sigaction sa;

	if (ptraced_proc)
		return DBGERR_NOT_IMPLEMENTED; /* TODO */

	if (!pid || (pid == getpid()) || (pid == getppid()))
		return DBGERR_BAD_PID;

	memset(p, 0, sizeof(*p));
	p->pid  = pid;
	snprintf(p->pid_str, 8, "%u", pid);
	ptraced_proc = p;

	ret = parse_maps(p);
	if (ret) {
		ptraced_proc = NULL;
		return ret;
	}

	/* catch signals to avoid leaving the child ptraced */
	memset(&sa, 0, sizeof(sa));
	for (i=1; i<_NSIG-1; ++i) { /* FIXME */
		sa.sa_flags     = SA_SIGINFO;
		sa.sa_sigaction = killme;
		switch (i) {
			case SIGKILL:
			case SIGSTOP:
				break;
			default:
				sigaction(i, &sa, NULL);
		}
	}

	return 0;
}

void dbg_exit(proc_t *p)
{
	mapping_t *tmp, *next;

	for (tmp=p->maps; tmp; tmp=next) {
		if (tmp->data)
			free(tmp->data);
		next = tmp->next;
		free(tmp);
	}
	memset(p, 0, sizeof(*p));
}

/* }}} */

/* attach / detach {{{ */

int dbg_attach(proc_t *p, int mode)
{
#ifdef DBG_DARWIN
		// no ptrace needed to dump memory
#elif defined(DBG_SOLARIS)
	char path[64];

	snprintf(path, sizeof(path)-1, "/proc/%s/as", p->pid_str);
	p->mem_fd = open(path, O_RDONLY);
	if (p->mem_fd < 0) {
		perror("open");
		return -1;
	}
#else
	int status;

	if (p->flags & DBGPROC_TRACED)
		return DBGERR_ALREADY_ATTACHED;

	p->flags |= DBGPROC_TRACED;


#if defined(DBG_HPUX)
	if (ttrace(TT_PROC_ATTACH, p->pid, 0, 0, TT_VERSION, 0)) {
#elif defined(DBG_LINUX)
	if (ptrace(PTRACE_ATTACH, p->pid, 0, 0)) {
#elif defined(DBG_FREEBSD) || defined(DBG_NETBSD) || defined(DBG_OPENBSD)
	if (ptrace(PT_ATTACH, p->pid, 0, 0)) {
#elif defined(DBG_MACOSX)
	if (ptrace(PT_ATTACH, p->pid, 0, 0, 0)) {
#elif defined(DBG_SOLARIS)
	printf("toto\n");
	if (ptrace(9, p->pid, 0, 0)) {
#endif
		p->flags &= ~DBGPROC_TRACED;
		if (errno == EPERM)
			return DBGERR_ENOPERM;
#ifndef DBG_HPUX
		perror("ptrace");
#else
		perror("ttrace");
#endif
		return -1;
	}

#ifndef DBG_HPUX
	/* all OS with ptrace interface */

	/* wait ptraced child to stop */
	alarm(5);
	wait(&status);
	alarm(0);

	if (!WIFSTOPPED(status)) {
		dbg_detach(p);
		return DBGERR_TARGET_KILLED;
	}
#endif // DBG_HPUX
#endif
	return 0;
}

void dbg_detach(proc_t *p)
{
	if (p->flags & DBGPROC_TRACED) {
#if defined(DBG_LINUX)
		ptrace(PTRACE_DETACH, p->pid, 0, 0);
#elif defined(DBG_SOLARIS)
		//ptrace(PTRACE_DETACH, p->pid, 1, 0);
		close(p->mem_fd);
		p->mem_fd = -1;
#elif defined(DBG_FREEBSD) || defined(DBG_NETBSD) || defined(DBG_OPENBSD)
		ptrace(PT_DETACH, p->pid, 0, 0);
#elif defined(DBG_HPUX)
		ttrace(TT_PROC_DETACH, pid, 0, 0, 0, 0);
#endif
		p->flags &= ~DBGPROC_TRACED;
		if (dbg_verbose)
			fprintf(stdout, "dbg: detached from process %u\n", p->pid);
	}
}

/* }}} */

/* get/set registers {{{ */
int dbg_get_regs(proc_t *p, void *regs)
{
#if defined(DBG_LINUX)
	return ptrace(PTRACE_GETREGS, p->pid, NULL, regs);
#else
	return DBGERR_NOT_IMPLEMENTED; /* TODO */
#endif
}

int dbg_set_regs(proc_t *p, const void *regs)
{
#if defined(DBG_LINUX)
	return ptrace(PTRACE_SETREGS, p->pid, NULL, regs);
#else
	return DBGERR_NOT_IMPLEMENTED; /* TODO */
#endif
}
/* }}} */

int dbg_continue(proc_t *p)
{
#if defined(DBG_LINUX)
	return ptrace(PTRACE_CONT, p->pid, NULL, NULL);
#else
	return DBGERR_NOT_IMPLEMENTED; /* TODO */
#endif
}

char *dbg_get_binpath(proc_t *p)
{
#if defined(DBG_LINUX)
	ssize_t ret;
	size_t len;
	char *bak, *real_path, path[64];

	snprintf(path, 63, "/proc/%s/exe", p->pid_str);
	path[63] = 0;

	len = 0;
	real_path = NULL;
	do {
		bak = real_path;
		real_path = realloc(real_path, len+256);
		if (!real_path) {
			if (bak)
				free(bak);
			return NULL;
		}
		len += 256;

		ret = readlink(path, real_path, len-1);
		if (ret > 0) {
			real_path[ret] = 0;
			return real_path;
		}
	} while (errno == ENAMETOOLONG);
	return NULL;
#else
	return NULL;
#endif
}

/* read/write mem {{{ */

int dbg_read(proc_t *p, xaddr_t addr, void *buf, unsigned int size)
{
#if defined(DBG_HPUX)
		return ttrace(TTRACE_READ, p->pid, 0, addr, size, buf);
#elif defined(DBG_DARWIN)
		unsigned int tmp = size;

		task_t task;

		if ( task_for_pid(current_task(), p->pid, &task) != KERN_SUCCESS ) {
				printf("task_for_pid error\n");
				return -1;
		}

		kern_return_t res = vm_read_overwrite(task, addr, size, (unsigned long) buf, &tmp);
		switch(res) {
				case KERN_SUCCESS:
						return 0;
				case KERN_PROTECTION_FAILURE:
						fprintf(stderr, "KERN_PROTECTION_FAILURE %p\n", (void *) addr);
						return -1;
				case KERN_INVALID_ADDRESS:
						fprintf(stderr, "KERN_INVALID_ADDRESS %p\n", (void *) addr);
						return -1;
		}
		printf("unknown return value %d @%p\n", res, (void *) addr);
		return -1;
#elif defined(DBG_SOLARIS)
		ssize_t ret;

		if (lseek(p->mem_fd, (off_t)addr, SEEK_SET) != (off_t)addr) {
				perror("lseek");
				return -1;
		}
		ret = read(p->mem_fd, buf, size);
		if (ret < 0)
				return -1;
		return size != (unsigned int) ret;

#elif defined(DBG_WIN)
		DWORD len;

		len = 0;
		if (ReadProcessMemory(p->handle, addr, buf, (DWORD)size, &len))
				return 0;
		return win_to_dbgerr();
#else
		unsigned int i;
		long ret, *out;

		for (i=0, out=(long*)buf; i<size; i+=sizeof(long), ++out) {
				errno = 0;

#if defined(DBG_LINUX) || defined(DBG_SOLARIS)
				ret = ptrace(PTRACE_PEEKDATA, p->pid, addr+i, 1);
#elif defined(DBG_FREEBSD) || defined(DBG_OPENBSD) || defined(DBG_NETBSD)
				ret = ptrace(PT_READ_D, p->pid, (caddr_t)(addr+i), 0);
#elif defined(DBG_MACOSX)
				ret = ptrace(PT_READ_D, p->pid, addr+i, 0, 0);
#endif
				if ((ret == -1) && errno) {
						fprintf(stderr, "error: cannot fetch word @ 0x%lx\n", addr+i);
						if (errno == ESRCH) {
								/* ESRCH also means access denied ! */
								fprintf(stderr,
												"ptrace: access denied or process has terminated\n");
						} else {
								perror("ptrace");
						}
						return -1;
				}
				*out = ret;
		}
		return 0;
#endif
}
/* }}} */

/* read helpers {{{ */
void *dbg_xlate_ptr(proc_t *p, xaddr_t addr)
{
	mapping_t *map;
	unsigned int off;

	map = dbg_map_lookup_by_address(p, addr, &off);
	if (!map)
		return NULL;
	if ((addr < map->address)
			|| (addr > (map->address + map->size - 4))) {
		return NULL;
	}

	return map->data + off;
}

int dbg_read_ptr(proc_t *p, xaddr_t addr, xaddr_t *v)
{
	if (!(p->flags & DBGPROC_TRACED))
		return DBGERR_NOT_ATTACHED;

	/* FIXME : ptr size .. 32/64 */
	return dbg_read(p, addr, v, sizeof(*v));
}

int dbg_get_memory(proc_t *p) {

    mapping_t * map;
    int error = 0;
    dbg_map_for_each(p, map) {

        if (((map->flags & (DBGMAP_READ|DBGMAP_WRITE)) != (DBGMAP_READ|DBGMAP_WRITE))
		|| (map->flags & DBGMAP_SHARED))
            continue;

	if (dbg_map_cache(map)) {
            fprintf(stderr, "error reading %d bytes at %p\n", map->size, (void *)map->address);
	    error = 1;
	}
    }

   return error;
}
/* }}} */

// vim: ts=3 sw=3 fdm=marker
