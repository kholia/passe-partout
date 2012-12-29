#ifndef __DBG_H__
#define __DBG_H__

#ifndef DBG_NO_STDIO
#include <stdio.h>
#endif
#include <sys/types.h>

/*
typedef struct _linux_regs32 {
	u_int32_t ebx, ecx, edx, esi, edi, ebp, eax;
	u_int16_t ds, __ds, es, __es;
	u_int16_t fs, __fs, gs, __gs;
	u_int32_t orig_eax, eip;
	u_int16_t cs, __cs;
	u_int32_t eflags, esp;
	u_int16_t ss, __ss;
} linux_regs32_t;
*/

typedef struct user_regs_struct registers_t;
typedef struct _proc proc_t;

#define DBGMAP_READ   1
#define DBGMAP_WRITE  2
#define DBGMAP_EXEC   4
#define DBGMAP_SHARED 8

typedef struct _mapping {
	struct _mapping *next;
	//char *base;
	unsigned long address;
	unsigned int size;
	int flags;
	const char *name;
	proc_t *proc;
   char * data;
} mapping_t;

#define DBGPROC_TRACED 1

struct _proc {
	pid_t pid;
	int flags;
#ifdef DBG_SOLARIS
	int mem_fd;
#endif
	mapping_t *maps;
	char pid_str[8];
};

typedef unsigned long xaddr_t;

int dbg_init(proc_t *, pid_t);
void dbg_exit(proc_t *);

int dbg_find_stack(proc_t *, xaddr_t *, unsigned int *);
int dbg_find_heap(proc_t *, xaddr_t *, unsigned int *);

#define DBGMODE_READ  0
#define DBGMODE_WRITE 1
#define DBGMODE_EXEC  2

int dbg_attach(proc_t *, int);
void dbg_detach(proc_t *);

int dbg_get_regs(proc_t *, void *);
int dbg_set_regs(proc_t *, const void *);

int dbg_continue(proc_t *);

int dbg_read(proc_t *, xaddr_t, void *, unsigned int);
int dbg_write(proc_t *, xaddr_t, const void *, unsigned int);

int dbg_maps_lookup(proc_t *, int, const char *, mapping_t ***);
mapping_t *dbg_map_lookup(proc_t *, int, const char *);
mapping_t *dbg_map_get_stack(proc_t *);
mapping_t *dbg_map_get_default_heap(proc_t *);
mapping_t *dbg_map_get_bincode(proc_t *);
mapping_t *dbg_map_get_bindata(proc_t *);
mapping_t *dbg_map_get_libcode(proc_t *, const char *);
mapping_t *dbg_map_get_libdata(proc_t *, const char *);
mapping_t *dbg_map_lookup_by_address(proc_t *, xaddr_t, unsigned int *);
int dbg_map_cache(mapping_t *);

#define dbg_map_for_each(proc, map) \
		for (map=(proc)->maps; map; map=map->next)

char *dbg_get_binpath(proc_t *);

void *dbg_xlate_ptr(proc_t *, xaddr_t);

int dbg_read_ptr(proc_t *, xaddr_t, xaddr_t *);

#define DBGSTR_ASCII  0
#define DBGSTR_8BITS  1

char *dbg_read_string(proc_t *, int, xaddr_t);

int dbg_call(proc_t *, xaddr_t, long *, unsigned int, const long *);

xaddr_t dbg_resolve(proc_t *, const char *, const char *);

int dbg_call_lib(proc_t *, const char *, const char *, long *,
						unsigned int, const long *);

int dbg_get_memory(proc_t *p);
void dbg_free_memory(proc_t *p);

/* remote heap helpers ***/
xaddr_t dbg_malloc(proc_t *, unsigned int);
xaddr_t dbg_calloc(proc_t *, unsigned int, unsigned int);
xaddr_t dbg_malloc0(proc_t *, unsigned int);
xaddr_t dbg_memdup(proc_t *, void *, unsigned int);
void dbg_free(proc_t *, xaddr_t);

/* memory pattern lookup */
typedef int (*bmatch_func_t)(xaddr_t, void *, unsigned int, void *);

int dbg_lookup_pattern(mapping_t *, xaddr_t, xaddr_t, const char *,
								bmatch_func_t, void *);

#define DBGPATTERN_UNIQUE 0
#define DBGPATTERN_FIRST  1
#define DBGPATTERN_LAST   2

int dbg_lookup_one_pattern(mapping_t *, xaddr_t, xaddr_t, const char *,
									int, xaddr_t *, void **, unsigned int *);

/* misc helpers ***/
int dbg_read_file(const char *, unsigned int, void **, unsigned int *);

/* errors */
const char *dbg_error(int);
#ifndef DBG_NO_STDIO
void dbg_fprint_err(FILE *, int);
#endif

#define DBGERR_GENERIC 				-1
#define DBGERR_ENOMEM 				-2
#define DBGERR_BAD_PID 				-3
#define DBGERR_ENOPERM				-4
#define DBGERR_ALREADY_ATTACHED	-5
#define DBGERR_TARGET_KILLED		-6
#define DBGERR_NOT_IMPLEMENTED	-7
#define DBGERR_TOO_SMALL	 		-8
#define DBGERR_RECURSIVE	 		-9
#define DBGERR_BAD_PATTERN1 		-10
#define DBGERR_BAD_PATTERN2 		-11
#define DBGERR_BAD_PATTERN3 		-12
#define DBGERR_BAD_PATTERN4 		-13
#define DBGERR_BAD_PATTERN5 		-14
#define DBGERR_BAD_PATTERN6 		-15
#define DBGERR_BAD_PATTERN7 		-16
#define DBGERR_BAD_PATTERN8		-17
#define DBGERR_BAD_PATTERN9		-18
#define DBGERR_BAD_PATTERN10		-19
#define DBGERR_BAD_PATTERN11		-20
#define DBGERR_BAD_PATTERN12		-21
#define DBGERR_NOT_ATTACHED		-22
#define DBGERR_RESOLVE_SYMBOL		-23
#define DBGERR_MAP_NOT_FOUND		-24
#define DBGERR_MAP_TOO_BIG			-25
#define DBGERR_MAP_PTR_END			-26

#endif
// vim: ts=3 sw=3 fdm=marker
