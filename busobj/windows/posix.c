/* This file contains functions which implement those POSIX and Linux functions
 * that MinGW and Microsoft don't provide. The implementations contain just enough
 * functionality to support fio.
 */

#if defined(WIN32) || defined(WIN64)

#include <arpa/inet.h>
#include <netinet/in.h>
#include <windows.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
//#include <pthread.h>
#include <time.h>
#include <semaphore.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/resource.h>
#include <poll.h>
#include <sys/wait.h>
#include <setjmp.h>
#include <io.h>
#include <stdbool.h>
#include <stdio.h>

#include "win_clock_gettime.h"

#define log_err printf

//#include "../os-windows.h"
//#include "../../lib/hweight.h"

/* Values for the argument to `sysconf'.  */
enum
{
	_SC_ARG_MAX,
#define        _SC_ARG_MAX                        _SC_ARG_MAX
	_SC_CHILD_MAX,
#define        _SC_CHILD_MAX                        _SC_CHILD_MAX
	_SC_CLK_TCK,
#define        _SC_CLK_TCK                        _SC_CLK_TCK
	_SC_NGROUPS_MAX,
#define        _SC_NGROUPS_MAX                        _SC_NGROUPS_MAX
	_SC_OPEN_MAX,
#define        _SC_OPEN_MAX                        _SC_OPEN_MAX
	_SC_STREAM_MAX,
#define        _SC_STREAM_MAX                        _SC_STREAM_MAX
	_SC_TZNAME_MAX,
#define        _SC_TZNAME_MAX                        _SC_TZNAME_MAX
	_SC_JOB_CONTROL,
#define        _SC_JOB_CONTROL                        _SC_JOB_CONTROL
	_SC_SAVED_IDS,
#define        _SC_SAVED_IDS                        _SC_SAVED_IDS
	_SC_REALTIME_SIGNALS,
#define        _SC_REALTIME_SIGNALS                _SC_REALTIME_SIGNALS
	_SC_PRIORITY_SCHEDULING,
#define        _SC_PRIORITY_SCHEDULING                _SC_PRIORITY_SCHEDULING
	_SC_TIMERS,
#define        _SC_TIMERS                        _SC_TIMERS
	_SC_ASYNCHRONOUS_IO,
#define        _SC_ASYNCHRONOUS_IO                _SC_ASYNCHRONOUS_IO
	_SC_PRIORITIZED_IO,
#define        _SC_PRIORITIZED_IO                _SC_PRIORITIZED_IO
	_SC_SYNCHRONIZED_IO,
#define        _SC_SYNCHRONIZED_IO                _SC_SYNCHRONIZED_IO
	_SC_FSYNC,
#define        _SC_FSYNC                        _SC_FSYNC
	_SC_MAPPED_FILES,
#define        _SC_MAPPED_FILES                _SC_MAPPED_FILES
	_SC_MEMLOCK,
#define        _SC_MEMLOCK                        _SC_MEMLOCK
	_SC_MEMLOCK_RANGE,
#define        _SC_MEMLOCK_RANGE                _SC_MEMLOCK_RANGE
	_SC_MEMORY_PROTECTION,
#define        _SC_MEMORY_PROTECTION                _SC_MEMORY_PROTECTION
	_SC_MESSAGE_PASSING,
#define        _SC_MESSAGE_PASSING                _SC_MESSAGE_PASSING
	_SC_SEMAPHORES,
#define        _SC_SEMAPHORES                        _SC_SEMAPHORES
	_SC_SHARED_MEMORY_OBJECTS,
#define        _SC_SHARED_MEMORY_OBJECTS        _SC_SHARED_MEMORY_OBJECTS
	_SC_AIO_LISTIO_MAX,
#define        _SC_AIO_LISTIO_MAX                _SC_AIO_LISTIO_MAX
	_SC_AIO_MAX,
#define        _SC_AIO_MAX                        _SC_AIO_MAX
	_SC_AIO_PRIO_DELTA_MAX,
#define        _SC_AIO_PRIO_DELTA_MAX                _SC_AIO_PRIO_DELTA_MAX
	_SC_DELAYTIMER_MAX,
#define        _SC_DELAYTIMER_MAX                _SC_DELAYTIMER_MAX
	_SC_MQ_OPEN_MAX,
#define        _SC_MQ_OPEN_MAX                        _SC_MQ_OPEN_MAX
	_SC_MQ_PRIO_MAX,
#define        _SC_MQ_PRIO_MAX                        _SC_MQ_PRIO_MAX
	_SC_VERSION,
#define        _SC_VERSION                        _SC_VERSION
	_SC_PAGESIZE,
#define        _SC_PAGESIZE                        _SC_PAGESIZE
#define        _SC_PAGE_SIZE                        _SC_PAGESIZE
	_SC_RTSIG_MAX,
#define        _SC_RTSIG_MAX                        _SC_RTSIG_MAX
	_SC_SEM_NSEMS_MAX,
#define        _SC_SEM_NSEMS_MAX                _SC_SEM_NSEMS_MAX
	_SC_SEM_VALUE_MAX,
#define        _SC_SEM_VALUE_MAX                _SC_SEM_VALUE_MAX
	_SC_SIGQUEUE_MAX,
#define        _SC_SIGQUEUE_MAX                _SC_SIGQUEUE_MAX
	_SC_TIMER_MAX,
#define        _SC_TIMER_MAX                        _SC_TIMER_MAX

	/* Values for the argument to `sysconf'
	   corresponding to _POSIX2_* symbols.  */
	   _SC_BC_BASE_MAX,
#define        _SC_BC_BASE_MAX                        _SC_BC_BASE_MAX
	   _SC_BC_DIM_MAX,
#define        _SC_BC_DIM_MAX                        _SC_BC_DIM_MAX
	   _SC_BC_SCALE_MAX,
#define        _SC_BC_SCALE_MAX                _SC_BC_SCALE_MAX
	   _SC_BC_STRING_MAX,
#define        _SC_BC_STRING_MAX                _SC_BC_STRING_MAX
	   _SC_COLL_WEIGHTS_MAX,
#define        _SC_COLL_WEIGHTS_MAX                _SC_COLL_WEIGHTS_MAX
	   _SC_EQUIV_CLASS_MAX,
#define        _SC_EQUIV_CLASS_MAX                _SC_EQUIV_CLASS_MAX
	   _SC_EXPR_NEST_MAX,
#define        _SC_EXPR_NEST_MAX                _SC_EXPR_NEST_MAX
	   _SC_LINE_MAX,
#define        _SC_LINE_MAX                        _SC_LINE_MAX
	   _SC_RE_DUP_MAX,
#define        _SC_RE_DUP_MAX                        _SC_RE_DUP_MAX
	   _SC_CHARCLASS_NAME_MAX,
#define        _SC_CHARCLASS_NAME_MAX                _SC_CHARCLASS_NAME_MAX

	   _SC_2_VERSION,
#define        _SC_2_VERSION                        _SC_2_VERSION
	   _SC_2_C_BIND,
#define        _SC_2_C_BIND                        _SC_2_C_BIND
	   _SC_2_C_DEV,
#define        _SC_2_C_DEV                        _SC_2_C_DEV
	   _SC_2_FORT_DEV,
#define        _SC_2_FORT_DEV                        _SC_2_FORT_DEV
	   _SC_2_FORT_RUN,
#define        _SC_2_FORT_RUN                        _SC_2_FORT_RUN
	   _SC_2_SW_DEV,
#define        _SC_2_SW_DEV                        _SC_2_SW_DEV
	   _SC_2_LOCALEDEF,
#define        _SC_2_LOCALEDEF                        _SC_2_LOCALEDEF

	   _SC_PII,
#define        _SC_PII                                _SC_PII
	   _SC_PII_XTI,
#define        _SC_PII_XTI                        _SC_PII_XTI
	   _SC_PII_SOCKET,
#define        _SC_PII_SOCKET                        _SC_PII_SOCKET
	   _SC_PII_INTERNET,
#define        _SC_PII_INTERNET                _SC_PII_INTERNET
	   _SC_PII_OSI,
#define        _SC_PII_OSI                        _SC_PII_OSI
	   _SC_POLL,
#define        _SC_POLL                        _SC_POLL
	   _SC_SELECT,
#define        _SC_SELECT                        _SC_SELECT
	   _SC_UIO_MAXIOV,
#define        _SC_UIO_MAXIOV                        _SC_UIO_MAXIOV
	   _SC_IOV_MAX = _SC_UIO_MAXIOV,
#define _SC_IOV_MAX                        _SC_IOV_MAX
	   _SC_PII_INTERNET_STREAM,
#define        _SC_PII_INTERNET_STREAM                _SC_PII_INTERNET_STREAM
	   _SC_PII_INTERNET_DGRAM,
#define        _SC_PII_INTERNET_DGRAM                _SC_PII_INTERNET_DGRAM
	   _SC_PII_OSI_COTS,
#define        _SC_PII_OSI_COTS                _SC_PII_OSI_COTS
	   _SC_PII_OSI_CLTS,
#define        _SC_PII_OSI_CLTS                _SC_PII_OSI_CLTS
	   _SC_PII_OSI_M,
#define        _SC_PII_OSI_M                        _SC_PII_OSI_M
	   _SC_T_IOV_MAX,
#define        _SC_T_IOV_MAX                        _SC_T_IOV_MAX

	   /* Values according to POSIX 1003.1c (POSIX threads).  */
	   _SC_THREADS,
#define        _SC_THREADS                        _SC_THREADS
	   _SC_THREAD_SAFE_FUNCTIONS,
#define _SC_THREAD_SAFE_FUNCTIONS        _SC_THREAD_SAFE_FUNCTIONS
	   _SC_GETGR_R_SIZE_MAX,
#define        _SC_GETGR_R_SIZE_MAX                _SC_GETGR_R_SIZE_MAX
	   _SC_GETPW_R_SIZE_MAX,
#define        _SC_GETPW_R_SIZE_MAX                _SC_GETPW_R_SIZE_MAX
	   _SC_LOGIN_NAME_MAX,
#define        _SC_LOGIN_NAME_MAX                _SC_LOGIN_NAME_MAX
	   _SC_TTY_NAME_MAX,
#define        _SC_TTY_NAME_MAX                _SC_TTY_NAME_MAX
	   _SC_THREAD_DESTRUCTOR_ITERATIONS,
#define        _SC_THREAD_DESTRUCTOR_ITERATIONS _SC_THREAD_DESTRUCTOR_ITERATIONS
	   _SC_THREAD_KEYS_MAX,
#define        _SC_THREAD_KEYS_MAX                _SC_THREAD_KEYS_MAX
	   _SC_THREAD_STACK_MIN,
#define        _SC_THREAD_STACK_MIN                _SC_THREAD_STACK_MIN
	   _SC_THREAD_THREADS_MAX,
#define        _SC_THREAD_THREADS_MAX                _SC_THREAD_THREADS_MAX
	   _SC_THREAD_ATTR_STACKADDR,
#define        _SC_THREAD_ATTR_STACKADDR        _SC_THREAD_ATTR_STACKADDR
	   _SC_THREAD_ATTR_STACKSIZE,
#define        _SC_THREAD_ATTR_STACKSIZE        _SC_THREAD_ATTR_STACKSIZE
	   _SC_THREAD_PRIORITY_SCHEDULING,
#define        _SC_THREAD_PRIORITY_SCHEDULING        _SC_THREAD_PRIORITY_SCHEDULING
	   _SC_THREAD_PRIO_INHERIT,
#define        _SC_THREAD_PRIO_INHERIT                _SC_THREAD_PRIO_INHERIT
	   _SC_THREAD_PRIO_PROTECT,
#define        _SC_THREAD_PRIO_PROTECT                _SC_THREAD_PRIO_PROTECT
	   _SC_THREAD_PROCESS_SHARED,
#define        _SC_THREAD_PROCESS_SHARED        _SC_THREAD_PROCESS_SHARED

	   _SC_NPROCESSORS_CONF,
#define _SC_NPROCESSORS_CONF                _SC_NPROCESSORS_CONF
	   _SC_NPROCESSORS_ONLN,
#define _SC_NPROCESSORS_ONLN                _SC_NPROCESSORS_ONLN
	   _SC_PHYS_PAGES,
#define _SC_PHYS_PAGES                        _SC_PHYS_PAGES
	   _SC_AVPHYS_PAGES,
#define _SC_AVPHYS_PAGES                _SC_AVPHYS_PAGES
	   _SC_ATEXIT_MAX,
#define _SC_ATEXIT_MAX                        _SC_ATEXIT_MAX
	   _SC_PASS_MAX,
#define _SC_PASS_MAX                        _SC_PASS_MAX

	   _SC_XOPEN_VERSION,
#define _SC_XOPEN_VERSION                _SC_XOPEN_VERSION
	   _SC_XOPEN_XCU_VERSION,
#define _SC_XOPEN_XCU_VERSION                _SC_XOPEN_XCU_VERSION
	   _SC_XOPEN_UNIX,
#define _SC_XOPEN_UNIX                        _SC_XOPEN_UNIX
	   _SC_XOPEN_CRYPT,
#define _SC_XOPEN_CRYPT                        _SC_XOPEN_CRYPT
	   _SC_XOPEN_ENH_I18N,
#define _SC_XOPEN_ENH_I18N                _SC_XOPEN_ENH_I18N
	   _SC_XOPEN_SHM,
#define _SC_XOPEN_SHM                        _SC_XOPEN_SHM

	   _SC_2_CHAR_TERM,
#define _SC_2_CHAR_TERM                        _SC_2_CHAR_TERM
	   _SC_2_C_VERSION,
#define _SC_2_C_VERSION                        _SC_2_C_VERSION
	   _SC_2_UPE,
#define _SC_2_UPE                        _SC_2_UPE

	   _SC_XOPEN_XPG2,
#define _SC_XOPEN_XPG2                        _SC_XOPEN_XPG2
	   _SC_XOPEN_XPG3,
#define _SC_XOPEN_XPG3                        _SC_XOPEN_XPG3
	   _SC_XOPEN_XPG4,
#define _SC_XOPEN_XPG4                        _SC_XOPEN_XPG4

	   _SC_CHAR_BIT,
#define        _SC_CHAR_BIT                        _SC_CHAR_BIT
	   _SC_CHAR_MAX,
#define        _SC_CHAR_MAX                        _SC_CHAR_MAX
	   _SC_CHAR_MIN,
#define        _SC_CHAR_MIN                        _SC_CHAR_MIN
	   _SC_INT_MAX,
#define        _SC_INT_MAX                        _SC_INT_MAX
	   _SC_INT_MIN,
#define        _SC_INT_MIN                        _SC_INT_MIN
	   _SC_LONG_BIT,
#define        _SC_LONG_BIT                        _SC_LONG_BIT
	   _SC_WORD_BIT,
#define        _SC_WORD_BIT                        _SC_WORD_BIT
	   _SC_MB_LEN_MAX,
#define        _SC_MB_LEN_MAX                        _SC_MB_LEN_MAX
	   _SC_NZERO,
#define        _SC_NZERO                        _SC_NZERO
	   _SC_SSIZE_MAX,
#define        _SC_SSIZE_MAX                        _SC_SSIZE_MAX
	   _SC_SCHAR_MAX,
#define        _SC_SCHAR_MAX                        _SC_SCHAR_MAX
	   _SC_SCHAR_MIN,
#define        _SC_SCHAR_MIN                        _SC_SCHAR_MIN
	   _SC_SHRT_MAX,
#define        _SC_SHRT_MAX                        _SC_SHRT_MAX
	   _SC_SHRT_MIN,
#define        _SC_SHRT_MIN                        _SC_SHRT_MIN
	   _SC_UCHAR_MAX,
#define        _SC_UCHAR_MAX                        _SC_UCHAR_MAX
	   _SC_UINT_MAX,
#define        _SC_UINT_MAX                        _SC_UINT_MAX
	   _SC_ULONG_MAX,
#define        _SC_ULONG_MAX                        _SC_ULONG_MAX
	   _SC_USHRT_MAX,
#define        _SC_USHRT_MAX                        _SC_USHRT_MAX

	   _SC_NL_ARGMAX,
#define        _SC_NL_ARGMAX                        _SC_NL_ARGMAX
	   _SC_NL_LANGMAX,
#define        _SC_NL_LANGMAX                        _SC_NL_LANGMAX
	   _SC_NL_MSGMAX,
#define        _SC_NL_MSGMAX                        _SC_NL_MSGMAX
	   _SC_NL_NMAX,
#define        _SC_NL_NMAX                        _SC_NL_NMAX
	   _SC_NL_SETMAX,
#define        _SC_NL_SETMAX                        _SC_NL_SETMAX
	   _SC_NL_TEXTMAX,
#define        _SC_NL_TEXTMAX                        _SC_NL_TEXTMAX

	   _SC_XBS5_ILP32_OFF32,
#define _SC_XBS5_ILP32_OFF32                _SC_XBS5_ILP32_OFF32
	   _SC_XBS5_ILP32_OFFBIG,
#define _SC_XBS5_ILP32_OFFBIG                _SC_XBS5_ILP32_OFFBIG
	   _SC_XBS5_LP64_OFF64,
#define _SC_XBS5_LP64_OFF64                _SC_XBS5_LP64_OFF64
	   _SC_XBS5_LPBIG_OFFBIG,
#define _SC_XBS5_LPBIG_OFFBIG                _SC_XBS5_LPBIG_OFFBIG

	   _SC_XOPEN_LEGACY,
#define _SC_XOPEN_LEGACY                _SC_XOPEN_LEGACY
	   _SC_XOPEN_REALTIME,
#define _SC_XOPEN_REALTIME                _SC_XOPEN_REALTIME
	   _SC_XOPEN_REALTIME_THREADS,
#define _SC_XOPEN_REALTIME_THREADS        _SC_XOPEN_REALTIME_THREADS

	   _SC_ADVISORY_INFO,
#define _SC_ADVISORY_INFO                _SC_ADVISORY_INFO
	   _SC_BARRIERS,
#define _SC_BARRIERS                        _SC_BARRIERS
	   _SC_BASE,
#define _SC_BASE                        _SC_BASE
	   _SC_C_LANG_SUPPORT,
#define _SC_C_LANG_SUPPORT                _SC_C_LANG_SUPPORT
	   _SC_C_LANG_SUPPORT_R,
#define _SC_C_LANG_SUPPORT_R                _SC_C_LANG_SUPPORT_R
	   _SC_CLOCK_SELECTION,
#define _SC_CLOCK_SELECTION                _SC_CLOCK_SELECTION
	   _SC_CPUTIME,
#define _SC_CPUTIME                        _SC_CPUTIME
	   _SC_THREAD_CPUTIME,
#define _SC_THREAD_CPUTIME                _SC_THREAD_CPUTIME
	   _SC_DEVICE_IO,
#define _SC_DEVICE_IO                        _SC_DEVICE_IO
	   _SC_DEVICE_SPECIFIC,
#define _SC_DEVICE_SPECIFIC                _SC_DEVICE_SPECIFIC
	   _SC_DEVICE_SPECIFIC_R,
#define _SC_DEVICE_SPECIFIC_R                _SC_DEVICE_SPECIFIC_R
	   _SC_FD_MGMT,
#define _SC_FD_MGMT                        _SC_FD_MGMT
	   _SC_FIFO,
#define _SC_FIFO                        _SC_FIFO
	   _SC_PIPE,
#define _SC_PIPE                        _SC_PIPE
	   _SC_FILE_ATTRIBUTES,
#define _SC_FILE_ATTRIBUTES                _SC_FILE_ATTRIBUTES
	   _SC_FILE_LOCKING,
#define _SC_FILE_LOCKING                _SC_FILE_LOCKING
	   _SC_FILE_SYSTEM,
#define _SC_FILE_SYSTEM                        _SC_FILE_SYSTEM
	   _SC_MONOTONIC_CLOCK,
#define _SC_MONOTONIC_CLOCK                _SC_MONOTONIC_CLOCK
	   _SC_MULTI_PROCESS,
#define _SC_MULTI_PROCESS                _SC_MULTI_PROCESS
	   _SC_SINGLE_PROCESS,
#define _SC_SINGLE_PROCESS                _SC_SINGLE_PROCESS
	   _SC_NETWORKING,
#define _SC_NETWORKING                        _SC_NETWORKING
	   _SC_READER_WRITER_LOCKS,
#define _SC_READER_WRITER_LOCKS                _SC_READER_WRITER_LOCKS
	   _SC_SPIN_LOCKS,
#define _SC_SPIN_LOCKS                        _SC_SPIN_LOCKS
	   _SC_REGEXP,
#define _SC_REGEXP                        _SC_REGEXP
	   _SC_REGEX_VERSION,
#define _SC_REGEX_VERSION                _SC_REGEX_VERSION
	   _SC_SHELL,
#define _SC_SHELL                        _SC_SHELL
	   _SC_SIGNALS,
#define _SC_SIGNALS                        _SC_SIGNALS
	   _SC_SPAWN,
#define _SC_SPAWN                        _SC_SPAWN
	   _SC_SPORADIC_SERVER,
#define _SC_SPORADIC_SERVER                _SC_SPORADIC_SERVER
	   _SC_THREAD_SPORADIC_SERVER,
#define _SC_THREAD_SPORADIC_SERVER        _SC_THREAD_SPORADIC_SERVER
	   _SC_SYSTEM_DATABASE,
#define _SC_SYSTEM_DATABASE                _SC_SYSTEM_DATABASE
	   _SC_SYSTEM_DATABASE_R,
#define _SC_SYSTEM_DATABASE_R                _SC_SYSTEM_DATABASE_R
	   _SC_TIMEOUTS,
#define _SC_TIMEOUTS                        _SC_TIMEOUTS
	   _SC_TYPED_MEMORY_OBJECTS,
#define _SC_TYPED_MEMORY_OBJECTS        _SC_TYPED_MEMORY_OBJECTS
	   _SC_USER_GROUPS,
#define _SC_USER_GROUPS                        _SC_USER_GROUPS
	   _SC_USER_GROUPS_R,
#define _SC_USER_GROUPS_R                _SC_USER_GROUPS_R
	   _SC_2_PBS,
#define _SC_2_PBS                        _SC_2_PBS
	   _SC_2_PBS_ACCOUNTING,
#define _SC_2_PBS_ACCOUNTING                _SC_2_PBS_ACCOUNTING
	   _SC_2_PBS_LOCATE,
#define _SC_2_PBS_LOCATE                _SC_2_PBS_LOCATE
	   _SC_2_PBS_MESSAGE,
#define _SC_2_PBS_MESSAGE                _SC_2_PBS_MESSAGE
	   _SC_2_PBS_TRACK,
#define _SC_2_PBS_TRACK                        _SC_2_PBS_TRACK
	   _SC_SYMLOOP_MAX,
#define _SC_SYMLOOP_MAX                        _SC_SYMLOOP_MAX
	   _SC_STREAMS,
#define _SC_STREAMS                        _SC_STREAMS
	   _SC_2_PBS_CHECKPOINT,
#define _SC_2_PBS_CHECKPOINT                _SC_2_PBS_CHECKPOINT

	   _SC_V6_ILP32_OFF32,
#define _SC_V6_ILP32_OFF32                _SC_V6_ILP32_OFF32
	   _SC_V6_ILP32_OFFBIG,
#define _SC_V6_ILP32_OFFBIG                _SC_V6_ILP32_OFFBIG
	   _SC_V6_LP64_OFF64,
#define _SC_V6_LP64_OFF64                _SC_V6_LP64_OFF64
	   _SC_V6_LPBIG_OFFBIG,
#define _SC_V6_LPBIG_OFFBIG                _SC_V6_LPBIG_OFFBIG

	   _SC_HOST_NAME_MAX,
#define _SC_HOST_NAME_MAX                _SC_HOST_NAME_MAX
	   _SC_TRACE,
#define _SC_TRACE                        _SC_TRACE
	   _SC_TRACE_EVENT_FILTER,
#define _SC_TRACE_EVENT_FILTER                _SC_TRACE_EVENT_FILTER
	   _SC_TRACE_INHERIT,
#define _SC_TRACE_INHERIT                _SC_TRACE_INHERIT
	   _SC_TRACE_LOG,
#define _SC_TRACE_LOG                        _SC_TRACE_LOG

	   _SC_LEVEL1_ICACHE_SIZE,
#define _SC_LEVEL1_ICACHE_SIZE                _SC_LEVEL1_ICACHE_SIZE
	   _SC_LEVEL1_ICACHE_ASSOC,
#define _SC_LEVEL1_ICACHE_ASSOC                _SC_LEVEL1_ICACHE_ASSOC
	   _SC_LEVEL1_ICACHE_LINESIZE,
#define _SC_LEVEL1_ICACHE_LINESIZE        _SC_LEVEL1_ICACHE_LINESIZE
	   _SC_LEVEL1_DCACHE_SIZE,
#define _SC_LEVEL1_DCACHE_SIZE                _SC_LEVEL1_DCACHE_SIZE
	   _SC_LEVEL1_DCACHE_ASSOC,
#define _SC_LEVEL1_DCACHE_ASSOC                _SC_LEVEL1_DCACHE_ASSOC
	   _SC_LEVEL1_DCACHE_LINESIZE,
#define _SC_LEVEL1_DCACHE_LINESIZE        _SC_LEVEL1_DCACHE_LINESIZE
	   _SC_LEVEL2_CACHE_SIZE,
#define _SC_LEVEL2_CACHE_SIZE                _SC_LEVEL2_CACHE_SIZE
	   _SC_LEVEL2_CACHE_ASSOC,
#define _SC_LEVEL2_CACHE_ASSOC                _SC_LEVEL2_CACHE_ASSOC
	   _SC_LEVEL2_CACHE_LINESIZE,
#define _SC_LEVEL2_CACHE_LINESIZE        _SC_LEVEL2_CACHE_LINESIZE
	   _SC_LEVEL3_CACHE_SIZE,
#define _SC_LEVEL3_CACHE_SIZE                _SC_LEVEL3_CACHE_SIZE
	   _SC_LEVEL3_CACHE_ASSOC,
#define _SC_LEVEL3_CACHE_ASSOC                _SC_LEVEL3_CACHE_ASSOC
	   _SC_LEVEL3_CACHE_LINESIZE,
#define _SC_LEVEL3_CACHE_LINESIZE        _SC_LEVEL3_CACHE_LINESIZE
	   _SC_LEVEL4_CACHE_SIZE,
#define _SC_LEVEL4_CACHE_SIZE                _SC_LEVEL4_CACHE_SIZE
	   _SC_LEVEL4_CACHE_ASSOC,
#define _SC_LEVEL4_CACHE_ASSOC                _SC_LEVEL4_CACHE_ASSOC
	   _SC_LEVEL4_CACHE_LINESIZE,
#define _SC_LEVEL4_CACHE_LINESIZE        _SC_LEVEL4_CACHE_LINESIZE
	   /* Leave room here, maybe we need a few more cache levels some day.  */

	   _SC_IPV6 = _SC_LEVEL1_ICACHE_SIZE + 50,
#define _SC_IPV6                        _SC_IPV6
	   _SC_RAW_SOCKETS,
#define _SC_RAW_SOCKETS                        _SC_RAW_SOCKETS

	   _SC_V7_ILP32_OFF32,
#define _SC_V7_ILP32_OFF32                _SC_V7_ILP32_OFF32
	   _SC_V7_ILP32_OFFBIG,
#define _SC_V7_ILP32_OFFBIG                _SC_V7_ILP32_OFFBIG
	   _SC_V7_LP64_OFF64,
#define _SC_V7_LP64_OFF64                _SC_V7_LP64_OFF64
	   _SC_V7_LPBIG_OFFBIG,
#define _SC_V7_LPBIG_OFFBIG                _SC_V7_LPBIG_OFFBIG

	   _SC_SS_REPL_MAX,
#define _SC_SS_REPL_MAX                        _SC_SS_REPL_MAX

	   _SC_TRACE_EVENT_NAME_MAX,
#define _SC_TRACE_EVENT_NAME_MAX        _SC_TRACE_EVENT_NAME_MAX
	   _SC_TRACE_NAME_MAX,
#define _SC_TRACE_NAME_MAX                _SC_TRACE_NAME_MAX
	   _SC_TRACE_SYS_MAX,
#define _SC_TRACE_SYS_MAX                _SC_TRACE_SYS_MAX
	   _SC_TRACE_USER_EVENT_MAX,
#define _SC_TRACE_USER_EVENT_MAX        _SC_TRACE_USER_EVENT_MAX

	   _SC_XOPEN_STREAMS,
#define _SC_XOPEN_STREAMS                _SC_XOPEN_STREAMS

	   _SC_THREAD_ROBUST_PRIO_INHERIT,
#define _SC_THREAD_ROBUST_PRIO_INHERIT        _SC_THREAD_ROBUST_PRIO_INHERIT
	   _SC_THREAD_ROBUST_PRIO_PROTECT
#define _SC_THREAD_ROBUST_PRIO_PROTECT        _SC_THREAD_ROBUST_PRIO_PROTECT
};

extern unsigned long mtime_since_now(struct timespec *);
extern void fio_gettime(struct timespec *, void *);

int win_to_posix_error(DWORD winerr)
{
	switch (winerr) {
	case ERROR_SUCCESS:
		return 0;
	case ERROR_FILE_NOT_FOUND:
		return ENOENT;
	case ERROR_PATH_NOT_FOUND:
		return ENOENT;
	case ERROR_ACCESS_DENIED:
		return EACCES;
	case ERROR_INVALID_HANDLE:
		return EBADF;
	case ERROR_NOT_ENOUGH_MEMORY:
		return ENOMEM;
	case ERROR_INVALID_DATA:
		return EINVAL;
	case ERROR_OUTOFMEMORY:
		return ENOMEM;
	case ERROR_INVALID_DRIVE:
		return ENODEV;
	case ERROR_NOT_SAME_DEVICE:
		return EXDEV;
	case ERROR_WRITE_PROTECT:
		return EROFS;
	case ERROR_BAD_UNIT:
		return ENODEV;
	case ERROR_NOT_READY:
		return EAGAIN;
	case ERROR_SHARING_VIOLATION:
		return EACCES;
	case ERROR_LOCK_VIOLATION:
		return EACCES;
	case ERROR_SHARING_BUFFER_EXCEEDED:
		return ENOLCK;
	case ERROR_HANDLE_DISK_FULL:
		return ENOSPC;
	case ERROR_NOT_SUPPORTED:
		return ENOSYS;
	case ERROR_FILE_EXISTS:
		return EEXIST;
	case ERROR_CANNOT_MAKE:
		return EPERM;
	case ERROR_INVALID_PARAMETER:
		return EINVAL;
	case ERROR_NO_PROC_SLOTS:
		return EAGAIN;
	case ERROR_BROKEN_PIPE:
		return EPIPE;
	case ERROR_OPEN_FAILED:
		return EIO;
	case ERROR_NO_MORE_SEARCH_HANDLES:
		return ENFILE;
	case ERROR_CALL_NOT_IMPLEMENTED:
		return ENOSYS;
	case ERROR_INVALID_NAME:
		return ENOENT;
	case ERROR_WAIT_NO_CHILDREN:
		return ECHILD;
	case ERROR_CHILD_NOT_COMPLETE:
		return EBUSY;
	case ERROR_DIR_NOT_EMPTY:
		return ENOTEMPTY;
	case ERROR_SIGNAL_REFUSED:
		return EIO;
	case ERROR_BAD_PATHNAME:
		return ENOENT;
	case ERROR_SIGNAL_PENDING:
		return EBUSY;
	case ERROR_MAX_THRDS_REACHED:
		return EAGAIN;
	case ERROR_BUSY:
		return EBUSY;
	case ERROR_ALREADY_EXISTS:
		return EEXIST;
	case ERROR_NO_SIGNAL_SENT:
		return EIO;
	case ERROR_FILENAME_EXCED_RANGE:
		return EINVAL;
	case ERROR_META_EXPANSION_TOO_LONG:
		return EINVAL;
	case ERROR_INVALID_SIGNAL_NUMBER:
		return EINVAL;
	case ERROR_THREAD_1_INACTIVE:
		return EINVAL;
	case ERROR_BAD_PIPE:
		return EINVAL;
	case ERROR_PIPE_BUSY:
		return EBUSY;
	case ERROR_NO_DATA:
		return EPIPE;
	case ERROR_MORE_DATA:
		return EAGAIN;
	case ERROR_DIRECTORY:
		return ENOTDIR;
	case ERROR_PIPE_CONNECTED:
		return EBUSY;
	case ERROR_NO_TOKEN:
		return EINVAL;
	case ERROR_PROCESS_ABORTED:
		return EFAULT;
	case ERROR_BAD_DEVICE:
		return ENODEV;
	case ERROR_BAD_USERNAME:
		return EINVAL;
	case ERROR_OPEN_FILES:
		return EAGAIN;
	case ERROR_ACTIVE_CONNECTIONS:
		return EAGAIN;
	case ERROR_DEVICE_IN_USE:
		return EBUSY;
	case ERROR_INVALID_AT_INTERRUPT_TIME:
		return EINTR;
	case ERROR_IO_DEVICE:
		return EIO;
	case ERROR_NOT_OWNER:
		return EPERM;
	case ERROR_END_OF_MEDIA:
		return ENOSPC;
	case ERROR_EOM_OVERFLOW:
		return ENOSPC;
	case ERROR_BEGINNING_OF_MEDIA:
		return ESPIPE;
	case ERROR_SETMARK_DETECTED:
		return ESPIPE;
	case ERROR_NO_DATA_DETECTED:
		return ENOSPC;
	case ERROR_POSSIBLE_DEADLOCK:
		return EDEADLOCK;
	case ERROR_CRC:
		return EIO;
	case ERROR_NEGATIVE_SEEK:
		return EINVAL;
	case ERROR_DISK_FULL:
		return ENOSPC;
	case ERROR_NOACCESS:
		return EFAULT;
	case ERROR_FILE_INVALID:
		return ENXIO;
	default:
		log_err("fio: windows error %lu not handled\n", winerr);
		return EIO;
	}

	return winerr;
}

unsigned int hweight8(uint8_t w)
{
	unsigned int res = w - ((w >> 1) & 0x55);

	res = (res & 0x33) + ((res >> 2) & 0x33);
	return (res + (res >> 4)) & 0x0F;
}

unsigned int hweight32(uint32_t w)
{
	unsigned int res = w - ((w >> 1) & 0x55555555);

	res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
	res = (res + (res >> 4)) & 0x0F0F0F0F;
	res = res + (res >> 8);
	return (res + (res >> 16)) & 0x000000FF;
}

unsigned int hweight64(uint64_t w)
{
#if BITS_PER_LONG == 32
	return hweight32((unsigned int)(w >> 32)) + hweight32((unsigned int)w);
#else
	uint64_t res = w - ((w >> 1) & 0x5555555555555555ULL);
	res = (res & 0x3333333333333333ULL) + ((res >> 2) & 0x3333333333333333ULL);
	res = (res + (res >> 4)) & 0x0F0F0F0F0F0F0F0FULL;
	res = res + (res >> 8);
	res = res + (res >> 16);
	return (res + (res >> 32)) & 0x00000000000000FFULL;
#endif
}

int GetNumLogicalProcessors(void)
{
	SYSTEM_LOGICAL_PROCESSOR_INFORMATION *processor_info = NULL;
	DWORD len = 0;
	DWORD num_processors = 0;
	DWORD error = 0;
	DWORD i;

	while (!GetLogicalProcessorInformation(processor_info, &len)) {
		error = GetLastError();
		if (error == ERROR_INSUFFICIENT_BUFFER)
			processor_info = malloc(len);
		else {
			log_err("Error: GetLogicalProcessorInformation failed: %lu\n",
				error);
			return -1;
		}

		if (processor_info == NULL) {
			log_err("Error: failed to allocate memory for GetLogicalProcessorInformation");
			return -1;
		}
	}

	for (i = 0; i < len / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION); i++) {
		if (processor_info[i].Relationship == RelationProcessorCore)
			num_processors += hweight64(processor_info[i].ProcessorMask);
	}

	free(processor_info);
	return num_processors;
}


long sysconf(int name)
{
	long val = -1;
	long val2 = -1;
	SYSTEM_INFO sysInfo;
	MEMORYSTATUSEX status;

	switch (name) {
	case _SC_NPROCESSORS_ONLN:
		val = GetNumLogicalProcessors();
		if (val == -1)
			log_err("sysconf(_SC_NPROCESSORS_ONLN) failed\n");

		break;

	case _SC_PAGESIZE:
		GetSystemInfo(&sysInfo);
		val = sysInfo.dwPageSize;
		break;

	case _SC_PHYS_PAGES:
		status.dwLength = sizeof(status);
		val2 = sysconf(_SC_PAGESIZE);
		if (GlobalMemoryStatusEx(&status) && val2 != -1)
			val = status.ullTotalPhys / val2;
		else
			log_err("sysconf(_SC_PHYS_PAGES) failed\n");
		break;
	default:
		log_err("sysconf(%d) is not implemented\n", name);
		break;
	}

	return val;
}

char *dl_error = NULL;

int dlclose(void *handle)
{
	return !FreeLibrary((HMODULE)handle);
}

void *dlopen(const char *file, int mode)
{
	HMODULE hMod;

	hMod = LoadLibrary(file);
	if (hMod == INVALID_HANDLE_VALUE)
		dl_error = (char*)"LoadLibrary failed";
	else
		dl_error = NULL;

	return hMod;
}

void *dlsym(void *handle, const char *name)
{
	FARPROC fnPtr;

	fnPtr = GetProcAddress((HMODULE)handle, name);
	if (fnPtr == NULL)
		dl_error = (char*)"GetProcAddress failed";
	else
		dl_error = NULL;

	return fnPtr;
}

char *dlerror(void)
{
	return dl_error;
}

/* Copied from http://blogs.msdn.com/b/joshpoley/archive/2007/12/19/date-time-formats-and-conversions.aspx */
void Time_tToSystemTime(time_t dosTime, SYSTEMTIME *systemTime)
{
	FILETIME utcFT;
	LONGLONG jan1970;
	SYSTEMTIME tempSystemTime;

	jan1970 = Int32x32To64(dosTime, 10000000) + 116444736000000000;
	utcFT.dwLowDateTime = (DWORD)jan1970;
	utcFT.dwHighDateTime = jan1970 >> 32;

	FileTimeToSystemTime((FILETIME*)&utcFT, &tempSystemTime);
	SystemTimeToTzSpecificLocalTime(NULL, &tempSystemTime, systemTime);
}

char *ctime_r(const time_t *t, char *buf)
{
	SYSTEMTIME systime;
	const char * const dayOfWeek[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	const char * const monthOfYear[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

	Time_tToSystemTime(*t, &systime);

	/*
	 * We don't know how long `buf` is, but assume it's rounded up from
	 * the minimum of 25 to 32
	 */
	snprintf(buf, 32, "%s %s %d %02d:%02d:%02d %04d\n",
		 dayOfWeek[systime.wDayOfWeek % 7],
		 monthOfYear[(systime.wMonth - 1) % 12],
		 systime.wDay, systime.wHour, systime.wMinute,
		 systime.wSecond, systime.wYear);
	return buf;
}

int gettimeofday(struct timeval* /*restrict*/ tp, void* /*restrict*/ tzp)
{
	FILETIME fileTime;
	uint64_t unix_time, windows_time;
	const uint64_t MILLISECONDS_BETWEEN_1601_AND_1970 = 11644473600000;

	/* Ignore the timezone parameter */
	(void)tzp;

	/*
	 * Windows time is stored as the number 100 ns intervals since January 1 1601.
	 * Conversion details from http://www.informit.com/articles/article.aspx?p=102236&seqNum=3
	 * Its precision is 100 ns but accuracy is only one clock tick, or normally around 15 ms.
	 */
	GetSystemTimeAsFileTime(&fileTime);
	windows_time = ((uint64_t)fileTime.dwHighDateTime << 32) + fileTime.dwLowDateTime;
	/* Divide by 10,000 to convert to ms and subtract the time between 1601 and 1970 */
	unix_time = (((windows_time)/10000) - MILLISECONDS_BETWEEN_1601_AND_1970);
	/* unix_time is now the number of milliseconds since 1970 (the Unix epoch) */
	tp->tv_sec = unix_time / 1000;
	tp->tv_usec = (unix_time % 1000) * 1000;
	return 0;
}

int sigaction(int sig, const struct sigaction *act, struct sigaction *oact)
{
	int rc = 0;
	/*
	void (*prev_handler)(int);

	prev_handler = signal(sig, act->sa_handler);
	if (oact != NULL)
		oact->sa_handler = prev_handler;

	if (prev_handler == SIG_ERR)
		rc = -1;
	*/
	return rc;
}

int lstat(const char *path, struct stat *buf)
{
	return stat(path, buf);
}

void *_mmap(void *addr, size_t len, int prot, int flags, int fildes, off_t off)
{
	DWORD vaProt = 0;
	DWORD mapAccess = 0;
	DWORD lenlow;
	DWORD lenhigh;
	HANDLE hMap;
	void* allocAddr = NULL;

	if (prot & PROT_NONE)
		vaProt |= PAGE_NOACCESS;

	if ((prot & PROT_READ) && !(prot & PROT_WRITE)) {
		vaProt |= PAGE_READONLY;
		mapAccess = FILE_MAP_READ;
	}

	if (prot & PROT_WRITE) {
		vaProt |= PAGE_READWRITE;
		mapAccess |= FILE_MAP_WRITE;
	}

	lenlow = len & 0xFFFF;
	lenhigh = len >> 16;
	/* If the low DWORD is zero and the high DWORD is non-zero, `CreateFileMapping`
	   will return ERROR_INVALID_PARAMETER. To avoid this, set both to zero. */
	if (lenlow == 0)
		lenhigh = 0;

	if (flags & MAP_ANON || flags & MAP_ANONYMOUS) {
		allocAddr = VirtualAlloc(addr, len, MEM_COMMIT, vaProt);
		if (allocAddr == NULL)
			errno = win_to_posix_error(GetLastError());
	} else {
		hMap = CreateFileMapping((HANDLE)_get_osfhandle(fildes), NULL,
						vaProt, lenhigh, lenlow, NULL);

		if (hMap != NULL)
			allocAddr = MapViewOfFile(hMap, mapAccess, off >> 16,
							off & 0xFFFF, len);
		if (hMap == NULL || allocAddr == NULL)
			errno = win_to_posix_error(GetLastError());

	}

	return allocAddr;
}

int _munmap(void *addr, size_t len)
{
	BOOL success;

	/* We may have allocated the memory with either MapViewOfFile or
		 VirtualAlloc. Therefore, try calling UnmapViewOfFile first, and if that
		 fails, call VirtualFree. */
	success = UnmapViewOfFile(addr);

	if (!success)
		success = VirtualFree(addr, 0, MEM_RELEASE);

	return !success;
}

int msync(void *addr, size_t len, int flags)
{
	return !FlushViewOfFile(addr, len);
}

int fork(void)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

pid_t setsid(void)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

static HANDLE log_file = INVALID_HANDLE_VALUE;

void openlog(const char *ident, int logopt, int facility)
{
	if (log_file != INVALID_HANDLE_VALUE)
		return;

	log_file = CreateFileA("syslog.txt", GENERIC_WRITE,
				FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
				OPEN_ALWAYS, 0, NULL);
}

void closelog(void)
{
	CloseHandle(log_file);
	log_file = INVALID_HANDLE_VALUE;
}

void syslog(int priority, const char *message, ... /* argument */)
{
	va_list v;
	int len;
	char *output;
	DWORD bytes_written;

	if (log_file == INVALID_HANDLE_VALUE) {
		log_file = CreateFileA("syslog.txt", GENERIC_WRITE,
					FILE_SHARE_READ | FILE_SHARE_WRITE,
					NULL, OPEN_ALWAYS, 0, NULL);
	}

	if (log_file == INVALID_HANDLE_VALUE) {
		log_err("syslog: failed to open log file\n");
		return;
	}

	va_start(v, message);
	len = _vscprintf(message, v);
	output = malloc(len + sizeof(char));
	vsprintf(output, message, v);
	WriteFile(log_file, output, len, &bytes_written, NULL);
	va_end(v);
	free(output);
}

int kill(pid_t pid, int sig)
{
	errno = ESRCH;
	return -1;
}

/*
 * This is assumed to be used only by the network code,
 * and so doesn't try and handle any of the other cases
 */
int fcntl(int fildes, int cmd, ...)
{
	/*
	 * non-blocking mode doesn't work the same as in BSD sockets,
	 * so ignore it.
	 */
#if 0
	va_list ap;
	int val, opt, status;

	if (cmd == F_GETFL)
		return 0;
	else if (cmd != F_SETFL) {
		errno = EINVAL;
		return -1;
	}

	va_start(ap, 1);

	opt = va_arg(ap, int);
	if (opt & O_NONBLOCK)
		val = 1;
	else
		val = 0;

	status = ioctlsocket((SOCKET)fildes, opt, &val);

	if (status == SOCKET_ERROR) {
		errno = EINVAL;
		val = -1;
	}

	va_end(ap);

	return val;
#endif
return 0;
}

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW 4
#endif

/*
 * Get the value of a local clock source.
 * This implementation supports 3 clocks: CLOCK_MONOTONIC/CLOCK_MONOTONIC_RAW
 * provide high-accuracy relative time, while CLOCK_REALTIME provides a
 * low-accuracy wall time.
 */
int _clock_gettime(clockid_t clock_id, struct timespec *tp)
{
	int rc = 0;

	if (clock_id == CLOCK_MONOTONIC || clock_id == CLOCK_MONOTONIC_RAW) {
		static LARGE_INTEGER freq = {{0,0}};
		LARGE_INTEGER counts;
		uint64_t t;

		QueryPerformanceCounter(&counts);
		if (freq.QuadPart == 0)
			QueryPerformanceFrequency(&freq);

		tp->tv_sec = counts.QuadPart / freq.QuadPart;
		/* Get the difference between the number of ns stored
		 * in 'tv_sec' and that stored in 'counts' */
		t = tp->tv_sec * freq.QuadPart;
		t = counts.QuadPart - t;
		/* 't' now contains the number of cycles since the last second.
		 * We want the number of nanoseconds, so multiply out by 1,000,000,000
		 * and then divide by the frequency. */
		t *= 1000000000;
		tp->tv_nsec = t / freq.QuadPart;
	} else if (clock_id == CLOCK_REALTIME) {
		/* clock_gettime(CLOCK_REALTIME,...) is just an alias for gettimeofday with a
		 * higher-precision field. */
		struct timeval tv;
		gettimeofday(&tv, NULL);
		tp->tv_sec = tv.tv_sec;
		tp->tv_nsec = tv.tv_usec * 1000;
	} else {
		errno = EINVAL;
		rc = -1;
	}

	return rc;
}

int mlock(const void * addr, size_t len)
{
	SIZE_T min, max;
	BOOL success;
	HANDLE process = GetCurrentProcess();

	success = GetProcessWorkingSetSize(process, &min, &max);
	if (!success) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	min += len;
	max += len;
	success = SetProcessWorkingSetSize(process, min, max);
	if (!success) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	success = VirtualLock((LPVOID)addr, len);
	if (!success) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	return 0;
}

int munlock(const void * addr, size_t len)
{
	BOOL success = VirtualUnlock((LPVOID)addr, len);

	if (!success) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	return 0;
}

pid_t waitpid(pid_t pid, int *stat_loc, int options)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

typedef unsigned int useconds_t;

int usleep(useconds_t useconds)
{
	Sleep(useconds / 1000);
	return 0;
}

char *basename(char *path)
{
	static char name[MAX_PATH];
	int i;

	if (path == NULL || strlen(path) == 0)
		return (char*)".";

	i = strlen(path) - 1;

	while (path[i] != '\\' && path[i] != '/' && i >= 0)
		i--;

	name[MAX_PATH - 1] = '\0';
	strncpy(name, path + i + 1, MAX_PATH - 1);

	return name;
}

int fsync(int fildes)
{
	HANDLE hFile = (HANDLE)_get_osfhandle(fildes);
	if (!FlushFileBuffers(hFile)) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	return 0;
}

int nFileMappings = 0;
HANDLE fileMappings[1024];

int shmget(key_t key, size_t size, int shmflg)
{
	int mapid = -1;
	uint32_t size_low = size & 0xFFFFFFFF;
	uint32_t size_high = ((uint64_t)size) >> 32;
	HANDLE hMapping;

	hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL,
					PAGE_EXECUTE_READWRITE | SEC_RESERVE,
					size_high, size_low, NULL);
	if (hMapping != NULL) {
		fileMappings[nFileMappings] = hMapping;
		mapid = nFileMappings;
		nFileMappings++;
	} else
		errno = ENOSYS;

	return mapid;
}

void *shmat(int shmid, const void *shmaddr, int shmflg)
{
	void *mapAddr;
	MEMORY_BASIC_INFORMATION memInfo;

	mapAddr = MapViewOfFile(fileMappings[shmid], FILE_MAP_ALL_ACCESS, 0, 0, 0);
	if (mapAddr == NULL) {
		errno = win_to_posix_error(GetLastError());
		return (void*)-1;
	}

	if (VirtualQuery(mapAddr, &memInfo, sizeof(memInfo)) == 0) {
		errno = win_to_posix_error(GetLastError());
		return (void*)-1;
	}

	mapAddr = VirtualAlloc(mapAddr, memInfo.RegionSize, MEM_COMMIT, PAGE_READWRITE);
	if (mapAddr == NULL) {
		errno = win_to_posix_error(GetLastError());
		return (void*)-1;
	}

	return mapAddr;
}

int shmdt(const void *shmaddr)
{
	if (!UnmapViewOfFile(shmaddr)) {
		errno = win_to_posix_error(GetLastError());
		return -1;
	}

	return 0;
}

int shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
	if (cmd == IPC_RMID) {
		fileMappings[shmid] = INVALID_HANDLE_VALUE;
		return 0;
	}

	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

int setuid(uid_t uid)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

int setgid(gid_t gid)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}

int nice(int incr)
{
	DWORD prioclass = NORMAL_PRIORITY_CLASS;

	if (incr < -15)
		prioclass = HIGH_PRIORITY_CLASS;
	else if (incr < 0)
		prioclass = ABOVE_NORMAL_PRIORITY_CLASS;
	else if (incr > 15)
		prioclass = IDLE_PRIORITY_CLASS;
	else if (incr > 0)
		prioclass = BELOW_NORMAL_PRIORITY_CLASS;

	if (!SetPriorityClass(GetCurrentProcess(), prioclass))
		log_err("fio: SetPriorityClass failed\n");

	return 0;
}

int getrusage(int who, struct rusage *r_usage)
{
	const uint64_t SECONDS_BETWEEN_1601_AND_1970 = 11644473600;
	FILETIME cTime, eTime, kTime, uTime;
	time_t time;
	HANDLE h;

	memset(r_usage, 0, sizeof(*r_usage));

	if (who == RUSAGE_SELF) {
		h = GetCurrentProcess();
		GetProcessTimes(h, &cTime, &eTime, &kTime, &uTime);
	} else if (who == RUSAGE_THREAD) {
		h = GetCurrentThread();
		GetThreadTimes(h, &cTime, &eTime, &kTime, &uTime);
	} else {
		log_err("fio: getrusage %d is not implemented\n", who);
		return -1;
	}

	time = ((uint64_t)uTime.dwHighDateTime << 32) + uTime.dwLowDateTime;
	/* Divide by 10,000,000 to get the number of seconds and move the epoch from
	 * 1601 to 1970 */
	time = (time_t)(((time)/10000000) - SECONDS_BETWEEN_1601_AND_1970);
	r_usage->ru_utime.tv_sec = time;
	/* getrusage() doesn't care about anything other than seconds, so set tv_usec to 0 */
	r_usage->ru_utime.tv_usec = 0;
	time = ((uint64_t)kTime.dwHighDateTime << 32) + kTime.dwLowDateTime;
	/* Divide by 10,000,000 to get the number of seconds and move the epoch from
	 * 1601 to 1970 */
	time = (time_t)(((time)/10000000) - SECONDS_BETWEEN_1601_AND_1970);
	r_usage->ru_stime.tv_sec = time;
	r_usage->ru_stime.tv_usec = 0;
	return 0;
}

int posix_madvise(void *addr, size_t len, int advice)
{
	return ENOSYS;
}

int fdatasync(int fildes)
{
	return fsync(fildes);
}

ssize_t pwrite(int fildes, const void *buf, size_t nbyte,
		off_t offset)
{
	int64_t pos = _telli64(fildes);
	ssize_t len = _write(fildes, buf, nbyte);

	_lseeki64(fildes, pos, SEEK_SET);
	return len;
}

ssize_t pread(int fildes, void *buf, size_t nbyte, off_t offset)
{
	int64_t pos = _telli64(fildes);
	ssize_t len = _read(fildes, buf, nbyte);

	_lseeki64(fildes, pos, SEEK_SET);
	return len;
}

ssize_t readv(int fildes, const struct iovec *iov, int iovcnt)
{
	//log_err("%s is not implemented\n", __func__);
	//errno = ENOSYS;
	//return -1;

	long r, t = 0;
	while (iovcnt)
	{
		r = recv((SOCKET)fildes, iov->iov_base, iov->iov_len, 0);
		if (r < 0) {
			printf("readv: %d %d\n", iovcnt, WSAGetLastError());
			//return r;
			return 0;
		}
		else if (r == 0) {
			printf("***readv: 0\n");
		}
		t += r;
		iov++;
		iovcnt--;
	}
	return t;
}

ssize_t writev(int fildes, const struct iovec *iov, int iovcnt)
{
	int i;
	DWORD bytes_written = 0;

	for (i = 0; i < iovcnt; i++) {
		int len;

		len = send((SOCKET)fildes, iov[i].iov_base, iov[i].iov_len, 0);
		if (len == SOCKET_ERROR) {
			DWORD err = GetLastError();
			errno = win_to_posix_error(err);
			bytes_written = -1;
			break;
		}
		bytes_written += len;
	}

	return bytes_written;
}

long long _strtoll(const char */*restrict*/ str, char** /*restrict*/ endptr, int base)
{
	return _strtoi64(str, endptr, base);
}

int poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
	struct timeval tv;
	struct timeval *to = NULL;
	fd_set readfds, writefds, exceptfds;
	int i;
	int rc;

	if (timeout != -1) {
		to = &tv;
		to->tv_sec = timeout / 1000;
		to->tv_usec = (timeout % 1000) * 1000;
	}

	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);

	for (i = 0; i < nfds; i++) {
		if (fds[i].fd == INVALID_SOCKET) {
			fds[i].revents = 0;
			continue;
		}

		if (fds[i].events & POLLIN)
			FD_SET(fds[i].fd, &readfds);

		if (fds[i].events & POLLOUT)
			FD_SET(fds[i].fd, &writefds);

		FD_SET(fds[i].fd, &exceptfds);
	}
	rc = select(nfds, &readfds, &writefds, &exceptfds, to);

	if (rc != SOCKET_ERROR) {
		for (i = 0; i < nfds; i++) {
			if (fds[i].fd == INVALID_SOCKET)
				continue;

			if ((fds[i].events & POLLIN) && FD_ISSET(fds[i].fd, &readfds))
				fds[i].revents |= POLLIN;

			if ((fds[i].events & POLLOUT) && FD_ISSET(fds[i].fd, &writefds))
				fds[i].revents |= POLLOUT;

			if (FD_ISSET(fds[i].fd, &exceptfds))
				fds[i].revents |= POLLHUP;
		}
	}
	return rc;
}

int nanosleep(const struct timespec *rqtp, struct timespec *rmtp)
{
	struct timespec tv;
	DWORD ms_remaining;
	DWORD ms_total = (rqtp->tv_sec * 1000) + (rqtp->tv_nsec / 1000000.0);

	if (ms_total == 0)
		ms_total = 1;

	ms_remaining = ms_total;

	/* Since Sleep() can sleep for less than the requested time, add a loop to
	   ensure we only return after the requested length of time has elapsed */
/*
	do {
		fio_gettime(&tv, NULL);
		Sleep(ms_remaining);
		ms_remaining = ms_total - mtime_since_now(&tv);
	} while (ms_remaining > 0 && ms_remaining < ms_total);
*/
	/* this implementation will never sleep for less than the requested time */
	if (rmtp != NULL) {
		rmtp->tv_sec = 0;
		rmtp->tv_nsec = 0;
	}

	return 0;
}

DIR *opendir(const char *dirname)
{
	struct dirent_ctx *dc = NULL;
	HANDLE file;

	/* See if we can open it. If not, we'll return an error here */
	file = CreateFileA(dirname, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
				OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (file != INVALID_HANDLE_VALUE) {
		CloseHandle(file);
		dc = malloc(sizeof(struct dirent_ctx));
		snprintf(dc->dirname, sizeof(dc->dirname), "%s", dirname);
		dc->find_handle = INVALID_HANDLE_VALUE;
	} else {
		DWORD error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND)
			errno = ENOENT;

		else if (error == ERROR_PATH_NOT_FOUND)
			errno = ENOTDIR;
		else if (error == ERROR_TOO_MANY_OPEN_FILES)
			errno = ENFILE;
		else if (error == ERROR_ACCESS_DENIED)
			errno = EACCES;
		else
			errno = error;
	}

	return dc;
}

int closedir(DIR *dirp)
{
	if (dirp != NULL && dirp->find_handle != INVALID_HANDLE_VALUE)
		FindClose(dirp->find_handle);

	free(dirp);
	return 0;
}

struct dirent *readdir(DIR *dirp)
{
	static struct dirent de;
	WIN32_FIND_DATA find_data;

	if (dirp == NULL)
		return NULL;

	if (dirp->find_handle == INVALID_HANDLE_VALUE) {
		char search_pattern[MAX_PATH];

		snprintf(search_pattern, sizeof(search_pattern), "%s\\*",
			 dirp->dirname);
		dirp->find_handle = FindFirstFileA(search_pattern, &find_data);
		if (dirp->find_handle == INVALID_HANDLE_VALUE)
			return NULL;
	} else {
		if (!FindNextFile(dirp->find_handle, &find_data))
			return NULL;
	}

	snprintf(de.d_name, sizeof(de.d_name), find_data.cFileName);
	de.d_ino = 0;

	return &de;
}

/*
uid_t geteuid(void)
{
	log_err("%s is not implemented\n", __func__);
	errno = ENOSYS;
	return -1;
}
*/

in_addr_t inet_network(const char *cp)
{
	in_addr_t hbo;
	in_addr_t nbo = inet_addr(cp);
	hbo = ((nbo & 0xFF) << 24) + ((nbo & 0xFF00) << 8) + ((nbo & 0xFF0000) >> 8) + ((nbo & 0xFF000000) >> 24);
	return hbo;
}

static HANDLE create_named_pipe(char *pipe_name, int wait_connect_time)
{
	HANDLE hpipe;

	hpipe = CreateNamedPipe (
			pipe_name,
			PIPE_ACCESS_DUPLEX,
			PIPE_WAIT | PIPE_TYPE_BYTE,
			1, 0, 0, wait_connect_time, NULL);

	if (hpipe == INVALID_HANDLE_VALUE) {
		log_err("ConnectNamedPipe failed (%lu).\n", GetLastError());
		return INVALID_HANDLE_VALUE;
	}

	if (!ConnectNamedPipe(hpipe, NULL)) {
		log_err("ConnectNamedPipe failed (%lu).\n", GetLastError());
		CloseHandle(hpipe);
		return INVALID_HANDLE_VALUE;
	}

	return hpipe;
}

static BOOL windows_create_process(PROCESS_INFORMATION *pi, const char *args, HANDLE *hjob)
{
	LPSTR this_cmd_line = GetCommandLine();
	LPSTR new_process_cmd_line = malloc((strlen(this_cmd_line)+strlen(args)) * sizeof(char *));
	STARTUPINFO si = {0};
	DWORD flags = 0;

	strcpy(new_process_cmd_line, this_cmd_line);
	strcat(new_process_cmd_line, args);

	si.cb = sizeof(si);
	memset(pi, 0, sizeof(*pi));

	if ((hjob != NULL) && (*hjob != INVALID_HANDLE_VALUE))
		flags = CREATE_SUSPENDED | CREATE_BREAKAWAY_FROM_JOB;

	flags |= CREATE_NEW_CONSOLE;

	if( !CreateProcess( NULL,
		new_process_cmd_line,
		NULL,    /* Process handle not inherited */
		NULL,    /* Thread handle not inherited */
		TRUE,    /* no handle inheritance */
		flags,
		NULL,    /* Use parent's environment block */
		NULL,    /* Use parent's starting directory */
		&si,
		pi )
	)
	{
		log_err("CreateProcess failed (%lu).\n", GetLastError() );
		free(new_process_cmd_line);
		return 1;
	}
	if ((hjob != NULL) && (*hjob != INVALID_HANDLE_VALUE)) {
		BOOL ret = AssignProcessToJobObject(*hjob, pi->hProcess);
		if (!ret) {
			log_err("AssignProcessToJobObject failed (%lu).\n", GetLastError() );
			return 1;
		}

 		ResumeThread(pi->hThread);
	}

	free(new_process_cmd_line);
	return 0;
}

HANDLE windows_create_job(void)
{
	JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
	BOOL success;
	HANDLE hjob = CreateJobObject(NULL, NULL);

	jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
	success = SetInformationJobObject(hjob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli));
	if ( success == 0 ) {
        log_err( "SetInformationJobObject failed: error %lu\n", GetLastError() );
        return INVALID_HANDLE_VALUE;
    }
	return hjob;
}

#define dprint fprintf
#define FD_PROCESS stderr

/* wait for a child process to either exit or connect to a child */
static bool monitor_process_till_connect(PROCESS_INFORMATION *pi, HANDLE *hpipe)
{
	bool connected = FALSE;
	bool process_alive = TRUE;
	char buffer[32] = {0};
	DWORD bytes_read;

	do {
		DWORD exit_code;
		GetExitCodeProcess(pi->hProcess, &exit_code);
		if (exit_code != STILL_ACTIVE) {
			dprint(FD_PROCESS, "process %u exited %d\n", GetProcessId(pi->hProcess), exit_code);
			break;
		}

		memset(buffer, 0, sizeof(buffer));
		ReadFile(*hpipe, &buffer, sizeof(buffer) - 1, &bytes_read, NULL);
		if (bytes_read && strstr(buffer, "connected")) {
			dprint(FD_PROCESS, "process %u connected to client\n", GetProcessId(pi->hProcess));
			connected = TRUE;
		}
		usleep(10*1000);
	} while (process_alive && !connected);
	return connected;
}

/*create a process with --server-internal to emulate fork() */
HANDLE windows_handle_connection(HANDLE hjob, int sk)
{
	char pipe_name[64] =  "\\\\.\\pipe\\fiointernal-";
	char args[128] = " --server-internal=";
	PROCESS_INFORMATION pi;
	HANDLE hpipe = INVALID_HANDLE_VALUE;
	WSAPROTOCOL_INFO protocol_info;
	HANDLE ret;

	sprintf(pipe_name+strlen(pipe_name), "%d", GetCurrentProcessId());
	sprintf(args+strlen(args), "%s", pipe_name);

	if (windows_create_process(&pi, args, &hjob) != 0)
		return INVALID_HANDLE_VALUE;
	else
		ret = pi.hProcess;

	/* duplicate socket and write the protocol_info to pipe so child can
	 * duplicate the communciation socket */
	if (WSADuplicateSocket(sk, GetProcessId(pi.hProcess), &protocol_info)) {
		log_err("WSADuplicateSocket failed (%lu).\n", GetLastError());
		ret = INVALID_HANDLE_VALUE;
		goto cleanup;
	}

	/* make a pipe with a unique name based upon processid */
	hpipe = create_named_pipe(pipe_name, 1000);
	if (hpipe == INVALID_HANDLE_VALUE) {
		ret = INVALID_HANDLE_VALUE;
		goto cleanup;
	}

	if (!WriteFile(hpipe, &protocol_info, sizeof(protocol_info), NULL, NULL)) {
		log_err("WriteFile failed (%lu).\n", GetLastError());
		ret = INVALID_HANDLE_VALUE;
		goto cleanup;
	}

	dprint(FD_PROCESS, "process %d created child process %u\n", GetCurrentProcessId(), GetProcessId(pi.hProcess));

	/* monitor the process until it either exits or connects. This level
	 * doesnt care which of those occurs because the result is that it
	 * needs to loop around and create another child process to monitor */
	if (!monitor_process_till_connect(&pi, &hpipe))
		ret = INVALID_HANDLE_VALUE;

cleanup:
	/* close the handles and pipes because this thread is done monitoring them */
	if (ret == INVALID_HANDLE_VALUE)
		CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	DisconnectNamedPipe(hpipe);
	CloseHandle(hpipe);
	return ret;
}




#endif