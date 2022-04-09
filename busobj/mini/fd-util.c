/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#endif

#include <errno.h>
#include <fcntl.h>
#if defined(__linux__)
#include <linux/btrfs.h>
#include <linux/magic.h>
#endif
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
//#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "io-util.h"
#include "macro.h"
#include "missing_fcntl.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "tmpfile-util.h"
#include "util.h"


int fd_nonblock(int fd, bool nonblock) {

#ifdef WIN32

	//-------------------------
	// Set the socket I/O mode: In this case FIONBIO
	// enables or disables the blocking mode for the 
	// socket based on the numerical value of iMode.
	// If iMode = 0, blocking is enabled; 
	// If iMode != 0, non-blocking mode is enabled.
	u_long iMode = 1;
	int iResult = ioctlsocket(fd, FIONBIO, &iMode);
	if (iResult != NO_ERROR) {
		printf("ioctlsocket failed with error: %ld\n", iResult);
		return RET_NERRNO(iResult);
	}
	return 0;

#else
	int flags, nflags;

	assert(fd >= 0);

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -errno;

	nflags = UPDATE_FLAG(flags, O_NONBLOCK, nonblock);
	if (nflags == flags)
		return 0;

	return RET_NERRNO(fcntl(fd, F_SETFL, nflags));

#endif

}

int fd_cloexec(int fd, bool cloexec) {
#ifdef WIN32
	return 0;
#else
	int flags, nflags;

	assert(fd >= 0);

	flags = fcntl(fd, F_GETFD, 0);
	if (flags < 0)
		return -errno;

	nflags = UPDATE_FLAG(flags, FD_CLOEXEC, cloexec);
	if (nflags == flags)
		return 0;

	return RET_NERRNO(fcntl(fd, F_SETFD, nflags));
#endif
}

int fd_get_path(int fd, char** ret) {

#if ENABLE_FD_GET_PATH
	int r;

	r = readlink_malloc(FORMAT_PROC_FD_PATH(fd), ret);
	if (r == -ENOENT) {
		/* ENOENT can mean two things: that the fd does not exist or that /proc is not mounted. Let's make
		 * things debuggable and distinguish the two. */

		if (proc_mounted() == 0)
			return -ENOSYS;  /* /proc is not available or not set up properly, we're most likely in some chroot
							  * environment. */
		return -EBADF; /* The directory exists, hence it's the fd that doesn't. */
	}

	return r;
#else
	return 0;
#endif
}
