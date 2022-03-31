#ifndef SYSLOG_H
#define SYSLOG_H

int syslog();

//#define LOG_INFO	0x1
#define LOG_ERROR	0x2
#define LOG_WARN	0x4

#define LOG_NDELAY	0x1
#define LOG_NOWAIT	0x2
#define LOG_PID		0x4
#define LOG_USER	0x8

#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */

#define	LOG_PRIMASK	0x07	/* mask to extract priority part (internal) */
/* extract priority */
#define	LOG_PRI(p)	((p) & LOG_PRIMASK)
#define	LOG_MAKEPRI(fac, pri)	(((fac) << 3) | (pri))

void closelog(void);
void openlog(const char *ident, int logopt, int facility);

#endif /* SYSLOG_H */
