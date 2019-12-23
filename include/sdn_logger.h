#ifndef __SDN_LOGGER_H__
#define __SDN_LOGGER_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#ifdef __cplusplus
	extern "C" {
#endif

typedef enum SDN_LOGGER_TYPE
{
	LOGGER_TYPE_FILE =0,
	LOGGER_TYPE_SYSLOG
}SDN_LOGGER_TYPE;

typedef struct logger
{
	int iFd;
	pid_t pid;
	SDN_LOGGER_TYPE type;
	char *var_buf;
	int loglevel;
	int facility;
	int (*fpOpenLogger)(struct logger *thisptr, char *pcLoggerType, char *filename, int loglevel, int facility);
	int (*fpCloseLogger)(struct logger *thisptr);
	int (*WriteLog)(struct logger *thisptr, int loglevel, char *fmt, ...);
	char buffer[2048];
}Logger;

int OpenLogger(struct logger *thisptr, char *pcLoggerType, char *pcFileName, int loglevel, int facility);
int CloseLogger(struct logger *thisptr);
int WriteLog(struct logger *thisptr, int loglevel, char *fmt, ...);
struct logger * init_logger(struct logger *thisptr, char *pcLoggerType, char *FileName, int loglevel, int facility);
void exit_logger(struct logger *thisptr);
SDN_LOGGER_TYPE GetLoggerType(char *pcLoggerType);

#ifdef __cplusplus
}
#endif
#endif	// __SDN_LOGGER_H__
