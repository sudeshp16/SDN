#include <sdn_logger.h>


/*@Fn GetLoggerType
 *
 * @Params:
 * 	
 * 	@*/
SDN_LOGGER_TYPE GetLoggerType(char *pcLoggerType)
{
	if (strncmp(pcLoggerType, "file", 4) == 0)
		return LOGGER_TYPE_FILE;
	else
		return LOGGER_TYPE_SYSLOG;	
}


int OpenLogger(struct logger *thisptr, char *pcLoggerType, char *pcFileName, int loglevel, int facility)
{
	int fd = -1;
	SDN_LOGGER_TYPE type;
	if (!pcLoggerType)
	{
		// Please Specify Logger type
	  return -1;
	}
	type = GetLoggerType(pcLoggerType);
	thisptr->type = type; 
	if (type == LOGGER_TYPE_FILE)
	{
		fd = open(pcFileName, O_CREAT | O_APPEND, S_IRUSR | S_IWUSR| S_IRGRP| S_IWGRP| S_IWOTH);
		if (fd < 0)
		{
			perror("Failed to initialise Log File\n");
			return -1;
		}
		thisptr->iFd = fd;
	}
	else
	{
		// Syslog
		openlog("SDN",LOG_NDELAY | LOG_PID, facility);
		thisptr->iFd = 0;
	}
	return 0;
}

int CloseLogger(struct logger *thisptr)
{
	if (thisptr->type == LOGGER_TYPE_FILE && thisptr->iFd > 0)
	{
		close(thisptr->iFd);
	}
	else
	{
		closelog();
	}
	return 0;
}



int WriteLog(struct logger *thisptr, int loglevel, char *fmt, ...)
{
	int i = 0;
	if (!thisptr)
		return i;
 	va_list ap;
	char *current_buffer = thisptr->buffer;

    int d;
    char c, *s = NULL;
	char temp[50];
	memset(thisptr->buffer, 0, 2048);
	va_start(ap, fmt);
    while (*fmt)
	{
		if (*fmt == '%')
		{
        	switch (*(fmt+ 1)) 
			{
        		case 's':              
            		s = va_arg(ap, char *);
					strncpy(current_buffer, s, strlen(s));
					current_buffer = current_buffer + strlen(s) + 1;
            		break;
        		case 'd':              /* int */
            		d = va_arg(ap, int);
					sprintf(temp, "%d", d);
					strncpy(current_buffer, temp, strlen(temp));
					current_buffer = current_buffer + strlen(temp) + 1;
            		break;
        		case 'c':              /* char */
            		/* need a cast here since va_arg only takes fully promoted types */
            		c = (char) va_arg(ap, int);
					sprintf(current_buffer, "%c", c);
					current_buffer++;
            		break;
			}
        }
		else
		{
			strncpy(current_buffer, fmt, 1);
			current_buffer++;
		}
		fmt++;
	}
    va_end(ap);
	*current_buffer = '\0';
	printf("FD %d \n", thisptr->iFd);

	if(thisptr->type ==  LOGGER_TYPE_FILE && thisptr->iFd > 0 )
	{
		if (loglevel >= thisptr->loglevel)
			i = write(thisptr->iFd, thisptr->buffer, strlen(thisptr->buffer));
			if (i <= 0)
			{
				printf("FD %d \n", thisptr->iFd);
				perror("Failed to write logs :");
			}
		return i;
	}	
	else
	{
		if (loglevel >= thisptr->loglevel)
			syslog(loglevel, thisptr->buffer);
		return 1;
		
	}
}

struct logger * init_logger(struct logger *thisptr, char *pcLoggerType, char *pcFileName, int loglevel, int facility)
{
	int iRet = -1;
	if (!pcLoggerType)
		return NULL;
	if (!thisptr)
	{
		struct logger * ptr = (struct logger *)malloc(sizeof(struct logger));
		if (!ptr)
			return NULL;
		ptr->fpOpenLogger = OpenLogger;
		ptr->fpCloseLogger = CloseLogger;
		ptr->WriteLog = WriteLog;
		iRet = ptr->fpOpenLogger(ptr, pcLoggerType, pcFileName, loglevel, facility);
		if (iRet != 0)
		{
			free(ptr);
			return NULL;
		}
		return ptr;
	}
 	return thisptr;
}

void exit_logger(struct logger *thisptr)
{
	if (!thisptr)
		return;
	thisptr->fpCloseLogger(thisptr);
	return;
}
