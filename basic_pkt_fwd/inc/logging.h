/* #define PRINTF 1 */
/* #define SYSLOG 1 */
/* #define LOG_LEVEL LOG_DEBUG */

/* #define	LOG_EMERG	0	/\* system is unusable *\/ */
/* #define	LOG_ALERT	1	/\* action must be taken immediately *\/ */
/* #define	LOG_CRIT	2	/\* critical conditions *\/ */
/* #define	LOG_ERR		3	/\* error conditions *\/ */
/* #define	LOG_WARNING	4	/\* warning conditions *\/ */
/* #define	LOG_NOTICE	5	/\* normal but significant condition *\/ */
/* #define	LOG_INFO	6	/\* informational *\/ */
/* #define	LOG_DEBUG	7	/\* debug-level messages *\/ */

#include <syslog.h>
#define LOG(LEVEL, MESSAGE,...)            \
	if (logging_level >= LEVEL) {          \
            if (use_syslog) syslog(LEVEL, MESSAGE, ##__VA_ARGS__);     \
            if (use_printf) fprintf(stderr,"[%s](%s:%d) " MESSAGE ,logging_names[LEVEL], __FILE__, __LINE__,##__VA_ARGS__); \
	}


const char * const logging_names[] = {
        "EMERGENCY",
        "ALERT",
        "PANIC",
        "ERROR",
        "WARNING",
        "NOTICE",
        "INFO",
        "DEBUG"
};

bool use_syslog = true; //overwritten by configuration file
bool use_printf = true;// as well
int logging_level = LOG_DEBUG; //this one also
