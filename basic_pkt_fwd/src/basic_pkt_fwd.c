/*
 / _____)             _              | |
( (____  _____ ____ _| |_ _____  ____| |__
 \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 _____) ) ____| | | || |_| ____( (___| | | |
(______/|_____)_|_|_| \__)_____)\____)_| |_|
  (C)2013 Semtech-Cycleo

Description:
	Configure Lora concentrator and forward packets to a server

License: Revised BSD License, see LICENSE.TXT file include in the project
Maintainer: Sylvain Miermont
*/


/* -------------------------------------------------------------------------- */
/* --- DEPENDANCIES --------------------------------------------------------- */

/* fix an issue between POSIX and C99 */
#if __STDC_VERSION__ >= 199901L
	#define _XOPEN_SOURCE 600
#else
	#define _XOPEN_SOURCE 500
#endif

#include <stdint.h>		/* C99 types */
#include <stdbool.h>	/* bool type */
#include <stdio.h>		/* printf, fprintf, snprintf, fopen, fputs */


#include <string.h>		/* memset */
#include <signal.h>		/* sigaction */
#include <time.h>		/* time, clock_gettime, strftime, gmtime */
#include <sys/time.h>	/* timeval */
#include <unistd.h>		/* getopt, access */
#include <stdlib.h>		/* atoi, exit */
#include <errno.h>		/* error messages */


#include <sys/socket.h> /* socket specific definitions */
#include <netinet/in.h> /* INET constants and stuff */
#include <arpa/inet.h>  /* IP address conversion stuff */
#include <netdb.h>		/* gai_strerror */

#include <pthread.h>


#include "parson.h"
#include "base64.h"
#include "loragw_hal.h"
#include "loragw_aux.h"
#include "logging.h"


/* -------------------------------------------------------------------------- */
/* --- PRIVATE MACROS ------------------------------------------------------- */

#define ARRAY_SIZE(a)	(sizeof(a) / sizeof((a)[0]))
#define STRINGIFY(x)	#x
#define STR(x)			STRINGIFY(x)
#define MSG(args...)	printf(args) /* message that is destined to the user */
#define TRACE() 		fprintf(stderr, "@ %s %d\n", __FUNCTION__, __LINE__);

/* -------------------------------------------------------------------------- */
/* --- PRIVATE CONSTANTS ---------------------------------------------------- */

#ifndef VERSION_STRING
  #define VERSION_STRING "undefined"
#endif

#define	DEFAULT_SERVER		127.0.0.1 /* hostname also supported */
#define	DEFAULT_PORT_UP		1780
#define	DEFAULT_PORT_DW		1782
#define DEFAULT_KEEPALIVE	5	/* default time interval for downstream keep-alive packet */
#define DEFAULT_STAT		30	/* default time interval for statistics */
#define PUSH_TIMEOUT_MS		100
#define PULL_TIMEOUT_MS		200
#define FETCH_SLEEP_MS		10	/* nb of ms waited when a fetch return no packets */

#define	PROTOCOL_VERSION	1

#define PKT_PUSH_DATA	0
#define PKT_PUSH_ACK	1
#define PKT_PULL_DATA	2
#define PKT_PULL_RESP	3
#define PKT_PULL_ACK	4

#define	NB_PKT_MAX		8 /* max number of packets per fetch/send cycle */

#define MIN_LORA_PREAMB	6 /* minimum Lora preamble length for this application */

#define DOWNSTREAM 1
#define UPSTREAM 0

/* -------------------------------------------------------------------------- */
/* --- PRIVATE VARIABLES (GLOBAL) ------------------------------------------- */

/* signal handling variables */
volatile bool exit_sig = false; /* 1 -> application terminates cleanly (shut down hardware, close open files, etc) */
volatile bool quit_sig = false; /* 1 -> application terminates without shutting down the hardware */

/* packets filtering configuration variables */
static bool fwd_valid_pkt = true; /* packets with PAYLOAD CRC OK are forwarded */
static bool fwd_error_pkt = false; /* packets with PAYLOAD CRC ERROR are NOT forwarded */
static bool fwd_nocrc_pkt = false; /* packets with NO PAYLOAD CRC are NOT forwarded */

/* network configuration variables */
static uint64_t lgwm = 0; /* Lora gateway MAC address */
static char serv_addr[64] = STR(DEFAULT_SERVER); /* address of the server (host name or IPv4/IPv6) */
static char serv_port_up[8] = STR(DEFAULT_PORT_UP); /* server port for upstream traffic */
static char serv_port_down[8] = STR(DEFAULT_PORT_DW); /* server port for downstream traffic */
static int keepalive_time = DEFAULT_KEEPALIVE; /* send a PULL_DATA request every X seconds, negative = disabled */

/* statistics collection configuration variables */
static unsigned stat_interval = DEFAULT_STAT; /* time interval (in sec) at which statistics are collected and displayed */

/* gateway <-> MAC protocol variables */
static uint32_t net_mac_h; /* Most Significant Nibble, network order */
static uint32_t net_mac_l; /* Least Significant Nibble, network order */

/* network sockets */
static int sock_up; /* socket for upstream traffic */
static int sock_down; /* socket for downstream traffic */

/* network protocol variables */
static struct timeval push_timeout_half = {0, (PUSH_TIMEOUT_MS * 500)}; /* cut in half, critical for throughput */
static struct timeval pull_timeout = {0, (PULL_TIMEOUT_MS * 1000)}; /* non critical for throughput */

/* hardware access control and correction */
static pthread_mutex_t mx_concent = PTHREAD_MUTEX_INITIALIZER; /* control access to the concentrator */

/* measurements to establish statistics */
static pthread_mutex_t mx_meas_up = PTHREAD_MUTEX_INITIALIZER; /* control access to the upstream measurements */
static uint32_t meas_nb_rx_rcv = 0; /* count packets received */
static uint32_t meas_nb_rx_ok = 0; /* count packets received with PAYLOAD CRC OK */
static uint32_t meas_nb_rx_bad = 0; /* count packets received with PAYLOAD CRC ERROR */
static uint32_t meas_nb_rx_nocrc = 0; /* count packets received with NO PAYLOAD CRC */
static uint32_t meas_up_pkt_fwd = 0; /* number of radio packet forwarded to the server */
static uint32_t meas_up_network_byte = 0; /* sum of UDP bytes sent for upstream traffic */
static uint32_t meas_up_payload_byte = 0; /* sum of radio payload bytes sent for upstream traffic */
static uint32_t meas_up_dgram_sent = 0; /* number of datagrams sent for upstream traffic */
static uint32_t meas_up_ack_rcv = 0; /* number of datagrams acknowledged for upstream traffic */

static pthread_mutex_t mx_meas_dw = PTHREAD_MUTEX_INITIALIZER; /* control access to the downstream measurements */
static uint32_t meas_dw_pull_sent = 0; /* number of PULL requests sent for downstream traffic */
static uint32_t meas_dw_ack_rcv = 0; /* number of PULL requests acknowledged for downstream traffic */
static uint32_t meas_dw_dgram_rcv = 0; /* count PULL response packets received for downstream traffic */
static uint32_t meas_dw_network_byte = 0; /* sum of UDP bytes sent for upstream traffic */
static uint32_t meas_dw_payload_byte = 0; /* sum of radio payload bytes sent for upstream traffic */
static uint32_t meas_nb_tx_ok = 0; /* count packets emitted successfully */
static uint32_t meas_nb_tx_fail = 0; /* count packets were TX failed for other reasons */

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DECLARATION ---------------------------------------- */

static void sig_handler(int sigio);

int parse_SX1301_configuration(const char * conf_file);

int parse_gateway_configuration(const char * conf_file);

static void dump_json(uint8_t * json_buff, int header_size);

static void dump_packet(const uint8_t* payload,int payload_size, uint8_t * json_buff, int header_size, uint8_t stream);

static int parse_logging_configuration(const char * conf_file);

/* threads */
void thread_up(void);
void thread_down(void);

/* -------------------------------------------------------------------------- */
/* --- PRIVATE FUNCTIONS DEFINITION ----------------------------------------- */


static int parse_logging_configuration(const char * conf_file){
    const char conf_obj_name[] = "logging_conf";
	JSON_Value *root_val;
	JSON_Object *conf_obj = NULL;
	JSON_Value *val = NULL; /* needed to detect the absence of some
                             * fields */
    int temp; /* for checking whether number is in needed range */


    /* try to parse JSON */
	root_val = json_parse_file_with_comments(conf_file);
	if (root_val == NULL) {
		LOG(LOG_ERR,"%s is not a valid JSON file\n", conf_file);
		exit(EXIT_FAILURE);
	}
	
	/* point to the logging configuration object */
	conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
	if (conf_obj == NULL) {
		LOG(LOG_DEBUG,"%s does not contain a JSON object named %s\n", conf_file, conf_obj_name);
		return -1;
	} else {
		LOG(LOG_DEBUG,"%s does contain a JSON object named %s, parsing gateway parameters\n", conf_file, conf_obj_name);
	}


    val = json_object_get_value(conf_obj, "logging_level");
    if(val!=NULL && json_value_get_type(val) == JSONNumber ){
            temp = (uint8_t)json_value_get_number(val);
            if(temp<0 || temp>7 ) {
                    LOG(LOG_WARNING, "The logging level should be between 0-7, please check\n");
            } else{
                    logging_level=temp;
            }
    }
    LOG(LOG_DEBUG, "the logging level is set to %s\n", logging_names[logging_level]);

    val = json_object_get_value(conf_obj, "stdout");
    if(val!=NULL && json_value_get_type(val) == JSONBoolean ){
            use_printf = (bool)json_value_get_boolean(val);
    }
    LOG(LOG_DEBUG, "the output will%s be printed to stdout\n", (use_printf?"":" NOT"));

    val = json_object_get_value(conf_obj, "syslog");
    if(val!=NULL && json_value_get_type(val) == JSONBoolean ){
            use_syslog = (bool)json_value_get_boolean(val);
    }
    LOG(LOG_DEBUG, "the output will%s be sent to syslog\n", (use_syslog?"":" NOT"));

    json_value_free(root_val);
	return 0;

    
        
}
static void sig_handler(int sigio) {
	if (sigio == SIGQUIT) {
		quit_sig = true;;
	} else if ((sigio == SIGINT) || (sigio == SIGTERM)) {
		exit_sig = true;
	}
	return;
}

int parse_SX1301_configuration(const char * conf_file) {
	int i;
	char param_name[32]; /* used to generate variable parameter names */
	const char conf_obj_name[] = "SX1301_conf";
	JSON_Value *root_val = NULL;
	JSON_Object *conf_obj = NULL;
	JSON_Value *val = NULL;
	struct lgw_conf_rxrf_s rfconf;
	struct lgw_conf_rxif_s ifconf;
	uint32_t sf, bw;
	
	/* try to parse JSON */
	root_val = json_parse_file_with_comments(conf_file);
	if (root_val == NULL) {
		LOG(LOG_ERR,"%s is not a valid JSON file\n", conf_file);
		exit(EXIT_FAILURE);
	}
	
	/* point to the gateway configuration object */
	conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
	if (conf_obj == NULL) {
		LOG(LOG_DEBUG,"%s does not contain a JSON object named %s\n", conf_file, conf_obj_name);
		return -1;
	} else {
		LOG(LOG_DEBUG,"%s does contain a JSON object named %s, parsing SX1301 parameters\n", conf_file, conf_obj_name);
	}
	
	/* set configuration for RF chains */
	for (i = 0; i < LGW_RF_CHAIN_NB; ++i) {
		memset(&rfconf, 0, sizeof rfconf); /* initialize configuration structure */
		snprintf(param_name, sizeof param_name, "radio_%i", i); /* compose parameter path inside JSON structure */
		val = json_object_get_value(conf_obj, param_name); /* fetch value (if possible) */
		if (json_value_get_type(val) != JSONObject) {
			LOG(LOG_DEBUG,"no configuration for radio %i\n", i);
			continue;
		}
		/* there is an object to configure that radio, let's parse it */
		snprintf(param_name, sizeof param_name, "radio_%i.enable", i);
		val = json_object_dotget_value(conf_obj, param_name);
		if (json_value_get_type(val) == JSONBoolean) {
			rfconf.enable = (bool)json_value_get_boolean(val);
		} else {
			rfconf.enable = false;
		}
		if (rfconf.enable == false) { /* radio disabled, nothing else to parse */
			LOG(LOG_DEBUG,"radio %i disabled\n", i);
		} else  { /* radio enabled, will parse the other parameters */
			snprintf(param_name, sizeof param_name, "radio_%i.freq", i);
			rfconf.freq_hz = (uint32_t)json_object_dotget_number(conf_obj, param_name);
			LOG(LOG_DEBUG,"radio %i enabled, center frequency %u\n", i, rfconf.freq_hz);
		}
		/* all parameters parsed, submitting configuration to the HAL */
		if (lgw_rxrf_setconf(i, rfconf) != LGW_HAL_SUCCESS) {
                LOG(LOG_WARNING,"invalid configuration for radio %i\n", i);
		}
	}
	
	/* set configuration for Lora multi-SF channels (bandwidth cannot be set) */
	for (i = 0; i < LGW_MULTI_NB; ++i) {
		memset(&ifconf, 0, sizeof ifconf); /* initialize configuration structure */
		snprintf(param_name, sizeof param_name, "chan_multiSF_%i", i); /* compose parameter path inside JSON structure */
		val = json_object_get_value(conf_obj, param_name); /* fetch value (if possible) */
		if (json_value_get_type(val) != JSONObject) {
			LOG(LOG_DEBUG,"no configuration for Lora multi-SF channel %i\n", i);
			continue;
		}
		/* there is an object to configure that Lora multi-SF channel, let's parse it */
		snprintf(param_name, sizeof param_name, "chan_multiSF_%i.enable", i);
		val = json_object_dotget_value(conf_obj, param_name);
		if (json_value_get_type(val) == JSONBoolean) {
			ifconf.enable = (bool)json_value_get_boolean(val);
		} else {
			ifconf.enable = false;
		}
		if (ifconf.enable == false) { /* Lora multi-SF channel disabled, nothing else to parse */
			LOG(LOG_DEBUG,"Lora multi-SF channel %i disabled\n", i);
		} else  { /* Lora multi-SF channel enabled, will parse the other parameters */
			snprintf(param_name, sizeof param_name, "chan_multiSF_%i.radio", i);
			ifconf.rf_chain = (uint32_t)json_object_dotget_number(conf_obj, param_name);
			snprintf(param_name, sizeof param_name, "chan_multiSF_%i.if", i);
			ifconf.freq_hz = (int32_t)json_object_dotget_number(conf_obj, param_name);
			// TODO: handle individual SF enabling and disabling (spread_factor)
			LOG(LOG_DEBUG,"Lora multi-SF channel %i>  radio %i, IF %i Hz, 125 kHz bw, SF 7 to 12\n", i, ifconf.rf_chain, ifconf.freq_hz);
		}
		/* all parameters parsed, submitting configuration to the HAL */
		if (lgw_rxif_setconf(i, ifconf) != LGW_HAL_SUCCESS) {
			LOG(LOG_WARNING,"invalid configuration for Lora multi-SF channel %i\n", i);
		}
	}
	
	/* set configuration for Lora standard channel */
	memset(&ifconf, 0, sizeof ifconf); /* initialize configuration structure */
	val = json_object_get_value(conf_obj, "chan_Lora_std"); /* fetch value (if possible) */
	if (json_value_get_type(val) != JSONObject) {
		LOG(LOG_DEBUG,"no configuration for Lora standard channel\n");
	} else {
		val = json_object_dotget_value(conf_obj, "chan_Lora_std.enable");
		if (json_value_get_type(val) == JSONBoolean) {
			ifconf.enable = (bool)json_value_get_boolean(val);
		} else {
			ifconf.enable = false;
		}
		if (ifconf.enable == false) {
			LOG(LOG_DEBUG,"Lora standard channel %i disabled\n", i);
		} else  {
			ifconf.rf_chain = (uint32_t)json_object_dotget_number(conf_obj, "chan_Lora_std.radio");
			ifconf.freq_hz = (int32_t)json_object_dotget_number(conf_obj, "chan_Lora_std.if");
			bw = (uint32_t)json_object_dotget_number(conf_obj, "chan_Lora_std.bandwidth");
			switch(bw) {
				case 500000: ifconf.bandwidth = BW_500KHZ; break;
				case 250000: ifconf.bandwidth = BW_250KHZ; break;
				case 125000: ifconf.bandwidth = BW_125KHZ; break;
				default: ifconf.bandwidth = BW_UNDEFINED;
			}
			sf = (uint32_t)json_object_dotget_number(conf_obj, "chan_Lora_std.spread_factor");
			switch(sf) {
				case  7: ifconf.datarate = DR_LORA_SF7;  break;
				case  8: ifconf.datarate = DR_LORA_SF8;  break;
				case  9: ifconf.datarate = DR_LORA_SF9;  break;
				case 10: ifconf.datarate = DR_LORA_SF10; break;
				case 11: ifconf.datarate = DR_LORA_SF11; break;
				case 12: ifconf.datarate = DR_LORA_SF12; break;
				default: ifconf.datarate = DR_UNDEFINED;
			}
			LOG(LOG_NOTICE,"Lora std channel> radio %i, IF %i Hz, %u Hz bw, SF %u\n", ifconf.rf_chain, ifconf.freq_hz, bw, sf);
		}
		if (lgw_rxif_setconf(8, ifconf) != LGW_HAL_SUCCESS) {
			LOG(LOG_WARNING,"invalid configuration for Lora standard channel\n");
		}
	}
	
	/* set configuration for FSK channel */
	memset(&ifconf, 0, sizeof ifconf); /* initialize configuration structure */
	val = json_object_get_value(conf_obj, "chan_FSK"); /* fetch value (if possible) */
	if (json_value_get_type(val) != JSONObject) {
		LOG(LOG_DEBUG,"no configuration for FSK channel\n");
	} else {
		val = json_object_dotget_value(conf_obj, "chan_FSK.enable");
		if (json_value_get_type(val) == JSONBoolean) {
			ifconf.enable = (bool)json_value_get_boolean(val);
		} else {
			ifconf.enable = false;
		}
		if (ifconf.enable == false) {
			LOG(LOG_DEBUG,"FSK channel %i disabled\n", i);
		} else  {
			ifconf.rf_chain = (uint32_t)json_object_dotget_number(conf_obj, "chan_FSK.radio");
			ifconf.freq_hz = (int32_t)json_object_dotget_number(conf_obj, "chan_FSK.if");
			bw = (uint32_t)json_object_dotget_number(conf_obj, "chan_FSK.bandwidth");
			if      (bw <= 7800)   ifconf.bandwidth = BW_7K8HZ;
			else if (bw <= 15600)  ifconf.bandwidth = BW_15K6HZ;
			else if (bw <= 31200)  ifconf.bandwidth = BW_31K2HZ;
			else if (bw <= 62500)  ifconf.bandwidth = BW_62K5HZ;
			else if (bw <= 125000) ifconf.bandwidth = BW_125KHZ;
			else if (bw <= 250000) ifconf.bandwidth = BW_250KHZ;
			else if (bw <= 500000) ifconf.bandwidth = BW_500KHZ;
			else ifconf.bandwidth = BW_UNDEFINED;
			ifconf.datarate = (uint32_t)json_object_dotget_number(conf_obj, "chan_FSK.datarate");
			LOG(LOG_DEBUG, "FSK channel> radio %i, IF %i Hz, %u Hz bw, %u bps datarate\n", ifconf.rf_chain, ifconf.freq_hz, bw, ifconf.datarate);
		}
		if (lgw_rxif_setconf(9, ifconf) != LGW_HAL_SUCCESS) {
                LOG(LOG_WARNING,"invalid configuration for FSK channel\n");
		}
	}
	json_value_free(root_val);
	return 0;
}

int parse_gateway_configuration(const char * conf_file) {
	const char conf_obj_name[] = "gateway_conf";
	JSON_Value *root_val;
	JSON_Object *conf_obj = NULL;
	JSON_Value *val = NULL; /* needed to detect the absence of some fields */
	const char *str; /* pointer to sub-strings in the JSON data */
	unsigned long long ull = 0;
	
	/* try to parse JSON */
	root_val = json_parse_file_with_comments(conf_file);
	if (root_val == NULL) {
		LOG(LOG_ERR,"%s is not a valid JSON file\n", conf_file);
		exit(EXIT_FAILURE);
	}
	
	/* point to the gateway configuration object */
	conf_obj = json_object_get_object(json_value_get_object(root_val), conf_obj_name);
	if (conf_obj == NULL) {
		LOG(LOG_DEBUG,"%s does not contain a JSON object named %s\n", conf_file, conf_obj_name);
		return -1;
	} else {
		LOG(LOG_DEBUG,"%s does contain a JSON object named %s, parsing gateway parameters\n", conf_file, conf_obj_name);
	}
	
	/* gateway unique identifier (aka MAC address) (optional) */
	str = json_object_get_string(conf_obj, "gateway_ID");
	if (str != NULL) {
		sscanf(str, "%llx", &ull);
		lgwm = ull;
		LOG(LOG_DEBUG,"gateway MAC address is configured to %016llX\n", ull);
	}
	
	/* server hostname or IP address (optional) */
	str = json_object_get_string(conf_obj, "server_address");
	if (str != NULL) {
		strncpy(serv_addr, str, sizeof serv_addr);
		LOG(LOG_DEBUG,"server hostname or IP address is configured to \"%s\"\n", serv_addr);
	}
	
	/* get up and down ports (optional) */
	val = json_object_get_value(conf_obj, "serv_port_up");
	if (val != NULL) {
		snprintf(serv_port_up, sizeof serv_port_up, "%u", (uint16_t)json_value_get_number(val));
		LOG(LOG_DEBUG,"upstream port is configured to \"%s\"\n", serv_port_up);
	}
	val = json_object_get_value(conf_obj, "serv_port_down");
	if (val != NULL) {
		snprintf(serv_port_down, sizeof serv_port_down, "%u", (uint16_t)json_value_get_number(val));
		LOG(LOG_DEBUG,"downstream port is configured to \"%s\"\n", serv_port_down);
	}
	
	/* get keep-alive interval (in seconds) for downstream (optional) */
	val = json_object_get_value(conf_obj, "keepalive_interval");
	if (val != NULL) {
		keepalive_time = (int)json_value_get_number(val);
		LOG(LOG_DEBUG,"downstream keep-alive interval is configured to %u seconds\n", keepalive_time);
	}
	
	/* get interval (in seconds) for statistics display (optional) */
	val = json_object_get_value(conf_obj, "stat_interval");
	if (val != NULL) {
		stat_interval = (unsigned)json_value_get_number(val);
		LOG(LOG_DEBUG,"statistics display interval is configured to %u seconds\n", stat_interval);
	}
	
	/* get time-out value (in ms) for upstream datagrams (optional) */
	val = json_object_get_value(conf_obj, "push_timeout_ms");
	if (val != NULL) {
		push_timeout_half.tv_usec = 500 * (long int)json_value_get_number(val);
		LOG(LOG_DEBUG,"upstream PUSH_DATA time-out is configured to %u ms\n", (unsigned)(push_timeout_half.tv_usec / 500));
	}
	
	/* packet filtering parameters */
	val = json_object_get_value(conf_obj, "forward_crc_valid");
	if (json_value_get_type(val) == JSONBoolean) {
		fwd_valid_pkt = (bool)json_value_get_boolean(val);
	}
	LOG(LOG_DEBUG,"packets received with a valid CRC will%s be forwarded\n", (fwd_valid_pkt ? "" : " NOT"));
	val = json_object_get_value(conf_obj, "forward_crc_error");
	if (json_value_get_type(val) == JSONBoolean) {
		fwd_error_pkt = (bool)json_value_get_boolean(val);
	}
	LOG(LOG_DEBUG,"packets received with a CRC error will%s be forwarded\n", (fwd_error_pkt ? "" : " NOT"));
	val = json_object_get_value(conf_obj, "forward_crc_disabled");
	if (json_value_get_type(val) == JSONBoolean) {
		fwd_nocrc_pkt = (bool)json_value_get_boolean(val);
	}
	LOG(LOG_DEBUG,"packets received with no CRC will%s be forwarded\n", (fwd_nocrc_pkt ? "" : " NOT"));
	
	/* free JSON parsing data structure */
	json_value_free(root_val);
	return 0;
}


/*  Print out json to stdout/stderr or syslog, depending on local configuration */
static void dump_json(uint8_t * json_buff, int header_size){
        //TODO implement better way to discern between upstream and downstream
        LOG(LOG_INFO,"[%s] JSON : %s \n", (header_size==4? "down":"up"), (char *)(json_buff + header_size));

}

/*  Print out json and payload in HEX to stdout/stderr or syslog, depending on local configuration */
static void dump_packet(const uint8_t* payload,int payload_size, uint8_t * json_buff, int header_size, uint8_t stream){
        
        char hex_buff[2*payload_size+1]; // 1 byte is 2 HEX digits (in
                                      // hex string) +1 for '\0'
        char *ptr_hex = hex_buff; // moving pointer

        dump_json(json_buff,header_size);

        // convert payload to hex string
        for (int i = 0; i <  payload_size; i++)
		{
                ptr_hex += sprintf(ptr_hex,"%02X", payload[i]);
		}

        LOG(LOG_INFO,"[%s]The payload in HEX: %s\n",((stream==UPSTREAM)?"up":"down"), hex_buff);

        
        
}





/* -------------------------------------------------------------------------- */
/* --- MAIN FUNCTION -------------------------------------------------------- */

int main(void)
{

    openlog("basic_pkt_fwd", LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
	struct sigaction sigact; /* SIGQUIT&SIGINT&SIGTERM signal handling */
	int i; /* loop variable and temporary variable for return value */
	
	/* configuration file related */
	char *global_cfg_path= "global_conf.json"; /* contain global (typ. network-wide) configuration */
	char *local_cfg_path = "local_conf.json"; /* contain node specific configuration, overwrite global parameters for parameters that are defined in both */
	char *debug_cfg_path = "debug_conf.json"; /* if present, all other configuration files are ignored */
	
	/* threads */
	pthread_t thrid_up;
	pthread_t thrid_down;
	
	/* network socket creation */
	struct addrinfo hints;
	struct addrinfo *result; /* store result of getaddrinfo */
	struct addrinfo *q; /* pointer to move into *result data */
	char host_name[64];
	char port_name[64];
	
	/* variables to get local copies of measurements */
	uint32_t cp_nb_rx_rcv;
	uint32_t cp_nb_rx_ok;
	uint32_t cp_nb_rx_bad;
	uint32_t cp_nb_rx_nocrc;
	uint32_t cp_up_pkt_fwd;
	uint32_t cp_up_network_byte;
	uint32_t cp_up_payload_byte;
	uint32_t cp_up_dgram_sent;
	uint32_t cp_up_ack_rcv;
	uint32_t cp_dw_pull_sent;
	uint32_t cp_dw_ack_rcv;
	uint32_t cp_dw_dgram_rcv;
	uint32_t cp_dw_network_byte;
	uint32_t cp_dw_payload_byte;
	uint32_t cp_nb_tx_ok;
	uint32_t cp_nb_tx_fail;
	
	/* statistics variable */
	time_t t;
	char stat_timestamp[24];
	float rx_ok_ratio;
	float rx_bad_ratio;
	float rx_nocrc_ratio;
	float up_ack_ratio;
	float dw_ack_ratio;
	
	/* display version informations */
	LOG(LOG_NOTICE,"*** Basic Packet Forwarder for Lora Gateway ***\nVersion: " VERSION_STRING "\n");
	LOG(LOG_NOTICE,"*** Lora concentrator HAL library version info ***\n%s\n***\n", lgw_version_info());
	
	/* display host endianness */
	#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        LOG(LOG_DEBUG,"Little endian host\n");
	#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
		LOG(LOG_DEBUG,"Big endian host\n");
	#else
		LOG(LOG_DEBUG,"Host endianness unknown\n");
	#endif
	
	/* load configuration files */
	if (access(debug_cfg_path, R_OK) == 0) { /* if there is a debug conf, parse only the debug conf */
		LOG(LOG_DEBUG,"found debug configuration file %s, parsing it\n", debug_cfg_path);
		LOG(LOG_DEBUG,"other configuration files will be ignored\n");
		parse_SX1301_configuration(debug_cfg_path);
		parse_gateway_configuration(debug_cfg_path);
	} else if (access(global_cfg_path, R_OK) == 0) { /* if there is a global conf, parse it and then try to parse local conf  */
		LOG(LOG_DEBUG,"found global configuration file %s, parsing it\n", global_cfg_path);
        parse_logging_configuration(global_cfg_path);
		parse_SX1301_configuration(global_cfg_path);
		parse_gateway_configuration(global_cfg_path);
		if (access(local_cfg_path, R_OK) == 0) {
			LOG(LOG_DEBUG,"found local configuration file %s, parsing it\n", local_cfg_path);
			LOG(LOG_DEBUG,"redefined parameters will overwrite global parameters\n");
            parse_logging_configuration(local_cfg_path);
			parse_SX1301_configuration(local_cfg_path);
			parse_gateway_configuration(local_cfg_path);
		}
	} else if (access(local_cfg_path, R_OK) == 0) { /* if there is only a local conf, parse it and that's all */
		LOG(LOG_DEBUG,"found local configuration file %s, parsing it\n", local_cfg_path);
		parse_SX1301_configuration(local_cfg_path);
		parse_gateway_configuration(local_cfg_path);
	} else {
		LOG(LOG_ERR,"[main] failed to find any configuration file named %s, %s OR %s\n", global_cfg_path, local_cfg_path, debug_cfg_path);
		exit(EXIT_FAILURE);
	}
	
	/* sanity check on configuration variables */
	// TODO
	
	/* process some of the configuration variables */
	net_mac_h = htonl((uint32_t)(0xFFFFFFFF & (lgwm>>32)));
	net_mac_l = htonl((uint32_t)(0xFFFFFFFF &  lgwm  ));
	
	/* prepare hints to open network sockets */
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; /* should handle IP v4 or v6 automatically */
	hints.ai_socktype = SOCK_DGRAM;
	
	/* look for server address w/ upstream port */
	i = getaddrinfo(serv_addr, serv_port_up, &hints, &result);
	if (i != 0) {
		LOG(LOG_ERR,"[up] getaddrinfo on address %s (PORT %s) returned %s\n", serv_addr, serv_port_up, gai_strerror(i));
		exit(EXIT_FAILURE);
	}
	
	/* try to open socket for upstream traffic */
	for (q=result; q!=NULL; q=q->ai_next) {
		sock_up = socket(q->ai_family, q->ai_socktype,q->ai_protocol);
		if (sock_up == -1) continue; /* try next field */
		else break; /* success, get out of loop */
	}
	if (q == NULL) {
		LOG(LOG_ERR,"[up] failed to open socket to any of server %s addresses (port %s)\n", serv_addr, serv_port_up);
		i = 1;
		for (q=result; q!=NULL; q=q->ai_next) {
			getnameinfo(q->ai_addr, q->ai_addrlen, host_name, sizeof host_name, port_name, sizeof port_name, NI_NUMERICHOST);
			LOG(LOG_INFO,"[up] result %i host:%s service:%s\n", i, host_name, port_name);
			++i;
		}
		exit(EXIT_FAILURE);
	}
	
	/* connect so we can send/receive packet with the server only */
	i = connect(sock_up, q->ai_addr, q->ai_addrlen);
	if (i != 0) {
		LOG(LOG_ERR,"[up] connect returned %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(result);

	/* look for server address w/ downstream port */
	i = getaddrinfo(serv_addr, serv_port_down, &hints, &result);
	if (i != 0) {
		LOG(LOG_ERR,"[down] getaddrinfo on address %s (port %s) returned %s\n", serv_addr, serv_port_up, gai_strerror(i));
		exit(EXIT_FAILURE);
	}
	
	/* try to open socket for downstream traffic */
	for (q=result; q!=NULL; q=q->ai_next) {
		sock_down = socket(q->ai_family, q->ai_socktype,q->ai_protocol);
		if (sock_down == -1) continue; /* try next field */
		else break; /* success, get out of loop */
	}
	if (q == NULL) {
		LOG(LOG_ERR,"[down] failed to open socket to any of server %s addresses (port %s)\n", serv_addr, serv_port_up);
		i = 1;
		for (q=result; q!=NULL; q=q->ai_next) {
			getnameinfo(q->ai_addr, q->ai_addrlen, host_name, sizeof host_name, port_name, sizeof port_name, NI_NUMERICHOST);
			LOG(LOG_INFO,"[down] result %i host:%s service:%s\n", i, host_name, port_name);
			++i;
		}
		exit(EXIT_FAILURE);
	}
	
	/* connect so we can send/receive packet with the server only */
	i = connect(sock_down, q->ai_addr, q->ai_addrlen);
	if (i != 0) {
		LOG(LOG_ERR,"[down] connect returned %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(result);
	
	/* starting the concentrator */
	i = lgw_start();
	if (i == LGW_HAL_SUCCESS) {
		LOG(LOG_NOTICE,"[main] concentrator started, packet can now be received\n");
	} else {
		LOG(LOG_ERR,"[main] failed to start the concentrator\n");
		exit(EXIT_FAILURE);
	}
	
	/* spawn threads to manage upstream and downstream */
	i = pthread_create( &thrid_up, NULL, (void * (*)(void *))thread_up, NULL);
	if (i != 0) {
		LOG(LOG_ERR,"[main] impossible to create upstream thread\n");
		exit(EXIT_FAILURE);
	}
	i = pthread_create( &thrid_down, NULL, (void * (*)(void *))thread_down, NULL);
	if (i != 0) {
		LOG(LOG_ERR,"[main] impossible to create downstream thread\n");
		exit(EXIT_FAILURE);
	}
	
	/* configure signal handling */
	sigemptyset(&sigact.sa_mask);
	sigact.sa_flags = 0;
	sigact.sa_handler = sig_handler;
	sigaction(SIGQUIT, &sigact, NULL); /* Ctrl-\ */
	sigaction(SIGINT, &sigact, NULL); /* Ctrl-C */
	sigaction(SIGTERM, &sigact, NULL); /* default "kill" command */
	
	/* main loop task : statistics collection */
	while (!exit_sig && !quit_sig) {
		/* wait for next reporting interval */
		wait_ms(1000 * stat_interval);
		
		/* get timestamp for statistics */
		t = time(NULL);
		strftime(stat_timestamp, sizeof stat_timestamp, "%F %T %Z", gmtime(&t));
		
		/* access upstream statistics, copy and reset them */
		pthread_mutex_lock(&mx_meas_up);
		cp_nb_rx_rcv       = meas_nb_rx_rcv;
		cp_nb_rx_ok        = meas_nb_rx_ok;
		cp_nb_rx_bad       = meas_nb_rx_bad;
		cp_nb_rx_nocrc     = meas_nb_rx_nocrc;
		cp_up_pkt_fwd      = meas_up_pkt_fwd;
		cp_up_network_byte = meas_up_network_byte;
		cp_up_payload_byte = meas_up_payload_byte;
		cp_up_dgram_sent   = meas_up_dgram_sent;
		cp_up_ack_rcv      = meas_up_ack_rcv;
		meas_nb_rx_rcv = 0;
		meas_nb_rx_ok = 0;
		meas_nb_rx_bad = 0;
		meas_nb_rx_nocrc = 0;
		meas_up_pkt_fwd = 0;
		meas_up_network_byte = 0;
		meas_up_payload_byte = 0;
		meas_up_dgram_sent = 0;
		meas_up_ack_rcv = 0;
		pthread_mutex_unlock(&mx_meas_up);
		if (cp_nb_rx_rcv > 0) {
			rx_ok_ratio = (float)cp_nb_rx_ok / (float)cp_nb_rx_rcv;
			rx_bad_ratio = (float)cp_nb_rx_bad / (float)cp_nb_rx_rcv;
			rx_nocrc_ratio = (float)cp_nb_rx_nocrc / (float)cp_nb_rx_rcv;
		} else {
			rx_ok_ratio = 0.0;
			rx_bad_ratio = 0.0;
			rx_nocrc_ratio = 0.0;
		}
		if (cp_up_dgram_sent > 0) {
			up_ack_ratio = (float)cp_up_ack_rcv / (float)cp_up_dgram_sent;
		} else {
			up_ack_ratio = 0.0;
		}
		
		/* access downstream statistics, copy and reset them */
		pthread_mutex_lock(&mx_meas_dw);
		cp_dw_pull_sent    =  meas_dw_pull_sent;
		cp_dw_ack_rcv      =  meas_dw_ack_rcv;
		cp_dw_dgram_rcv    =  meas_dw_dgram_rcv;
		cp_dw_network_byte =  meas_dw_network_byte;
		cp_dw_payload_byte =  meas_dw_payload_byte;
		cp_nb_tx_ok        =  meas_nb_tx_ok;
		cp_nb_tx_fail      =  meas_nb_tx_fail;
		meas_dw_pull_sent = 0;
		meas_dw_ack_rcv = 0;
		meas_dw_dgram_rcv = 0;
		meas_dw_network_byte = 0;
		meas_dw_payload_byte = 0;
		meas_nb_tx_ok = 0;
		meas_nb_tx_fail = 0;
		pthread_mutex_unlock(&mx_meas_dw);
		if (cp_dw_pull_sent > 0) {
			dw_ack_ratio = (float)cp_dw_ack_rcv / (float)cp_dw_pull_sent;
		} else {
			dw_ack_ratio = 0.0;
		}
        
		/* display a report */
		LOG(LOG_DEBUG,"\n##### %s #####\n", stat_timestamp);
		LOG(LOG_DEBUG,"### [UPSTREAM] ###\n");
		LOG(LOG_DEBUG,"# RF packets received by concentrator: %u\n", cp_nb_rx_rcv);
		LOG(LOG_DEBUG,"# CRC_OK: %.2f%%, CRC_FAIL: %.2f%%, NO_CRC: %.2f%%\n", 100.0 * rx_ok_ratio, 100.0 * rx_bad_ratio, 100.0 * rx_nocrc_ratio);
		LOG(LOG_DEBUG,"# RF packets forwarded: %u (%u bytes)\n", cp_up_pkt_fwd, cp_up_payload_byte);
		LOG(LOG_DEBUG,"# PUSH_DATA datagrams sent: %u (%u bytes)\n", cp_up_dgram_sent, cp_up_network_byte);
		LOG(LOG_DEBUG,"# PUSH_DATA acknowledged: %.2f%%\n", 100.0 * up_ack_ratio);
		LOG(LOG_DEBUG,"### [DOWNSTREAM] ###\n");
		LOG(LOG_DEBUG,"# PULL_DATA sent: %u (%.2f%% acknowledged)\n", cp_dw_pull_sent, 100.0 * dw_ack_ratio);
		LOG(LOG_DEBUG,"# PULL_RESP(onse) datagrams received: %u (%u bytes)\n", cp_dw_dgram_rcv, cp_dw_network_byte);
		LOG(LOG_DEBUG,"# RF packets sent to concentrator: %u (%u bytes)\n", (cp_nb_tx_ok+cp_nb_tx_fail), cp_dw_payload_byte);
		LOG(LOG_DEBUG,"# TX errors: %u\n", cp_nb_tx_fail);
		LOG(LOG_DEBUG,"##### END #####\n");
	}
	
	/* wait for upstream thread to finish (1 fetch cycle max) */
	pthread_join(thrid_up, NULL);
	pthread_cancel(thrid_down); /* don't wait for downstream thread */
	
	/* if an exit signal was received, try to quit properly */
	if (exit_sig) {
		/* shut down network sockets */
		shutdown(sock_up, SHUT_RDWR);
		shutdown(sock_down, SHUT_RDWR);
		/* stop the hardware */
		i = lgw_stop();
		if (i == LGW_HAL_SUCCESS) {
			LOG(LOG_NOTICE,"concentrator stopped successfully\n");
		} else {
			LOG(LOG_WARNING,"failed to stop concentrator successfully\n");
		}
	}
    closelog();
	LOG(LOG_NOTICE,"Exiting packet forwarder program\n");
	exit(EXIT_SUCCESS);
}

/* -------------------------------------------------------------------------- */
/* --- THREAD 1: RECEIVING PACKETS AND FORWARDING THEM ---------------------- */

void thread_up(void) {
	int i, j; /* loop variables */
	unsigned pkt_in_dgram; /* nb on Lora packet in the current datagram */
	
	/* allocate memory for packet fetching and processing */
	struct lgw_pkt_rx_s rxpkt[NB_PKT_MAX]; /* array containing inbound packets + metadata */
	struct lgw_pkt_rx_s *p; /* pointer on a RX packet */
	int nb_pkt;
	
	/* local timestamp variables until we get accurate GPS time */
	struct timespec fetch_time;
	struct tm * x;
	char fetch_timestamp[28]; /* timestamp as a text string */
	
	/* data buffers */
	uint8_t buff_up[5000]; /* buffer to compose the upstream packet */
	int buff_index;
	uint8_t buff_ack[32]; /* buffer to receive acknowledges */
	
	/* protocol variables */
	uint8_t token_h; /* random token for acknowledgement matching */
	uint8_t token_l; /* random token for acknowledgement matching */
	
	/* set upstream socket RX timeout */
	i = setsockopt(sock_up, SOL_SOCKET, SO_RCVTIMEO, (void *)&push_timeout_half, sizeof push_timeout_half);
	if (i != 0) {
		LOG(LOG_ERR,"[up] setsockopt returned %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	/* pre-fill the data buffer with fixed fields */
	buff_up[0] = PROTOCOL_VERSION;
	buff_up[3] = PKT_PUSH_DATA;
	*(uint32_t *)(buff_up + 4) = net_mac_h;
	*(uint32_t *)(buff_up + 8) = net_mac_l;
	
	while (!exit_sig && !quit_sig) {
	
		/* fetch packets */
		pthread_mutex_lock(&mx_concent);
		nb_pkt = lgw_receive(NB_PKT_MAX, rxpkt);
		pthread_mutex_unlock(&mx_concent);
		if (nb_pkt == LGW_HAL_ERROR) {
			LOG(LOG_ERR,"[up] failed packet fetch, exiting\n");
			exit(EXIT_FAILURE);
		} else if (nb_pkt == 0) {
			wait_ms(FETCH_SLEEP_MS); /* wait a short time if no packets */
			continue;
		}
		
		/* local timestamp generation until we get accurate GPS time */
		clock_gettime(CLOCK_REALTIME, &fetch_time);
		x = gmtime(&(fetch_time.tv_sec)); /* split the UNIX timestamp to its calendar components */
		snprintf(fetch_timestamp, sizeof fetch_timestamp, "%04i-%02i-%02iT%02i:%02i:%02i.%06liZ", (x->tm_year)+1900, (x->tm_mon)+1, x->tm_mday, x->tm_hour, x->tm_min, x->tm_sec, (fetch_time.tv_nsec)/1000); /* ISO 8601 format */
		
		/* start composing datagram with the header */
		token_h = (uint8_t)rand(); /* random token */
		token_l = (uint8_t)rand(); /* random token */
		buff_up[1] = token_h;
		buff_up[2] = token_l;
		buff_index = 12; /* 12-byte header */
		
		/* start of JSON structure */
		memcpy((void *)(buff_up + buff_index), (void *)"{\"rxpk\":[", 9);
		buff_index += 9;
		
		/* serialize Lora packets metadata and payload */
		pkt_in_dgram = 0;
		for (i=0; i < nb_pkt; ++i) {
			p = &rxpkt[i];
			
			/* basic packet filtering */
			pthread_mutex_lock(&mx_meas_up);
			meas_nb_rx_rcv += 1;
			switch(p->status) {
				case STAT_CRC_OK:
					meas_nb_rx_ok += 1;
					if (!fwd_valid_pkt) {
						pthread_mutex_unlock(&mx_meas_up);
						continue; /* skip that packet */
					}
					break;
				case STAT_CRC_BAD:
                        LOG(LOG_NOTICE,"Received packet with bad CRC\n");
					meas_nb_rx_bad += 1;
					if (!fwd_error_pkt) {
						pthread_mutex_unlock(&mx_meas_up);
						continue; /* skip that packet */
					}
					break;
				case STAT_NO_CRC:
                    LOG(LOG_NOTICE,"Received packet with no CRC\n");
					meas_nb_rx_nocrc += 1;
					if (!fwd_nocrc_pkt) {
						pthread_mutex_unlock(&mx_meas_up);
						continue; /* skip that packet */
					}
					break;
				default:
					LOG(LOG_WARNING,"[up] received packet with unknown status %u (size %u, modulation %u, BW %u, DR %u, RSSI %.1f)\n", p->status, p->size, p->modulation, p->bandwidth, p->datarate, p->rssi);
					pthread_mutex_unlock(&mx_meas_up);
					continue; /* skip that packet */
					// exit(EXIT_FAILURE);
			}
			meas_up_pkt_fwd += 1;
			meas_up_payload_byte += p->size;
			pthread_mutex_unlock(&mx_meas_up);
			
			/* Start of packet, add inter-packet separator if necessary */
			if (pkt_in_dgram == 0) {
				buff_up[buff_index] = '{';
				++buff_index;
			} else {
				buff_up[buff_index] = ',';
				buff_up[buff_index+1] = '{';
				buff_index += 2;
			}
			
			/* RAW timestamp */
			j = snprintf((char *)(buff_up + buff_index),19 , "\"tmst\":%u", p->count_us);
			if ((j>=0) && (j < 19)) {
				buff_index += j;
			} else {
				LOG(LOG_ERR,"[up] snprintf failed line %u\n", (__LINE__ - 4));
				exit(EXIT_FAILURE);
			}
			
			/* Packet RX time (system time based) */
			memcpy((void *)(buff_up + buff_index), (void *)",\"time\":\"???????????????????????????\"", 37);
			memcpy((void *)(buff_up + buff_index + 9), (void *)fetch_timestamp, 27);
			buff_index += 37;
			
			/* Packet concentrator channel, RF chain & RX frequency */
			j = snprintf((char *)(buff_up + buff_index),39 , ",\"chan\":%1u,\"rfch\":%1u,\"freq\":%.6lf", p->if_chain, p->rf_chain, ((double)p->freq_hz / 1e6));
			if ((j>=0) && (j < 39)) {
				buff_index += j;
			} else {
				LOG(LOG_ERR,"[up] snprintf failed line %u\n", (__LINE__ - 4));
				exit(EXIT_FAILURE);
			}
			
			/* Packet status */
			switch (p->status) {
				case STAT_CRC_OK:
					memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":1", 9);
					buff_index += 9;
					break;
				case STAT_CRC_BAD:
					memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":-1", 10);
					buff_index += 10;
					break;
				case STAT_NO_CRC:
					memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":0", 9);
					buff_index += 9;
					break;
				default:
					LOG(LOG_ERR,"[up] received packet with unknown status\n");
					memcpy((void *)(buff_up + buff_index), (void *)",\"stat\":?", 9);
					buff_index += 9;
					exit(EXIT_FAILURE);
			}
			
			/* Packet modulation */
			if (p->modulation == MOD_LORA) {
				memcpy((void *)(buff_up + buff_index), (void *)",\"modu\":\"LORA\"", 14);
				buff_index += 14;
				
				/* Lora datarate & bandwidth*/
				switch (p->datarate) {
					case DR_LORA_SF7:
						memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF7", 12);
						buff_index += 12;
						break;
					case DR_LORA_SF8:
						memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF8", 12);
						buff_index += 12;
						break;
					case DR_LORA_SF9:
						memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF9", 12);
						buff_index += 12;
						break;
					case DR_LORA_SF10:
						memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF10", 13);
						buff_index += 13;
						break;
					case DR_LORA_SF11:
						memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF11", 13);
						buff_index += 13;
						break;
					case DR_LORA_SF12:
						memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF12", 13);
						buff_index += 13;
						break;
					default:
						LOG(LOG_ERR,"[up] lora packet with unknown datarate\n");
						memcpy((void *)(buff_up + buff_index), (void *)",\"datr\":\"SF?", 12);
						buff_index += 12;
						exit(EXIT_FAILURE);
				}
				switch (p->bandwidth) {
					case BW_125KHZ:
						memcpy((void *)(buff_up + buff_index), (void *)"BW125\"", 6);
						buff_index += 6;
						break;
					case BW_250KHZ:
						memcpy((void *)(buff_up + buff_index), (void *)"BW250\"", 6);
						buff_index += 6;
						break;
					case BW_500KHZ:
						memcpy((void *)(buff_up + buff_index), (void *)"BW500\"", 6);
						buff_index += 6;
						break;
					default:
						LOG(LOG_ERR,"[up] lora packet with unknown bandwidth\n");
						memcpy((void *)(buff_up + buff_index), (void *)"BW?\"", 4);
						buff_index += 4;
						exit(EXIT_FAILURE);
				}
				
				/* Packet ECC coding rate */
				switch (p->coderate) {
					case CR_LORA_4_5:
						memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/5\"", 13);
						buff_index += 13;
						break;
					case CR_LORA_4_6:
						memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/6\"", 13);
						buff_index += 13;
						break;
					case CR_LORA_4_7:
						memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/7\"", 13);
						buff_index += 13;
						break;
					case CR_LORA_4_8:
						memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"4/8\"", 13);
						buff_index += 13;
						break;
					case 0: /* treat the CR0 case (mostly false sync) */
						memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"OFF\"", 13);
						buff_index += 13;
						break;
					default:
						LOG(LOG_ERR,"[up] lora packet with unknown coderate\n");
						memcpy((void *)(buff_up + buff_index), (void *)",\"codr\":\"?\"", 11);
						buff_index += 11;
						exit(EXIT_FAILURE);
				}
				
				/* Lora SNR */
				j = snprintf((char *)(buff_up + buff_index), 14, ",\"lsnr\":%.1f", p->snr);
				if ((j>=0) && (j < 14)) {
					buff_index += j;
				} else {
					LOG(LOG_ERR,"[up] snprintf failed line %u\n", (__LINE__ - 4));
					exit(EXIT_FAILURE);
				}
			} else if (p->modulation == MOD_FSK) {
				memcpy((void *)(buff_up + buff_index), (void *)",\"modu\":\"FSK\"", 13);
				buff_index += 13;
				
				// TODO: add datarate metadata
			} else {
                    LOG(LOG_ERR,"[up] received packet with unknown modulation\n");
				exit(EXIT_FAILURE);
			}
			
			/* Packet RSSI, payload size */
			j = snprintf((char *)(buff_up + buff_index), 23, ",\"rssi\":%.0f,\"size\":%u", p->rssi, p->size);
			if ((j>=0) && (j < 23)) {
				buff_index += j;
			} else {
				LOG(LOG_ERR,"[up] snprintf failed line %u\n", (__LINE__ - 4));
				exit(EXIT_FAILURE);
			}
			
			/* Packet base64-encoded payload */
			memcpy((void *)(buff_up + buff_index), (void *)",\"data\":\"", 9);
			buff_index += 9;
			j = bin_to_b64(p->payload, p->size, (char *)(buff_up + buff_index), 341); /* 255 bytes = 340 chars in b64 + null char */
			if (j>=0) {
				buff_index += j;
			} else {
				LOG(LOG_ERR,"[up] bin_to_b64 failed line %u\n", (__LINE__ - 5));
				exit(EXIT_FAILURE);
			}
			buff_up[buff_index] = '"';
			++buff_index;
			
			/* End of packet serialization */
			buff_up[buff_index] = '}';
			++buff_index;
			++pkt_in_dgram;
		}
		
		/* restart fetch sequence without sending empty JSON if all packets have been filtered out */
		if (pkt_in_dgram == 0) {
			continue;
		}
		
		/* end of packet array */
		buff_up[buff_index] = ']';
		++buff_index;
		
		/* end of JSON datagram payload */
		buff_up[buff_index] = '}';
		++buff_index;
		buff_up[buff_index] = 0; /* add string terminator, for safety */
		
		//printf("\nJSON up: %s\n", (char *)(buff_up + 12)); /* DEBUG:
		//display JSON payload */
        dump_packet(p->payload, p->size,buff_up,12,UPSTREAM); //header size (before json) is 12
		
		/* send datagram to server */
		send(sock_up, (void *)buff_up, buff_index, 0);
		pthread_mutex_lock(&mx_meas_up);
		meas_up_dgram_sent += 1;
		meas_up_network_byte += buff_index;
		
		/* wait for acknowledge (in 2 times, to catch extra packets) */
		for (i=0; i<2; ++i) {
			j = recv(sock_up, (void *)buff_ack, sizeof buff_ack, 0);
			if (j == -1) {
				if (errno == EAGAIN) { /* timeout */
					continue;
				} else { /* server connection error */
					break;
				}
			} else if ((j < 4) || (buff_ack[0] != PROTOCOL_VERSION) || (buff_ack[3] != PKT_PUSH_ACK)) {
				//MSG("WARNING: [up] ignored invalid non-ACL packet\n");
				continue;
			} else if ((buff_ack[1] != token_h) || (buff_ack[2] != token_l)) {
				//MSG("WARNING: [up] ignored out-of sync ACK packet\n");
				continue;
			} else {
				//MSG("INFO: [up] ACK received :)\n"); /* too verbose */
				meas_up_ack_rcv += 1;
				break;
			}
		}
		pthread_mutex_unlock(&mx_meas_up);
	}
	LOG(LOG_DEBUG,"\n End of upstream thread\n");
}

/* -------------------------------------------------------------------------- */
/* --- THREAD 2: POLLING SERVER AND EMITTING PACKETS ------------------------ */

void thread_down(void) {
	int i; /* loop variables */
	
	/* configuration and metadata for an outbound packet */
	struct lgw_pkt_tx_s txpkt;
	bool sent_immediate = false; /* option to sent the packet immediately */
	
	/* local timekeeping variables */
	time_t now; /* current time, with second accuracy */
	time_t requ_time; /* time of the pull request, low-res OK */
	
	/* data buffers */
	uint8_t buff_down[1000]; /* buffer to receive downstream packets */
	uint8_t buff_req[12]; /* buffer to compose pull requests */
	int msg_len;
	
	/* protocol variables */
	uint8_t token_h; /* random token for acknowledgement matching */
	uint8_t token_l; /* random token for acknowledgement matching */
	bool req_ack = false; /* keep track of whether PULL_DATA was acknowledged or not */
	
	/* JSON parsing variables */
	JSON_Value *root_val = NULL;
	JSON_Object *txpk_obj = NULL;
	JSON_Value *val = NULL; /* needed to detect the absence of some fields */
	const char *str; /* pointer to sub-strings in the JSON data */
	short x0, x1;
	
	/* set downstream socket RX timeout */
	i = setsockopt(sock_down, SOL_SOCKET, SO_RCVTIMEO, (void *)&pull_timeout, sizeof pull_timeout);
	if (i != 0) {
		LOG(LOG_ERR,"[down] setsockopt returned %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	/* pre-fill the pull request buffer with fixed fields */
	buff_req[0] = PROTOCOL_VERSION;
	buff_req[3] = PKT_PULL_DATA;
	*(uint32_t *)(buff_req + 4) = net_mac_h;
	*(uint32_t *)(buff_req + 8) = net_mac_l;
	
	while (!exit_sig && !quit_sig) {
		/* generate random token for request */
		token_h = (uint8_t)rand(); /* random token */
		token_l = (uint8_t)rand(); /* random token */
		buff_req[1] = token_h;
		buff_req[2] = token_l;
		
		/* send PULL request and record time */
		send(sock_down, (void *)buff_req, sizeof buff_req, 0);
		pthread_mutex_lock(&mx_meas_dw);
		meas_dw_pull_sent += 1;
		pthread_mutex_unlock(&mx_meas_dw);
		req_ack = false;
		
		/* listen to packets and process them until a new PULL request must be sent */
		for (time(&requ_time); (int)difftime(now, requ_time) < keepalive_time; time(&now)) {
			
			/* try to receive a datagram */
			msg_len = recv(sock_down, (void *)buff_down, (sizeof buff_down)-1, 0);
			
			/* if no network message was received, got back to listening sock_down socket */
			if (msg_len == -1) {
				//LOG(LOG_WARNING,"[down] recv returned %s\n", strerror(errno)); /* too verbose */
				continue;
			}
			
			/* if the datagram does not respect protocol, just ignore it */
			if ((msg_len < 4) || (buff_down[0] != PROTOCOL_VERSION) || ((buff_down[3] != PKT_PULL_RESP) && (buff_down[3] != PKT_PULL_ACK))) {
				LOG(LOG_WARNING,"[down] ignoring invalid packet\n");
				continue;
			}
			
			/* if the datagram is an ACK, check token */
			if (buff_down[3] == PKT_PULL_ACK) {
				if ((buff_down[1] == token_h) && (buff_down[2] == token_l)) {
					if (req_ack) {
						LOG(LOG_DEBUG,"[down] duplicate ACK received :)\n");
					} else { /* if that packet was not already acknowledged */
						req_ack = true;
						pthread_mutex_lock(&mx_meas_dw);
						meas_dw_ack_rcv += 1;
						pthread_mutex_unlock(&mx_meas_dw);
						LOG(LOG_DEBUG,"[down] ACK received :)\n"); /* very verbose */
					}
				} else { /* out-of-sync token */
					LOG(LOG_DEBUG,"[down] received out-of-sync ACK\n");
				}
				continue;
			}
			
			/* the datagram is a PULL_RESP */
			buff_down[msg_len] = 0; /* add string terminator, just to be safe */
			LOG(LOG_DEBUG,"[down] PULL_RESP received :)\n"); /* very verbose */
			// printf("\nJSON down: %s\n", (char *)(buff_down + 4));
			// /* DEBUG: display JSON payload */

			
			/* initialize TX struct and try to parse JSON */
			memset(&txpkt, 0, sizeof txpkt);
			root_val = json_parse_string_with_comments((const char *)(buff_down + 4)); /* JSON offset */
			if (root_val == NULL) {
				MSG("WARNING: [down] invalid JSON, TX aborted\n");
				continue;
			}
			
			/* look for JSON sub-object 'txpk' */
			txpk_obj = json_object_get_object(json_value_get_object(root_val), "txpk");
			if (txpk_obj == NULL) {
				MSG("WARNING: [down] no \"txpk\" object in JSON, TX aborted\n");
				json_value_free(root_val);
				continue;
			}
			
			/* Parse "immediate" tag, or target timestamp, or UTC time to be converted by GPS (mandatory) */
			i = json_object_get_boolean(txpk_obj,"imme"); /* can be 1 if true, 0 if false, or -1 if not a JSON boolean */
			if (i == 1) {
				/* TX procedure: send immediately */
				sent_immediate = true;
				LOG(LOG_DEBUG,"[down] a packet will be sent in \"immediate\" mode\n");
			} else {
				sent_immediate = false;
				val = json_object_get_value(txpk_obj,"tmst");
				if (val != NULL) {
					/* TX procedure: send on timestamp value */
					txpkt.count_us = (uint32_t)json_value_get_number(val);
					LOG(LOG_INFO,"[down] a packet will be sent on timestamp value %u\n", txpkt.count_us);
				} else {
					LOG(LOG_WARNING,"[down] only \"immediate\" and \"timestamp\" modes supported, TX aborted\n");
					json_value_free(root_val);
					continue;
				}
			}
			
			/* Parse "No CRC" flag (optional field) */
			val = json_object_get_value(txpk_obj,"ncrc");
			if (val != NULL) {
				txpkt.no_crc = (bool)json_value_get_boolean(val);
			}
			
			/* parse target frequency (mandatory) */
			val = json_object_get_value(txpk_obj,"freq");
			if (val == NULL) {
				LOG(LOG_WARNING,"[down] no mandatory \"txpk.freq\" object in JSON, TX aborted\n");
				json_value_free(root_val);
				continue;
			}
			txpkt.freq_hz = (uint32_t)(1e6 * json_value_get_number(val));
			
			/* parse RF chain used for TX (mandatory) */
			val = json_object_get_value(txpk_obj,"rfch");
			if (val == NULL) {
				LOG(LOG_WARNING,"[down] no mandatory \"txpk.rfch\" object in JSON, TX aborted\n");
				json_value_free(root_val);
				continue;
			}
			txpkt.rf_chain = (uint8_t)json_value_get_number(val);
			
			/* parse TX power (optional field) */
			val = json_object_get_value(txpk_obj,"powe");
			if (val != NULL) {
				txpkt.rf_power = (int8_t)json_value_get_number(val);
			}
			
			/* Parse modulation (mandatory) */
			str = json_object_get_string(txpk_obj, "modu");
			if (str == NULL) {
				LOG(LOG_WARNING,"[down] no mandatory \"txpk.modu\" object in JSON, TX aborted\n");
				json_value_free(root_val);
				continue;
			}
			if (strcmp(str, "LORA") == 0) {
				/* Lora modulation */
				txpkt.modulation = MOD_LORA;
				
				/* Parse Lora spreading-factor and modulation bandwidth (mandatory) */
				str = json_object_get_string(txpk_obj, "datr");
				if (str == NULL) {
					LOG(LOG_WARNING,"[down] no mandatory \"txpk.datr\" object in JSON, TX aborted\n");
					json_value_free(root_val);
					continue;
				}
				i = sscanf(str, "SF%2hdBW%3hd", &x0, &x1);
				if (i != 2) {
					LOG(LOG_WARNING,"[down] format error in \"txpk.datr\", TX aborted\n");
					json_value_free(root_val);
					continue;
				}
				switch (x0) {
					case  7: txpkt.datarate = DR_LORA_SF7;  break;
					case  8: txpkt.datarate = DR_LORA_SF8;  break;
					case  9: txpkt.datarate = DR_LORA_SF9;  break;
					case 10: txpkt.datarate = DR_LORA_SF10; break;
					case 11: txpkt.datarate = DR_LORA_SF11; break;
					case 12: txpkt.datarate = DR_LORA_SF12; break;
					default:
						LOG(LOG_WARNING,"[down] format error in \"txpk.datr\", invalid SF, TX aborted\n");
						json_value_free(root_val);
						continue;
				}
				switch (x1) {
					case 125: txpkt.bandwidth = BW_125KHZ; break;
					case 250: txpkt.bandwidth = BW_250KHZ; break;
					case 500: txpkt.bandwidth = BW_500KHZ; break;
					default:
						LOG(LOG_WARNING,"[down] format error in \"txpk.datr\", invalid BW, TX aborted\n");
						json_value_free(root_val);
						continue;
				}
				
				/* Parse ECC coding rate (optional field) */
				str = json_object_get_string(txpk_obj, "codr");
				if (str == NULL) {
					LOG(LOG_WARNING,"[down] no mandatory \"txpk.codr\" object in json, TX aborted\n");
					json_value_free(root_val);
					continue;
				}
				if      (strcmp(str, "4/5") == 0) txpkt.coderate = CR_LORA_4_5;
				else if (strcmp(str, "4/6") == 0) txpkt.coderate = CR_LORA_4_6;
				else if (strcmp(str, "2/3") == 0) txpkt.coderate = CR_LORA_4_6;
				else if (strcmp(str, "4/7") == 0) txpkt.coderate = CR_LORA_4_7;
				else if (strcmp(str, "4/8") == 0) txpkt.coderate = CR_LORA_4_8;
				else if (strcmp(str, "1/2") == 0) txpkt.coderate = CR_LORA_4_8;
				else {
					LOG(LOG_WARNING,"[down] format error in \"txpk.codr\", TX aborted\n");
					json_value_free(root_val);
					continue;
				}
				
				/* Parse signal polarity switch (optional field) */
				val = json_object_get_value(txpk_obj,"ipol");
				if (val != NULL) {
					txpkt.invert_pol = (bool)json_value_get_boolean(val);
				}
				
				/* parse Lora preamble length (optional field, optimum min value enforced) */
				val = json_object_get_value(txpk_obj,"prea");
				if (val != NULL) {
					i = (int)json_value_get_number(val);
					if (i >= MIN_LORA_PREAMB) {
						txpkt.preamble = (uint16_t)i;
					} else {
						txpkt.preamble = (uint16_t)MIN_LORA_PREAMB;
					}
				} else {
					txpkt.preamble = (uint16_t)MIN_LORA_PREAMB;
				}
				
			} else if (strcmp(str, "FSK") == 0) {
				/* FSK modulation */
				txpkt.modulation = MOD_FSK;
				
				// TODO
				MSG("WARNING: [down] FSK modulation not supported yet, TX aborted\n");
				json_value_free(root_val);
				continue;
				
				/* parse TX preamble length (optional field) */
				//val = json_object_get_value(txpk_obj,"prea");
				//if (val != NULL) {
				//	txpkt.preamble = (uint16_t)json_value_get_number(val);
				//}
				
			} else {
				LOG(LOG_WARNING,"[down] invalid modulation in \"txpk.modu\", TX aborted\n");
				json_value_free(root_val);
				continue;
			}
			
			/* Parse payload length (mandatory) */
			val = json_object_get_value(txpk_obj,"size");
			if (val == NULL) {
				LOG(LOG_WARNING,"[down] no mandatory \"txpk.size\" object in JSON, TX aborted\n");
				json_value_free(root_val);
				continue;
			}
			txpkt.size = (uint16_t)json_value_get_number(val);
			
			/* Parse payload data (mandatory) */
			str = json_object_get_string(txpk_obj, "data");
			if (str == NULL) {
				LOG(LOG_WARNING,"[down] no mandatory \"txpk.data\" object in JSON, TX aborted\n");
				json_value_free(root_val);
				continue;
			}


			i = b64_to_bin(str, strlen(str), txpkt.payload, sizeof txpkt.payload);
			if (i != txpkt.size) {
				LOG(LOG_WARNING,"[down] mismatch between .size and .data size once converter to binary\n");
			}
            //pass the same fields as when doing for upstream
            //just here we are reading them from the json we recieved
            //from nodeG, and in a structure appropriate for sending
            //and there we were putting them in a json to send to
            //NodeG
            //header size before json is 4
            dump_packet(txpkt.payload,txpkt.size,buff_down,4,DOWNSTREAM); 
			
			/* free the JSON parse tree from memory */
			json_value_free(root_val);
			
			/* select TX mode */
			if (sent_immediate) {
				txpkt.tx_mode = IMMEDIATE;
			} else {
				txpkt.tx_mode = TIMESTAMPED;
			}
			
			/* record measurement data */
			pthread_mutex_lock(&mx_meas_dw);
			meas_dw_dgram_rcv += 1; /* count only datagrams with no JSON errors */
			meas_dw_network_byte += msg_len; /* meas_dw_network_byte */
			meas_dw_payload_byte += txpkt.size;
			
			/* transfer data and metadata to the concentrator, and schedule TX */
			pthread_mutex_lock(&mx_concent); /* may have to wait for a fetch to finish */
			i = lgw_send(txpkt);
			pthread_mutex_unlock(&mx_concent); /* free concentrator ASAP */
			if (i == LGW_HAL_ERROR) {
				meas_nb_tx_fail += 1;
				pthread_mutex_unlock(&mx_meas_dw);
				LOG(LOG_WARNING,"[down] lgw_send failed\n");
				continue;
			} else {
				meas_nb_tx_ok += 1;
				pthread_mutex_unlock(&mx_meas_dw);
			}
		}
	}
	LOG(LOG_DEBUG,"End of downstream thread\n");
}

/* --- EOF ------------------------------------------------------------------ */
