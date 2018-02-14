/**
 *  File: loadenv.h
 *
 *  Environment load functions
 */

#include <regex.h>
#include <stdlib.h>
#include <inttypes.h>

#ifndef MACROS_H
#include "macros.h"
#endif


struct envstruct {
	uint8_t dinetaddr[IP_ALEN];
	uint8_t sinetaddr[IP_ALEN];
	uint8_t dhwaddr[ETH_ALEN];
	uint8_t shwaddr[ETH_ALEN];
	uint8_t whwaddr[ETH_ALEN];
	uint16_t dport; // htons
	uint16_t sport; // htons
};

/**
 * Name:  load_envs
 * Desc:  Load neccesary environment variables
 * Parm:
 *        env   Structure containing the environment variables
 */
int load_envs(struct envstruct *env);
