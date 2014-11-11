/************************************************************************/
/* libpkt - A packet dissector library  			        */
/* 								        */
/* Copyright 2014, -TOSH-					        */
/* File coded by -TOSH-	(tosh <at> t0x0sh <dot> org		        */
/* 								        */
/* This file is part of libpkt.					        */
/* 								        */
/* libpkt is free software: you can redistribute it and/or modify       */
/* it under the terms of the GNU General Public License as published by */
/* the Free Software Foundation, either version 3 of the License, or    */
/* (at your option) any later version.				        */
/* 								        */
/* libpkt is distributed in the hope that it will be useful,	        */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of       */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        */
/* GNU General Public License for more details.			        */
/* 								        */
/* You should have received a copy of the GNU General Public License    */
/* along with libpkt.  If not, see <http://www.gnu.org/licenses/>       */
/************************************************************************/


#ifndef DEF_ICMP_H
#define DEF_ICMP_H



/*!
 * \file
 * \brief Implement LAYER_ICMP
 */

#define ICMP_ECHOREPLY		0	/**< Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/**< Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/**< Source Quench		*/
#define ICMP_REDIRECT		5	/**< Redirect (change route)	*/
#define ICMP_ECHO		8	/**< Echo Request		*/
#define ICMP_TIME_EXCEEDED	11	/**< Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/**< Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/**< Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/**< Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/**< Information Request	*/
#define ICMP_INFO_REPLY		16	/**< Information Reply		*/
#define ICMP_ADDRESS		17	/**< Address Mask Request	*/
#define ICMP_ADDRESSREPLY	18	/**< Address Mask Reply		*/
#define NR_ICMP_TYPES		18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/**< Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/**< Host Unreachable		        */
#define ICMP_PROT_UNREACH	2	/**< Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/**< Port Unreachable		        */
#define ICMP_FRAG_NEEDED	4	/**< Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/**< Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/**< Packet filtered */
#define ICMP_PREC_VIOLATION	14	/**< Precedence violation */
#define ICMP_PREC_CUTOFF	15	/**< Precedence cut off */
#define NR_ICMP_UNREACH		15	/**< instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/**< Redirect Net		*/
#define ICMP_REDIR_HOST		1	/**< Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/**< Redirect Net for TOS	*/
#define ICMP_REDIR_HOSTTOS	3	/**< Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/**< TTL count exceeded	        	*/
#define ICMP_EXC_FRAGTIME	1	/**< Fragment Reass time exceeded	*/


/*! ICMP header
 * \private
 */
typedef struct icmp_hdr {
  u8    type;
  u8   	code;
  u16	checksum;
  union {
	struct {
		u16	id;
		u16	sequence;
	} echo;
	u32	gateway;
	struct {
		u16	__unused;
		u16	mtu;
	} frag;
  } un;
}__attribute__((__packed__)) icmp_hdr;


int icmp_get_code(layer_t *l, u8 *type);
int icmp_get_type(layer_t *l, u8 *type);

#endif /* DEF_ICMP_H */
