/* Responses from hook functions. */
#define NF_DROP 0
#define NF_ACCEPT 1
#define NF_STOLEN 2
#define NF_QUEUE 3
#define NF_REPEAT 4
#define NF_STOP 5	/* Deprecated, for userspace nf_queue compatibility. */
#define NF_MAX_VERDICT NF_STOP

#define ICMP_ECHOREPLY		0	/* Echo Reply			*/
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable	*/
#define ICMP_SOURCE_QUENCH	4	/* Source Quench		*/
#define ICMP_REDIRECT		5	/* Redirect (change route)	*/
#define ICMP_ECHO		8	/* Echo Request			*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded		*/
#define ICMP_PARAMETERPROB	12	/* Parameter Problem		*/
#define ICMP_TIMESTAMP		13	/* Timestamp Request		*/
#define ICMP_TIMESTAMPREPLY	14	/* Timestamp Reply		*/
#define ICMP_INFO_REQUEST	15	/* Information Request		*/
#define ICMP_INFO_REPLY		16	/* Information Reply		*/
#define ICMP_ADDRESS		17	/* Address Mask Request		*/
#define ICMP_ADDRESSREPLY	18	/* Address Mask Reply		*/
#define NR_ICMP_TYPES		18


/* Codes for UNREACH. */
#define ICMP_NET_UNREACH	0	/* Network Unreachable		*/
#define ICMP_HOST_UNREACH	1	/* Host Unreachable		*/
#define ICMP_PROT_UNREACH	2	/* Protocol Unreachable		*/
#define ICMP_PORT_UNREACH	3	/* Port Unreachable		*/
#define ICMP_FRAG_NEEDED	4	/* Fragmentation Needed/DF set	*/
#define ICMP_SR_FAILED		5	/* Source Route failed		*/
#define ICMP_NET_UNKNOWN	6
#define ICMP_HOST_UNKNOWN	7
#define ICMP_HOST_ISOLATED	8
#define ICMP_NET_ANO		9
#define ICMP_HOST_ANO		10
#define ICMP_NET_UNR_TOS	11
#define ICMP_HOST_UNR_TOS	12
#define ICMP_PKT_FILTERED	13	/* Packet filtered */
#define ICMP_PREC_VIOLATION	14	/* Precedence violation */
#define ICMP_PREC_CUTOFF	15	/* Precedence cut off */
#define NR_ICMP_UNREACH		15	/* instead of hardcoding immediate value */

/* Codes for REDIRECT. */
#define ICMP_REDIR_NET		0	/* Redirect Net			*/
#define ICMP_REDIR_HOST		1	/* Redirect Host		*/
#define ICMP_REDIR_NETTOS	2	/* Redirect Net for TOS		*/
#define ICMP_REDIR_HOSTTOS	3	/* Redirect Host for TOS	*/

/* Codes for TIME_EXCEEDED. */
#define ICMP_EXC_TTL		0	/* TTL count exceeded		*/
#define ICMP_EXC_FRAGTIME	1	/* Fragment Reass time exceeded	*/

/* Codes for EXT_ECHO (PROBE) */
#define ICMP_EXT_ECHO			42
#define ICMP_EXT_ECHOREPLY		43
#define ICMP_EXT_CODE_MAL_QUERY		1	/* Malformed Query */
#define ICMP_EXT_CODE_NO_IF		2	/* No such Interface */
#define ICMP_EXT_CODE_NO_TABLE_ENT	3	/* No such Table Entry */
#define ICMP_EXT_CODE_MULT_IFS		4	/* Multiple Interfaces Satisfy Query */

/* Constants for EXT_ECHO (PROBE) */
#define ICMP_EXT_ECHOREPLY_ACTIVE	(1 << 2)/* active bit in reply message */
#define ICMP_EXT_ECHOREPLY_IPV4		(1 << 1)/* ipv4 bit in reply message */
#define ICMP_EXT_ECHOREPLY_IPV6		1	/* ipv6 bit in reply message */
#define ICMP_EXT_ECHO_CTYPE_NAME	1
#define ICMP_EXT_ECHO_CTYPE_INDEX	2
#define ICMP_EXT_ECHO_CTYPE_ADDR	3
#define ICMP_AFI_IP			1	/* Address Family Identifier for ipv4 */
#define ICMP_AFI_IP6			2	/* Address Family Identifier for ipv6 */



enum proto_type {
    TCP,
    UDP,
    ICMP
};

struct log_entry {
    __u64 time;
    __u32 sip;
    struct {
        __u32 seq, ack;
        __u16 sport, dport;
    };
    __u8 prot_type;
};