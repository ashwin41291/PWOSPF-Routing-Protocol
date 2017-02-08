/*-----------------------------------------------------------------------------
 * file:  sr_pwospf.h
 * date:  Tue Nov 23 23:21:22 PST 2004 
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_PWOSPF_H
#define SR_PWOSPF_H

#include <pthread.h>
#include <stdint.h>
#include <time.h>

/* forward declare */
struct sr_instance;

struct pwospf_subsys
{
    /* -- pwospf subsystem state variables here -- */


    /* -- thread and single lock for pwospf subsystem -- */
    pthread_t thread;
    pthread_mutex_t lock;
};

struct neighbour
{
	uint32_t ip;
	time_t currenttime;
	uint32_t rid;
	char* interface;
	int valid;
	struct neighbour* next;
};

struct topology
{
    uint32_t rid;
    uint32_t subnet;
    uint32_t mask;
    uint32_t src;
    uint16_t seqno;
    struct topology *next;
};

int pwospf_init(struct sr_instance* sr);
void sendhello(struct sr_instance* sr);
void sendlsu(struct sr_instance* sr);
void handlehellopackets(struct sr_instance *sr, uint8_t* packet);
struct neighbour* checkneighbour(uint32_t ipAddr);
void printneighbours();
void printtopology();
void updateneighbour(struct sr_instance* sr);
void computegatewayorserver(struct sr_instance *sr, uint8_t* packet);
char* getinterface(struct sr_instance *sr, uint32_t ip);
struct ospfv2_lsu* populateadvertisements(struct sr_instance* sr);
void handlelsupackets(struct sr_instance* sr, uint8_t* packet);
struct sr_rt* routingtablelookup(uint32_t dest, struct sr_instance* sr, int gate);
struct sr_rt* gatewaylookup(struct sr_instance* sr, uint32_t ip);
void updateroutingtable(struct sr_instance* sr, uint32_t ip);
void createroutingtable(struct sr_instance* sr);
void printroutingtable(struct sr_instance *sr);
void addtopologyentry(uint32_t adsubnet, uint32_t adrid, uint32_t	admask, uint32_t srcip, uint16_t adseqno);
int checktopology(uint32_t subnet,uint32_t next_hop);
void printad(struct ospfv2_lsu* lsa);
void bringroutingtable(struct sr_instance* sr, uint32_t ip);

#endif /* SR_PWOSPF_H */
