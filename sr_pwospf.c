/*-----------------------------------------------------------------------------
 * file: sr_pwospf.c
 * date: Tue Nov 23 23:24:18 PST 2004
 * Author: Martin Casado
 *
 * Description:
 *
 *---------------------------------------------------------------------------*/

#include "sr_pwospf.h"
#include "sr_router.h"
#include "pwospf_protocol.h"
#include "sr_protocol.h"
#include "sr_if.h"
#include "sr_rt.h"

#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


/* -- declaration of main thread function for pwospf subsystem --- */
static void* pwospf_run_thread(void* arg);
static int seqnum = 0;
static int entered = 0;
struct neighbour *first = NULL;
struct topology *topofirst=NULL;
struct sr_rt *rtfirst=NULL;
struct sr_rt *staticentry=NULL;
pthread_mutex_t neighbour;
pthread_mutex_t sr_rt;

/*---------------------------------------------------------------------
 * Method: pwospf_init(..)
 *
 * Sets up the internal data structures for the pwospf subsystem
 *
 * You may assume that the interfaces have been created and initialized
 * by this point.
 *---------------------------------------------------------------------*/

int pwospf_init(struct sr_instance* sr)
{
    assert(sr);

    sr->ospf_subsys = (struct pwospf_subsys*)malloc(sizeof(struct
                                                      pwospf_subsys));

    assert(sr->ospf_subsys);
    pthread_mutex_init(&(sr->ospf_subsys->lock), 0);
	pthread_mutex_init(&neighbour,0);
	pthread_mutex_init(&sr_rt,0);

    /* -- handle subsystem initialization here! -- */
    pthread_t* hellothread;
   	pthread_t* lsuthread;
    pthread_t* updateneighbourthread;
    
    /* -- start thread subsystem -- */
    if( pthread_create(&sr->ospf_subsys->thread, 0, pwospf_run_thread, sr)) {
        perror("pthread_create");
        assert(0);
    }

	pthread_create((void*)&hellothread,NULL,(void*)&sendhello,sr);
    pthread_create((void*)&updateneighbourthread,NULL,(void*)&updateneighbour,sr);
    pthread_create((void*)&lsuthread,NULL,(void*)&sendlsu,sr);
    return 0; /* success */
} /* -- pwospf_init -- */


/*---------------------------------------------------------------------
 * Method: pwospf_lock
 *
 * Lock mutex associated with pwospf_subsys
 *
 *---------------------------------------------------------------------*/

void pwospf_lock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_lock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_unlock
 *
 * Unlock mutex associated with pwospf subsystem
 *
 *---------------------------------------------------------------------*/

void pwospf_unlock(struct pwospf_subsys* subsys)
{
    if ( pthread_mutex_unlock(&subsys->lock) )
    { assert(0); }
} /* -- pwospf_subsys -- */

/*---------------------------------------------------------------------
 * Method: pwospf_run_thread
 *
 * Main thread of pwospf subsystem.
 *
 *---------------------------------------------------------------------*/

static void* pwospf_run_thread(void* arg)
{
    struct sr_instance* sr = (struct sr_instance*)arg;

    while(1)
    {
        /* -- PWOSPF subsystem functionality should start  here! -- */

        pwospf_lock(sr->ospf_subsys);
        //printf(" pwospf subsystem sleeping \n");
        pwospf_unlock(sr->ospf_subsys);
        sleep(2);
        //printf(" pwospf subsystem awake \n");
    }
} /* -- run_ospf_thread -- */

/*---------------------------------------------------------------------
 * Method: sendhello
 *
 * Sends hello packets periodically
 *
 *---------------------------------------------------------------------*/

void sendhello(struct sr_instance* sr)
{
	while(1)
	{
	sleep(OSPF_DEFAULT_HELLOINT);
	pthread_mutex_lock(&neighbour);
	printf("Sending hello\n");
	struct sr_ethernet_hdr* ethhdr = ((struct sr_ethernet_hdr*)
									(malloc(sizeof(struct sr_ethernet_hdr))));
    struct ip* iphdr = ((struct ip*)(malloc(sizeof(struct ip))));
    struct ospfv2_hdr* ospfhdr = ((struct ospfv2_hdr*)(malloc(sizeof(struct ospfv2_hdr))));
    struct ospfv2_hello_hdr* hellohdr = ((struct ospfv2_hello_hdr*)
    									(malloc(sizeof(struct ospfv2_hello_hdr))));
    
    ethhdr->ether_type =  htons(ETHERTYPE_IP);
    int i;
    for (i = 0; i < ETHER_ADDR_LEN; i++)
	{
		ethhdr->ether_dhost[i] = htons(0xff);
	}
	
	iphdr->ip_dst.s_addr = htonl(OSPF_AllSPFRouters);
	iphdr->ip_hl = 5;
	iphdr->ip_v = 4;
	iphdr->ip_tos = 0;
	iphdr->ip_off = IP_DF;
	iphdr->ip_id = rand();
	iphdr->ip_ttl = 64;
	iphdr->ip_p = 89;
	iphdr->ip_len = htons(sizeof(struct ip) + sizeof(struct ospfv2_hdr) +
											(sizeof(struct ospfv2_hello_hdr)));
	
	ospfhdr->aid = 1;
    ospfhdr->autype = 0;
    ospfhdr->audata = 0;
    ospfhdr->version = 2;
    ospfhdr->type = OSPF_TYPE_HELLO;
    ospfhdr->len = htons(sizeof(struct ospfv2_hdr) + (sizeof(struct ospfv2_hello_hdr)));
    
    hellohdr->nmask = htonl(0xffffff00);
    hellohdr->helloint = OSPF_DEFAULT_HELLOINT;
    hellohdr->padding = 0;	
    
    struct sr_if* iflist = sr->if_list;
    while(iflist)
    {
    	for (i = 0; i < ETHER_ADDR_LEN; i++)
		{
			ethhdr->ether_shost[i] = iflist->addr[i];
		}
		struct in_addr temp1;
		temp1.s_addr = iflist->ip;
		iphdr->ip_src = temp1;
		iphdr->ip_sum = 0;
		iphdr->ip_sum = checksum((uint16_t*)iphdr, sizeof(struct ip));
    	
    	ospfhdr->rid = iflist->ip;
    	ospfhdr->csum = 0;
    	
    	uint8_t * pkt = malloc(sizeof(struct sr_ethernet_hdr)+ iphdr->ip_len);
    	
    	memcpy(pkt, ethhdr, sizeof(struct sr_ethernet_hdr));
    	memcpy(pkt + sizeof(struct sr_ethernet_hdr), iphdr, sizeof(struct ip));
    	memcpy(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), 
    							ospfhdr, sizeof(struct ospfv2_hdr));
    	memcpy(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + 
    				sizeof(struct ospfv2_hdr), hellohdr, sizeof(struct ospfv2_hello_hdr));
 		
 		ospfhdr->csum = checksum((uint16_t*)ospfhdr, sizeof(struct ospfv2_hdr) + 
 													sizeof(struct ospfv2_hello_hdr));
 		sr_send_packet(sr, pkt, (sizeof(struct sr_ethernet_hdr)+ sizeof(struct ip)+ 
 			sizeof(struct ospfv2_hdr)+ sizeof(struct ospfv2_hello_hdr)), iflist->name);
 		
 		free(pkt);   
 		iflist = iflist->next;    	
	}
	printf("Finished Hello\n");
	pthread_mutex_unlock(&neighbour);
	}
}
/*---------------------------------------------------------------------
 * Method: handlehellopackets
 *
 * used to handle the incoming hello packets
 *
 *---------------------------------------------------------------------*/
void handlehellopackets(struct sr_instance *sr, uint8_t* packet)
{
	pthread_mutex_lock(&neighbour);
	printf("Coming to hellopackets\n");
	struct ip* iphdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	if (checkneighbour(iphdr->ip_src.s_addr)!=NULL)
	{
		struct neighbour* temp = checkneighbour(iphdr->ip_src.s_addr);
		printf("Neighbour Address Exists\n");
		temp->currenttime = time(NULL);
		if(temp->rid == 0)
		{
			temp->rid = temp->ip;
			temp->valid = 1;
			bringroutingtable(sr, temp->ip);
		}
		struct neighbour* temp1 = first;
		while(temp1)
		{
			if(temp1->valid == 0)
			{
				temp1->currenttime = time(NULL);
			}
			temp1 = temp1->next;
		}
	}
	else
	{
		struct neighbour* temp = (struct neighbour*)malloc(sizeof(struct neighbour));
		if(temp!=NULL)
		{
			temp->ip = iphdr->ip_src.s_addr;
			temp->currenttime = time(NULL);
			temp->rid = iphdr->ip_src.s_addr;
			temp->valid = 1;
			temp->interface = getinterface(sr, iphdr->ip_src.s_addr);
			temp->next = first;
			first = temp;		
		}
		else
		{
			printf("malloc in neighbour caching failed\n");
			exit(-1);
		}
	}
	computegatewayorserver(sr, packet);
	printneighbours();
	pthread_mutex_unlock(&neighbour);
}

/*---------------------------------------------------------------------
 * Method: computegatewayorserver
 *
 * Adds the gateway or server entry into the neighbour table
 *
 *---------------------------------------------------------------------*/
void computegatewayorserver(struct sr_instance *sr, uint8_t* packet)
{
	int entries = 0;
	struct neighbour* temp = first;
	while(temp)
	{
		entries++;
		temp = temp->next;
	}
	if(entries == 2)
	{
		struct sr_if* loneinterface = sr->if_list;
		while(loneinterface)
		{
			struct neighbour* temp1 = first;
			while(temp1)
			{
				if(strcmp(temp1->interface, loneinterface->name) == 0)
				{
					break;
				}
				temp1 = temp1->next;
			}
			if(temp1 == NULL)
			{
				struct neighbour* newnode = (struct neighbour*)
											malloc(sizeof(struct neighbour));
				uint32_t ip = 0;
				if(newnode!=NULL)
				{
					struct sr_rt *routingtable = sr->routing_table;
					while(routingtable)
					{
						ip = routingtable->gw.s_addr;
						routingtable = routingtable->next;
					}
					if(ip!=0)
					{
						newnode->ip = ip;
						newnode->currenttime = time(NULL);
						newnode->rid = 0;
						newnode->valid = 0;
						newnode->interface = loneinterface->name;
						newnode->next = first;
						first = newnode;
					}
					else
					{
						newnode->ip = loneinterface->ip;
						newnode->currenttime = time(NULL);
						newnode->rid = 0;
						newnode->valid = 0;
						newnode->interface = loneinterface->name;
						newnode->next = first;
						first = newnode;
					}
				}
				else
				{
					printf("malloc in newnode neighbour caching failed\n");
					exit(-1);
				}
			}
			loneinterface = loneinterface->next;
		}
	}
	
}

/*---------------------------------------------------------------------
 * Method: checkneighbour
 *
 * Checks whether the given neighbour exits in the table or not
 *
 *---------------------------------------------------------------------*/
struct neighbour* checkneighbour(uint32_t ipAddr)
{	
	struct neighbour *temp = first;
	while (temp) {
		if (temp->ip == ipAddr)
		{
			return temp;
		}
		temp = temp->next;
	}
	return NULL;
}
/*---------------------------------------------------------------------
 * Method: getinterface
 *
 * used to find the interface for the incoming ip
 *
 *---------------------------------------------------------------------*/
char* getinterface(struct sr_instance *sr, uint32_t ip)
{
	struct sr_if *iflist = sr->if_list;
	int max = 0;
	char *intf;
	while (iflist)
	{
		if ((iflist->ip & ip) > max)
		{
			max = iflist->ip & ip;
			intf = iflist->name;
		}
		iflist = iflist->next;
	}
	return intf;
}
/*---------------------------------------------------------------------
 * Method: printneighbours
 *
 * prints the neighbour table
 *
 *---------------------------------------------------------------------*/

void printneighbours() 
{
	struct neighbour *temp = first;
	struct in_addr iptemp;
	while (temp) 
	{
		iptemp.s_addr = temp->ip;
		printf("IP is %s\n",  inet_ntoa(iptemp));
		printf("Interface is %s\n",  temp->interface);
		iptemp.s_addr = temp->rid;
		printf("RID is %s\n",  inet_ntoa(iptemp));
		printf("Time is %s\n",  ctime(&temp->currenttime));
		temp = temp->next;
	}
}
/*---------------------------------------------------------------------
 * Method: updateneighbour
 *
 * updates the neighbour table in case of a timeout
 *
 *---------------------------------------------------------------------*/

void updateneighbour(struct sr_instance* sr)
{
    while(1)
    {   
    	sleep(5);     
        pthread_mutex_lock(&neighbour);
      	struct neighbour *temp = first;
        time_t Time = time(NULL);
        while(temp)
        {            
            time_t pkt_time = temp->currenttime;
            double diff = difftime(Time,pkt_time);
        	if(diff>OSPF_NEIGHBOR_TIMEOUT)
            {
                temp->rid = 0; 
                temp->valid = 0; 
                updateroutingtable(sr, temp->ip);       
            }
            temp = temp->next;
        }
        pthread_mutex_unlock(&neighbour);
    }
}
/*---------------------------------------------------------------------
 * Method: updateroutingtable
 *
 * updates the routing table entries when a link is down
 *
 *---------------------------------------------------------------------*/

void updateroutingtable(struct sr_instance* sr, uint32_t ip)
 {
	struct sr_rt *rt = sr->routing_table;
	rt = rtfirst;
	while(rt)
	{
		if(rt->gw.s_addr == ip)
		{
			rt->dest.s_addr = 0;
			rt->status = 0;
		}
		rt = rt->next;
	}
	printroutingtable(sr);
 }

/*---------------------------------------------------------------------
 * Method: sendlsu
 *
 * Sends periodic lsu packets
 *
 *---------------------------------------------------------------------*/
 
void sendlsu(struct sr_instance* sr)
{
	while(1)
	{
	sleep(OSPF_DEFAULT_LSUINT);
	pthread_mutex_lock(&neighbour);
	printf("Sending lsu\n");
	struct sr_ethernet_hdr* ethhdr = ((struct sr_ethernet_hdr*)
									(malloc(sizeof(struct sr_ethernet_hdr))));
    struct ip* iphdr = ((struct ip*)(malloc(sizeof(struct ip))));
    struct ospfv2_hdr* ospfhdr = ((struct ospfv2_hdr*)(malloc(sizeof(struct ospfv2_hdr))));
    struct ospfv2_lsu_hdr* lsuhdr = ((struct ospfv2_lsu_hdr*)
    								(malloc(sizeof(struct ospfv2_lsu_hdr))));
    int i;
    seqnum++;
    ethhdr->ether_type =  htons(ETHERTYPE_IP);
    for (i = 0; i < ETHER_ADDR_LEN; i++)
	{
		ethhdr->ether_dhost[i] = htons(0xff);
	}
	iphdr->ip_hl = 5;
	iphdr->ip_v = 4;
	iphdr->ip_tos = 0;
	iphdr->ip_off = IP_DF;
	iphdr->ip_id = rand();
	iphdr->ip_ttl = 64;
	iphdr->ip_p = 89;
	iphdr->ip_len = htons(sizeof(struct ip) + sizeof(struct ospfv2_hdr) + 
					sizeof(struct ospfv2_lsu_hdr) + (sizeof(struct ospfv2_lsu) * 3));
	
	ospfhdr->version = 2;
    ospfhdr->type = OSPF_TYPE_LSU;
	ospfhdr->len = htons(sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + 
						(sizeof(struct ospfv2_lsu) * 3));
   	ospfhdr->aid = 1;
    ospfhdr->autype = 0;
    ospfhdr->audata = 0;
    
	lsuhdr->unused = 0;
	lsuhdr->ttl = 64;
 	lsuhdr->num_adv = 3;
 	lsuhdr->seq = seqnum;
 	
 	struct neighbour* temp = first;		
 	while (temp)
	{
		if(temp->rid!=0)
		{
			uint32_t routerip;
			unsigned char* mac;
			struct sr_if *iflist = sr->if_list;
			while (iflist)
			{
				if (strcmp(iflist->name, temp->interface) == 0)
				{
					routerip = iflist->ip;
					mac = iflist->addr;
				}
				iflist = iflist->next;
			}
			iphdr->ip_dst.s_addr = temp->ip;
			iphdr->ip_src.s_addr = routerip;

			for (i = 0; i < ETHER_ADDR_LEN; i++)
				ethhdr->ether_shost[i] = mac[i];

			ospfhdr->rid = routerip;
			iphdr->ip_sum = 0;
			iphdr->ip_sum = checksum((uint16_t*)iphdr, sizeof(struct ip));
			ospfhdr->csum = 0;
   			ospfhdr->csum = checksum((uint16_t *)ospfhdr, sizeof(struct ospfv2_hdr)); 

			uint8_t *pkt = (uint8_t *)malloc(sizeof(struct sr_ethernet_hdr) + 
					sizeof(struct ip) + sizeof(struct ospfv2_hdr) + 
						sizeof(struct ospfv2_lsu_hdr) + (sizeof(struct ospfv2_lsu) * 3));

			memcpy(pkt, ethhdr, sizeof(struct sr_ethernet_hdr));
			memcpy(pkt + sizeof(struct sr_ethernet_hdr), iphdr, sizeof(struct ip));
			memcpy(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip), ospfhdr,
				       sizeof(struct ospfv2_hdr));
			memcpy(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + 
						sizeof(struct ospfv2_hdr), lsuhdr, sizeof(struct ospfv2_lsu_hdr));
			memcpy(pkt + sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + 
						sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr), 
							populateadvertisements(sr), 3*sizeof(struct ospfv2_lsu));


			sr_send_packet(sr, pkt, sizeof(struct sr_ethernet_hdr) + sizeof(struct ip)
						 + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr) + 
						 			3*sizeof(struct ospfv2_lsu), temp->interface);
			free(pkt);
		}
		temp = temp->next;
	}
    printf("Finished sending LSU\n");
    pthread_mutex_unlock(&neighbour);
	}
}
/*---------------------------------------------------------------------
 * Method: populateadvertisements
 *
 * populates the lsa for the lsu packets to be sent
 *
 *---------------------------------------------------------------------*/
struct ospfv2_lsu* populateadvertisements(struct sr_instance* sr)
{
	
	struct ospfv2_lsu* lsa = ((struct ospfv2_lsu*)(malloc(3*sizeof(struct ospfv2_lsu))));
	struct ospfv2_lsu lsad;
	struct neighbour* temp = first;	
	int i = 0;
	while (temp)
	{
		uint32_t routerip;
		uint32_t subnet;
       	uint32_t defaultmask;
    	uint32_t mask;
		struct sr_if *iflist = sr->if_list;
		while (iflist)
		{
			if (strcmp(iflist->name, temp->interface) == 0)
			{
				routerip = iflist->ip;
			}
			iflist = iflist->next;
		}
		if(temp->ip != routerip)
		{
			subnet = temp->ip & routerip;
			defaultmask = 0xffffffff;
			mask = ((temp->ip)^(routerip))^defaultmask;
		}
		else
		{
			subnet = temp->ip & routerip;
			mask = htonl(0xfffffffe);
		}
    	lsad.subnet = subnet;
    	lsad.mask = mask;
    	lsad.rid = temp->rid;
    	lsa[i++] = lsad;
		temp = temp->next;
	}

	return lsa;
}

/*---------------------------------------------------------------------
 * Method: handlelsupackets
 *
 * handling the incoming lsu packets from neighbours
 *
 *---------------------------------------------------------------------*/
void handlelsupackets(struct sr_instance* sr, uint8_t* packet)
{
	printf("coming to lsu packets\n");
	int count = 0;
	struct ospfv2_lsu* lsa = (struct ospfv2_lsu*)(packet + sizeof(struct sr_ethernet_hdr)
			 + sizeof(struct ip) + sizeof(struct ospfv2_hdr) + sizeof(struct ospfv2_lsu_hdr));
	struct ip* iphdr = (struct ip*)(packet + sizeof(struct sr_ethernet_hdr));
	struct ospfv2_lsu_hdr* lsuhdr = (struct ospfv2_lsu_hdr*)(packet + 
				sizeof(struct sr_ethernet_hdr) + sizeof(struct ip) + sizeof(struct ospfv2_hdr));
	//printad(lsa);
	for(int i=0; i<3; i++)
	{
		if(checktopology(lsa[i].subnet,lsa[i].rid)!=1)
		{
			addtopologyentry(lsa[i].subnet, lsa[i].rid, lsa[i].mask, iphdr->ip_src.s_addr, lsuhdr->seq);
		}
	}
	//printtopology();
	struct topology *temp=topofirst;
	while(temp)
	{
		count++;
		temp = temp->next;
	}
	if(count == 6 && entered == 0)
	{
		entered = 1;
		createroutingtable(sr);
		printroutingtable(sr);
	}

}

/*---------------------------------------------------------------------
 * Method: printad
 *
 * prints the ads in the incoming packets
 *
 *---------------------------------------------------------------------*/
void printad(struct ospfv2_lsu* lsa) 
{
	struct in_addr iptemp;
	printf("ADVERTISEMENTS\n");
	for(int i = 0; i<3; i++)
	{
		iptemp.s_addr = lsa[i].subnet;
		printf("subnet is %s\n",  inet_ntoa(iptemp));
		iptemp.s_addr = lsa[i].mask;
		printf("Mask is %s\n",  inet_ntoa(iptemp));
		iptemp.s_addr = lsa[i].rid;
		printf("RID is %s\n",  inet_ntoa(iptemp));
		
	}
}
/*---------------------------------------------------------------------
 * Method: checktopology
 *
 * checks the topology table for existing entries
 *
 *---------------------------------------------------------------------*/
int checktopology(uint32_t subnet,uint32_t rid)
{
	struct topology *temp=topofirst;
	while(temp)
	{
		if(temp->subnet == subnet && temp->rid == rid)
			return 1;
		temp=temp->next;
	}
	return 0;
}

/*---------------------------------------------------------------------
 * Method: addtopologyentry
 *
 * Adds the entries into the topology table
 *
 *---------------------------------------------------------------------*/
void addtopologyentry(uint32_t adsubnet, uint32_t adrid, uint32_t admask, uint32_t srcip, uint16_t adseqno)
{
	struct topology *temp=(struct topology*)malloc(sizeof(struct topology));
	if(temp!=NULL)
	{
			temp->rid = adrid;
			temp->subnet = adsubnet;
			temp->mask = admask;
			temp->src = srcip;
			temp->seqno = adseqno;
			temp->next = topofirst;
			topofirst = temp;		
	}
	else
	{
		printf("malloc in neighbour caching failed\n");
		exit(-1);
	}
}
/*---------------------------------------------------------------------
 * Method: printtopology
 *
 * prints the topology table
 *
 *---------------------------------------------------------------------*/
void printtopology()
{
	struct topology *temp=topofirst;
	printf("TOPOLOGY\n");
	struct in_addr iptemp;
	while(temp)
	{
		iptemp.s_addr = temp->subnet;
		printf("%s\t",inet_ntoa(iptemp));
		iptemp.s_addr = temp->rid;
		printf("%s\t",inet_ntoa(iptemp));
		iptemp.s_addr = temp->mask;
		printf("%s\t",inet_ntoa(iptemp));
		iptemp.s_addr = temp->src;
		printf("%s\t",inet_ntoa(iptemp));
		printf("%d\n",temp->seqno);
		temp=temp->next;
	}
}

/*---------------------------------------------------------------------
 * Method: createroutingtable
 *
 * creates a routing table with existing entries from neighbour table
 *
 *---------------------------------------------------------------------*/
void createroutingtable(struct sr_instance* sr)
{
	pthread_mutex_lock(&neighbour);
	pthread_mutex_lock(&sr_rt);
	int i =0;
	int count = 0;
	struct sr_rt *routingtable = sr->routing_table;
	routingtable = rtfirst;
	while(routingtable)
	{
		count++;
		routingtable= routingtable->next;
	}
	if(count<3)
	{
	struct sr_rt *routingtable = sr->routing_table;
	if(routingtable==NULL)
	{
		struct neighbour* temp = first;
		while(temp)
		{
			if(strcmp(temp->interface, "eth2")==0)
			{
			struct sr_if *interface = sr->if_list;
			struct sr_rt *rt = sr->routing_table;
			while(rt)
			{
				rt = rt->next;
			}
			rt = malloc(sizeof(struct sr_rt));
			while (interface)
			{
				if (strcmp(interface->name, temp->interface) == 0)
				{
					rt->dest.s_addr = interface->ip;
					rt->mask.s_addr = interface->mask;
					break;
				}
				interface = interface->next;
			}
			rt->gw.s_addr = temp->ip;
			rt->status = 1;
			
			for(i=0; i<32; i++)
				rt->interface[i] = temp->interface[i];
			rt->next = rtfirst;	
			rtfirst = rt;
			}
			temp = temp->next;
		}
		struct neighbour* temp1 = first;
		while(temp1)
		{
			if(strcmp(temp1->interface, "eth1")==0)
			{
				struct sr_if *interface = sr->if_list;
				struct sr_rt *rt = sr->routing_table;
				while(rt)
				{
					rt = rt->next;
				}
				rt = malloc(sizeof(struct sr_rt));
				while (interface)
				{
					if (strcmp(interface->name, temp1->interface) == 0)
					{
						rt->dest.s_addr = interface->ip;
						rt->mask.s_addr = interface->mask;
						break;
					}
					interface = interface->next;
				}	
				rt->gw.s_addr = temp1->ip;
				rt->status = 1;
				
				for(i=0; i<32; i++)
					rt->interface[i] = temp1->interface[i];
				rt->next = rtfirst;	
				rtfirst = rt;		
			}
			temp1 = temp1->next;
		}
		struct neighbour* temp2 = first;
		while(temp2)
		{
			if(strcmp(temp2->interface, "eth0")==0)
			{
				struct sr_rt *rt = sr->routing_table;
				while(rt)
				{
					rt = rt->next;
				}
				rt = malloc(sizeof(struct sr_rt));
				rt->dest.s_addr = 0;
				rt->gw.s_addr = temp2->ip;
				rt->status = 1;
				rt->mask.s_addr = 0;
				for(i=0; i<32; i++)
					rt->interface[i] = temp2->interface[i];
				rt->next = rtfirst;
				rtfirst = rt;
			}
			temp2 = temp2->next;
		}
	}
	else
	{
		staticentry = sr->routing_table;
		staticentry->status = 1;
		struct neighbour* temp = first;
		while(temp)
		{
			if(strcmp(temp->interface, "eth2")==0)
			{
			struct sr_if *interface = sr->if_list;
			struct sr_rt *rt = sr->routing_table;
			while(rt)
			{
				rt = rt->next;
			}
			rt = malloc(sizeof(struct sr_rt));
			while (interface)
			{
				if (strcmp(interface->name, temp->interface) == 0)
				{
					rt->dest.s_addr = interface->ip;
					rt->mask.s_addr = interface->mask;
					break;
				}
				interface = interface->next;
			}
			rt->gw.s_addr = temp->ip;
			rt->status = 1;
			
			for(i=0; i<32; i++)
				rt->interface[i] = temp->interface[i];
			rt->next = rtfirst;	
			rtfirst = rt;
			}
			temp = temp->next;
		}
		struct neighbour* temp1 = first;
		while(temp1)
		{
			if(strcmp(temp1->interface, "eth1")==0)
			{
				struct sr_if *interface = sr->if_list;
				struct sr_rt *rt = sr->routing_table;
				while(rt)
				{
					rt = rt->next;
				}
				rt = malloc(sizeof(struct sr_rt));
				while (interface)
				{
					if (strcmp(interface->name, temp1->interface) == 0)
					{
						rt->dest.s_addr = interface->ip;
						rt->mask.s_addr = interface->mask;
						break;
					}
					interface = interface->next;
				}	
				rt->gw.s_addr = temp1->ip;
				rt->status = 1;
				
				for(i=0; i<32; i++)
					rt->interface[i] = temp1->interface[i];
				rt->next = rtfirst;	
				rtfirst = rt;		
			}
			temp1 = temp1->next;
		}
		staticentry->next = rtfirst;
		rtfirst = staticentry;
	}
	}
	pthread_mutex_unlock(&sr_rt);
	pthread_mutex_unlock(&neighbour);
}

/*---------------------------------------------------------------------
 * Method: printroutingtable
 *
 * prints the routing table entries from sr_rt
 *
 *---------------------------------------------------------------------*/ 		
void printroutingtable(struct sr_instance *sr)
{
	struct sr_rt *routing_table=sr->routing_table;
	routing_table = rtfirst;
	printf("ROUTING TABLE\n");
	while(routing_table)
	{
		struct in_addr temp;
		temp= routing_table->dest;
		printf("%s\t", inet_ntoa(temp));
		temp = routing_table->gw;
		printf("%s\t", inet_ntoa(temp));
		temp = routing_table->mask;
		printf("%s\t", inet_ntoa(temp));
		printf("%s\n", routing_table->interface);
		//printf("%d\t\n", routing_table->status);
		routing_table = routing_table->next;
	}
}	
		
/*---------------------------------------------------------------------
 * Method: routingtablelookup
 *
 * does a lookup of entries in the routing table and also 
 *  handles for gateway scenerios
 *---------------------------------------------------------------------*/
 		
struct sr_rt* routingtablelookup(uint32_t dest, struct sr_instance* sr, int gate) {
	struct sr_rt *routingtable = sr->routing_table;
	routingtable = rtfirst;
	struct sr_rt* rt = NULL;
	uint32_t max = 0;
	while (routingtable)
	{
		if(routingtable->status == 1){
		if ((routingtable->dest).s_addr != 0)
		{
			int ip1 = 0xff & dest;
			int ip2 = 0xff & (routingtable->dest).s_addr;
			if(ip1 == ip2)
			{
			uint32_t destmasked = dest & ((routingtable->dest).s_addr);
			if (destmasked > max)
			{
				max = destmasked;
				rt = routingtable;
			}
			}
			else if(gate == 1)
			{
				if(routingtable->dest.s_addr != routingtable->gw.s_addr)
				{
					return routingtable;
				}
			}		
		}}
		routingtable = routingtable->next;
	}
	return rt;
}	

/*---------------------------------------------------------------------
 * Method: gatewaylookup
 *
 * Looks for gateway entries from routing table and also checks the status and 
 * routes accordingly
 *---------------------------------------------------------------------*/
 		
struct sr_rt* gatewaylookup(struct sr_instance* sr, uint32_t ip)
{
	struct sr_rt *routingtable = sr->routing_table;
	struct sr_rt *rt ;
	routingtable = rtfirst;
	while (routingtable)
	{
		if(routingtable->status == 1){
		if ((routingtable->dest.s_addr) == 0)
		{
			return routingtable;
		}}
		routingtable = routingtable->next;
	}
	if(routingtable == NULL)
	{
		rt = routingtablelookup(ip, sr,1);
	}
	
	return rt;
}
	
/*---------------------------------------------------------------------
 * Method: bringroutingtable
 *
 * Brings the link up in the routing table
 *---------------------------------------------------------------------*/	

void bringroutingtable(struct sr_instance* sr, uint32_t ip)
{
	struct sr_rt* rt = sr->routing_table;
	rt = rtfirst;
	struct sr_if* intf = sr->if_list;
	while(rt)
	{
		if(rt->gw.s_addr == ip)
		{
			rt->status = 1;
			if(strcmp(rt->interface, "eth0")!=0)
			{
				 while(intf)
				 {
				 	if(strcmp(intf->name,rt->interface)==0)
				 	{
				 		rt->dest.s_addr = intf->ip;
				 		break;
				 	}
				 	intf = intf->next;
				 }
			}
		}
		rt = rt->next;
	}
	printroutingtable(sr);
}
		