/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);
  uint16_t ethtype = ethertype(packet);
  if(ethtype == ethertype_arp){
    print_hdr_arp(packet+sizeof(sr_ethernet_hdr_t));
    sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));/*get header*/
    printf("OPCODE %d\n",ntohs(arphdr->ar_op));
    if(ntohs(arphdr->ar_op) == arp_op_request){
      printf("**********HELLLOOOOO*********");
      if(arp_request_check(sr,packet+sizeof(sr_ethernet_hdr_t), interface)){
        print_hdrs(packet, len);
        sr_ethernet_hdr_t* ethhdr = (sr_ethernet_hdr_t *)(packet);
        uint8_t dhostcpy[ETHER_ADDR_LEN];
        int i = 0;
        for(i = 0; i<ETHER_ADDR_LEN; i++){
          ethhdr->ether_dhost[i] = ethhdr->ether_shost[i];
        }
        for(i = 0; i<ETHER_ADDR_LEN; i++){
          ethhdr->ether_shost[i] = arphdr->ar_sha[i];
        }
        print_hdrs(packet, len);
        sr_send_packet(sr, packet, len,interface);
      }
    }
    else{
      /*place mac address in cache and get queued packets*/
      struct sr_arpreq *arpreq = sr_arpcache_insert(&sr->cache,arphdr->ar_sha,arphdr->ar_sip);
      /*walk through the packets*/
      struct sr_packet* pack_walker = 0;
      pack_walker = arpreq->packets;
      while(pack_walker){
        /*get the ethernet header of the packet*/
        sr_ethernet_hdr_t* ethpack = (sr_ethernet_hdr_t *)(pack_walker->buf);
        /*place the MAC address in the ethernet header*/
        int i =0;
        for(i=0; i < ETHER_ADDR_LEN; i++){
          ethpack->ether_dhost[i] = arphdr->ar_sha[i];
        }
        /*send the packet*/
        sr_send_packet(sr, pack_walker->buf, pack_walker->len, pack_walker->iface);
        pack_walker = pack_walker->next;/*continue onto the next packet*/
      }
    }
  }
  else{
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    if(cksum(packet+sizeof(sr_ethernet_hdr_t),len-sizeof(sr_ethernet_hdr_t)) == ip_hdr->ip_sum){

    }
    else{
      sr_ethernet_hdr_t* ethhdr = (sr_ethernet_hdr_t *)(packet);
      uint8_t dhostcpy[ETHER_ADDR_LEN];
      int i = 0;
      for(i = 0;i < ETHER_ADDR_LEN; i++){
        dhostcpy[i] = ethhdr->ether_dhost[i];
      }
      for(i = 0; i<ETHER_ADDR_LEN; i++){
        ethhdr->ether_dhost[i] = ethhdr->ether_shost[i];
      }
      for(i = 0; i<ETHER_ADDR_LEN; i++){
        ethhdr->ether_shost[i] = dhostcpy[i];
      }
      
    }
  }
  /* fill in code here */

}/* end sr_ForwardPacket */

