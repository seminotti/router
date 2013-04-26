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
#include <string.h>
#include <stdlib.h>

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
  sr_ethernet_hdr_t* ethhdr = (sr_ethernet_hdr_t *)(packet);
  uint16_t ethtype = ethertype(packet);
  if(ethtype == ethertype_arp){
    print_hdr_arp(packet+sizeof(sr_ethernet_hdr_t));
    sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));/*get header*/
    printf("OPCODE %d\n",ntohs(arphdr->ar_op));
    if(ntohs(arphdr->ar_op) == arp_op_request){
      printf("**********HELLLOOOOO*********");
      if(arp_request_check(sr,packet+sizeof(sr_ethernet_hdr_t), interface)){
        print_hdrs(packet, len);
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
        /*place the MAC address in the ethernet header*/
        int i =0;
        for(i=0; i < ETHER_ADDR_LEN; i++){
          ethhdr->ether_dhost[i] = arphdr->ar_sha[i];
        }
        /*send the packet*/
        sr_send_packet(sr, pack_walker->buf, pack_walker->len, pack_walker->iface);
        pack_walker = pack_walker->next;/*continue onto the next packet*/
      }
      sr_arpreq_destroy(&(sr->cache), arpreq);
    }
  }
  else{
    print_hdrs(packet, len);
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet+sizeof(sr_ethernet_hdr_t));
    if(cksum(packet+sizeof(sr_ethernet_hdr_t),ip_hdr->ip_hl*4) == 0xffff && ntohs(ip_hdr->ip_len) >= 20){
      struct sr_if* get_iface = sr_get_interface(sr, interface);
      uint8_t *nex_buf = packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t);
      if(ip_hdr->ip_dst == get_iface->ip){
        if(ip_hdr->ip_p == ip_protocol_icmp){
          int nlen = len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t);
          if(cksum(nex_buf,nlen) == 0xffff){
            sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(nex_buf);
            icmp_hdr->icmp_type = 0;
            icmp_hdr->icmp_sum = 0;
            icmp_hdr->icmp_sum = cksum(nex_buf,nlen);
            flip_ip(packet);
            printf("****************Noobie******************\n");
            print_hdrs(packet, len);
            sr_send_packet(sr, packet, len, interface);
          }
          else{/*icmp checksum fails*/

          }
        }
        else{/*protocol is tcp/udp*/
          len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
          uint8_t* n_packet = malloc(len);
          memcpy(n_packet,packet,len);
          ip_hdr = (sr_ip_hdr_t *)(n_packet + sizeof(sr_ethernet_hdr_t));
          ip_hdr->ip_len = ntohs(sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t));
          ip_hdr->ip_p = ip_protocol_icmp;
          memcpy(n_packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_icmp_t3_hdr_t)-8,n_packet+sizeof(sr_ethernet_hdr_t),(int)(sizeof(sr_ip_hdr_t)+8));
          flip_ip(n_packet);
          sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(n_packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
          icmp_hdr->icmp_type = 3;
          icmp_hdr->icmp_code = 3;
          icmp_hdr->icmp_sum = 0;
          icmp_hdr->unused = 0;
          icmp_hdr->next_mtu = 0;
          icmp_hdr->icmp_sum = cksum(n_packet+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t),sizeof(sr_icmp_t3_hdr_t));
          printf("*******%d\n*********",len);
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(n_packet+sizeof(sr_ethernet_hdr_t),ip_hdr->ip_hl*4);
          printf("****************Noobie******************\n");
          print_hdrs(n_packet, len);
          sr_send_packet(sr, n_packet, len, interface);
          free(n_packet);
        }
      }
      else{/*ip destination is not this router*/
        ip_hdr->ip_ttl--;
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = cksum(packet+sizeof(sr_ethernet_hdr_t),ip_hdr->ip_hl*4);
        struct sr_rt* route = sr->routing_table;
        uint32_t ip_dest = ip_hdr->ip_dst;
        struct sr_rt* long_addr = 0;
        uint32_t long_pfx = 0;
        do{
          struct in_addr* gate = &route->gw;
          uint32_t gwadr = gate->s_addr;
          gate = &route->mask;
          uint32_t mask = gate->s_addr;
          gwadr = (gwadr & mask);
          if(gwadr == ip_dest & mask && mask > long_pfx){
            long_addr = route;
            long_pfx = mask;
          }
          route = route->next;
        } while(route);
        if(long_addr == 0){
          ip_hdr->ip_len = sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
          ip_hdr->ip_p = ip_protocol_icmp;
          memcpy(nex_buf+sizeof(sr_icmp_t3_hdr_t),packet+sizeof(sr_ethernet_hdr_t),(int)(sizeof(sr_ip_hdr_t)));
          sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(nex_buf);
          icmp_hdr->icmp_type = 3;
          icmp_hdr->icmp_code = 0;
          icmp_hdr->icmp_sum = 0;
          icmp_hdr->unused = 0;
          icmp_hdr->next_mtu = 0;
          icmp_hdr->icmp_sum = cksum(nex_buf,sizeof(sr_icmp_t3_hdr_t));
          len = sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
          flip_ip(packet);
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(packet+sizeof(sr_ethernet_hdr_t),ip_hdr->ip_hl*4);
          printf("****************Noobie******************\n");
          print_hdrs(packet, len);
          sr_send_packet(sr, packet, len, interface);
        }
        else{
          struct sr_arpentry* arplook = sr_arpcache_lookup(&sr->cache, (&long_addr->gw)->s_addr);
          struct sr_if* inter = sr_get_interface(sr, long_addr->interface);
          ip_hdr->ip_sum = 0;
          ip_hdr->ip_sum = cksum(packet+sizeof(sr_ethernet_hdr_t),ip_hdr->ip_hl*4);
          print_addr_ip_int(ntohl((&long_addr->gw)->s_addr));
          if(arplook){
            printf("*** d ***\n");
          }
          if(arplook){
            int i;
            for(i = 0; i< ETHER_ADDR_LEN; i++){
              ethhdr->ether_shost[i] = inter->addr[i];
              ethhdr->ether_dhost[i] = arplook->mac[i];
            }
            sr_send_packet(sr, packet, len, long_addr->interface);
          }
          else{
            sr_arpcache_queuereq(&sr->cache, ntohl((&long_addr->gw)->s_addr), packet, len, long_addr->interface);
          }
        }
      }
    }
    else{/*ip header checksum is not correct*/
      printf("****NOOOOOOOOOOO*******");
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

