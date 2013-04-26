#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_router.h"

uint16_t cksum (const void *_data, int len) {
  const uint8_t *data = _data;
  uint32_t sum;

  for (sum = 0;len >= 2; data += 2, len -= 2)
    sum += data[0] << 8 | data[1];
  if (len > 0)
    sum += data[0] << 8;
  while (sum > 0xffff)
    sum = (sum >> 16) + (sum & 0xffff);
  sum = htons (~sum);
  return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  return iphdr->ip_p;
}

uint8_t* arp_request_check(struct sr_instance* sr, uint8_t *buf, const char* name) {
  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(buf);
  struct sr_if* if_temp = sr_get_interface(sr, name);
  if(if_temp != 0) {
    arphdr->ar_op = ntohs(arp_op_reply);
    /*Swap ips*/
    uint32_t temp_ip = arphdr->ar_tip;
    arphdr->ar_tip = arphdr->ar_sip;
    arphdr->ar_sip = temp_ip;
    int i;
    for(i=0; i<ETHER_ADDR_LEN; i++) {
      arphdr->ar_tha[i] = arphdr->ar_sha[i];
      arphdr->ar_sha[i] = if_temp->addr[i];
    }
    return buf;
  }
  return NULL;
}

void flip_ether(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  uint8_t scpy[ETHER_ADDR_LEN];
  int i;
  for(i = 0; i < ETHER_ADDR_LEN; i++){
    scpy[i] = ehdr->ether_shost[i];
    ehdr->ether_shost[i] = ehdr->ether_dhost[i];
    ehdr->ether_dhost[i] = scpy[i];
  }
}

void flip_ip(uint8_t *buf) {
  flip_ether(buf);
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf+sizeof(sr_ethernet_hdr_t));
  uint32_t ip_src_cpy = iphdr->ip_src;
  iphdr->ip_src = iphdr->ip_dst;
  iphdr->ip_dst = ip_src_cpy;
}

uint8_t* build_arp_reply(uint32_t sip, uint32_t tip, unsigned char* sha) {
  unsigned char *buf = 0;
  if((buf = malloc(sizeof(sr_ethernet_hdr_t))+sizeof(sr_arp_hdr_t)) == 0) {
	 fprintf(stderr,"Error: out of memory (sr_read_from_server)\n");
	 return NULL;
  }
  sr_ethernet_hdr_t *ethhdr = (sr_ethernet_hdr_t *)(buf);
  int i;  
  for(i=0; i<ETHER_ADDR_LEN; i++) ethhdr->ether_dhost[i] = 255;
  for(i=0; i<ETHER_ADDR_LEN; i++) ethhdr->ether_shost[i] = sha[i];
  ethhdr->ether_type = 2054;

  sr_arp_hdr_t *arphdr = (sr_arp_hdr_t *)(buf);
  arphdr->ar_hrd = 1;
  arphdr->ar_pro = 2048;
  arphdr->ar_hln = 6;
  arphdr->ar_pln = 4;
  arphdr->ar_op = 1;
  for(i=0; i<ETHER_ADDR_LEN; i++) arphdr->ar_sha[i] = sha[i];
  arphdr->ar_sip = sip;
  for(i=0; i<ETHER_ADDR_LEN; i++) arphdr->ar_tha[i] = 0;
  arphdr->ar_tip = tip;
  
  return (uint8_t*) buf;
}

uint8_t* build_icmp_reply(uint32_t sip, uint32_t tip, unsigned char* sha, unsigned char* tha) {
  unsigned char *buf = 0;
  if((buf = malloc(sizeof(sr_ethernet_hdr_t))+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t)) == 0) {
	 fprintf(stderr,"Error: out of memory (sr_read_from_server)\n");
	 return NULL;
  }
  /*ethernet*/
  sr_ethernet_hdr_t *ethhdr = (sr_ethernet_hdr_t *)(buf);
  int i;  
  for(i=0; i<ETHER_ADDR_LEN; i++) ethhdr->ether_dhost[i] = tha[i];
  for(i=0; i<ETHER_ADDR_LEN; i++) ethhdr->ether_shost[i] = sha[i];
  ethhdr->ether_type = 2048;

  /*ip*/
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf+sizeof(sr_ethernet_hdr_t));
  iphdr->ip_v = 4;
  iphdr->ip_hl = 5;
  iphdr->ip_tos = 0;
  iphdr->ip_len = 84;
  iphdr->ip_id = 0;
  iphdr->ip_off = 0;
  iphdr->ip_ttl = 64;
  iphdr->ip_p = 1;
  iphdr->ip_sum = 0;
  iphdr->ip_src = sip;
  iphdr->ip_dst = tip;
  iphdr->ip_sum = cksum(buf+sizeof(sr_ethernet_hdr_t),sizeof(sr_ip_hdr_t));

  /*icmp*/
  sr_icmp_t3_hdr_t *icmp_hdr = (sr_icmp_t3_hdr_t *)(buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
  icmp_hdr->icmp_type = 3;
  icmp_hdr->icmp_code = 3;
  icmp_hdr->icmp_sum = 0;
  icmp_hdr->unused = 0;
  icmp_hdr->next_mtu = 0;
  icmp_hdr->icmp_sum = cksum(buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t),sizeof(sr_icmp_t3_hdr_t));
  
  return (uint8_t*) buf;
}

/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
  int pos = 0;
  uint8_t cur;
  for (; pos < ETHER_ADDR_LEN; pos++) {
    cur = addr[pos];
    if (pos > 0)
      fprintf(stderr, ":");
    fprintf(stderr, "%02X", cur);
  }
  fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
  char buf[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
    fprintf(stderr,"inet_ntop error on address conversion\n");
  else
    fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
  uint32_t curOctet = ip >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 8) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 16) >> 24;
  fprintf(stderr, "%d.", curOctet);
  curOctet = (ip << 24) >> 24;
  fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
  sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
  fprintf(stderr, "ETHERNET header:\n");
  fprintf(stderr, "\tdestination: ");
  print_addr_eth(ehdr->ether_dhost);
  fprintf(stderr, "\tsource: ");
  print_addr_eth(ehdr->ether_shost);
  fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
  sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
  fprintf(stderr, "IP header:\n");
  fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
  fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
  fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
  fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
  fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

  if (ntohs(iphdr->ip_off) & IP_DF)
    fprintf(stderr, "\tfragment flag: DF\n");
  else if (ntohs(iphdr->ip_off) & IP_MF)
    fprintf(stderr, "\tfragment flag: MF\n");
  else if (ntohs(iphdr->ip_off) & IP_RF)
    fprintf(stderr, "\tfragment flag: R\n");

  fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
  fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
  fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

  /*Keep checksum in NBO*/
  fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

  fprintf(stderr, "\tsource: ");
  print_addr_ip_int(ntohl(iphdr->ip_src));

  fprintf(stderr, "\tdestination: ");
  print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
  fprintf(stderr, "ICMP header:\n");
  fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
  fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
  /* Keep checksum in NBO */
  fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}


/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
  fprintf(stderr, "ARP header\n");
  fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
  fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
  fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
  fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
  fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

  fprintf(stderr, "\tsender hardware address: ");
  print_addr_eth(arp_hdr->ar_sha);
  fprintf(stderr, "\tsender ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_sip));

  fprintf(stderr, "\ttarget hardware address: ");
  print_addr_eth(arp_hdr->ar_tha);
  fprintf(stderr, "\ttarget ip address: ");
  print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

  /* Ethernet */
  int minlength = sizeof(sr_ethernet_hdr_t);
  if (length < minlength) {
    fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
    return;
  }

  uint16_t ethtype = ethertype(buf);
  print_hdr_eth(buf);

  if (ethtype == ethertype_ip) { /* IP */
    minlength += sizeof(sr_ip_hdr_t);
    if (length < minlength) {
      fprintf(stderr, "Failed to print IP header, insufficient length\n");
      return;
    }

    print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
    uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

    if (ip_proto == ip_protocol_icmp) { /* ICMP */
      minlength += sizeof(sr_icmp_hdr_t);
      if (length < minlength)
        fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
      else
        print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    }
  }
  else if (ethtype == ethertype_arp) { /* ARP */
    minlength += sizeof(sr_arp_hdr_t);
    if (length < minlength)
      fprintf(stderr, "Failed to print ARP header, insufficient length\n");
    else
      print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
  }
  else {
    fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
  }
}

