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
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */

/* See pseudo-code in sr_arpcache.h */

struct sr_if* corresponding_interface(struct sr_instance *sr, uint32_t ip){
  int i=0,j=0;
  char *a,*b;

  struct sr_if* interface, *destination;
  interface = sr->if_list;
  while(interface != NULL){
    j=0;
    a = (char*)&ip;
    b = (char*)&interface->ip;
    print_addr_ip_int(interface->ip);
    while(a[j]==b[j]) j++;
    if(j>=i){
      destination = interface;
      i = j;
    }
    interface = interface->next;
  }
  return destination;
}


void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  /* TODO: Fill this in */
  if(difftime(time(NULL), req->sent) > 1.0){
    if(req->times_sent >=5){
      struct sr_packet *packets;
      packets = req->packets;
      while(packets!=NULL){

        packets->len = sizeof(sr_ethernet_hdr_t) +
          sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);

        packets->buf = realloc(packets->buf, packets->len);
        struct sr_if * iface;
        iface = sr_get_interface(sr, packets->iface);

        sr_ethernet_hdr_t * pckt_hdr;
        pckt_hdr = (sr_ethernet_hdr_t *)packets->buf;

        memcpy(pckt_hdr->ether_dhost, pckt_hdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(pckt_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);

        pckt_hdr->ether_type = ethertype_ip;

        sr_ip_hdr_t * protocol_header;
        protocol_header = (sr_ip_hdr_t *)(packets->buf + sizeof(sr_ethernet_hdr_t));
        protocol_header->ip_dst = protocol_header->ip_src;
        protocol_header->ip_src = iface ->ip;
        protocol_header->ip_p = ip_protocol_icmp;

        sr_icmp_t3_hdr_t* icmp;
        icmp = (sr_icmp_t3_hdr_t*)(packets->buf + sizeof(sr_ip_hdr_t));

        icmp->icmp_type = 3;
        icmp->icmp_code = 1;

        sr_send_packet(sr,packets->buf,packets->len,packets->iface);
        packets = packets->next;
      }
      sr_arpreq_destroy(&(sr->cache),req);
    }
    else {

      struct sr_if *interface = corresponding_interface(sr,req->ip);
      int size_req = sizeof(sr_ethernet_hdr_t) +
        sizeof(sr_arp_hdr_t);

      int i=0;
      uint8_t *packet;
      packet = (uint8_t*)malloc(size_req);

      sr_ethernet_hdr_t* ethernet_header;
      ethernet_header = (sr_ethernet_hdr_t*)packet;

      sr_arp_hdr_t* arp_header;
      arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

      for(i=0; i<ETHER_ADDR_LEN; i++){
        ethernet_header->ether_dhost[i] = 0xff;
        ethernet_header->ether_shost[i] = interface->addr[i];
        arp_header->ar_tha[i] = 0x00;
        arp_header->ar_sha[i] = interface->addr[i];
      }

      ethernet_header->ether_type = htons(ethertype_arp);

      arp_header->ar_op  = htons(arp_op_request);
      arp_header->ar_sip = interface->ip;
      arp_header->ar_tip = req->ip;
      arp_header->ar_pro = 2048;
      arp_header->ar_pro = htons(arp_header->ar_pro);
      arp_header->ar_hrd = htons(1);
      arp_header->ar_hln = 6;
      arp_header->ar_pln = 4;

      sr_send_packet(sr, packet, size_req, interface->name);

      printf("---sent arp req--- \n");
      print_addr_ip_int(req->ip);
      print_hdrs(packet, size_req);

      free(packet);
    }
  }
}


int is_own(struct sr_if* iface, sr_ip_hdr_t *packet_ip_header){
    while(iface != NULL){
      if(iface->ip == packet_ip_header->ip_dst){
        return 1;
      }
      iface = iface->next;
    }
    return 0;
}

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
    
    /* TODO: (opt) Add initialization code here */

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
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){
  int i;

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d %s\n",len,interface);
  print_hdrs(packet, len);

  /* printf("------ %02x    %01x-----\n", ethertype(packet),ip_protocol(packet)); */

  struct sr_if* inter_f;
  inter_f = sr_get_interface(sr, interface);

  sr_ethernet_hdr_t *packet_header;

  packet_header = (sr_ethernet_hdr_t*)packet;

  if(ethertype(packet) == ethertype_arp){ 
    printf("---arp packet-----\n");

    sr_arp_hdr_t *arp_hdr;
    arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    if(ntohs(arp_hdr->ar_op) == arp_op_request){
      if(inter_f->ip == arp_hdr->ar_tip){

        for(i=0; i<ETHER_ADDR_LEN; i++){
          packet_header->ether_dhost[i] = arp_hdr->ar_sha[i];
          packet_header->ether_shost[i] = inter_f->addr[i];
          arp_hdr->ar_tha[i] = arp_hdr->ar_sha[i];
          arp_hdr->ar_sha[i] = inter_f->addr[i];
        }

        arp_hdr->ar_op = htons(arp_op_reply);
        arp_hdr->ar_tip = arp_hdr->ar_sip;
        arp_hdr->ar_sip = inter_f->ip;

        sr_send_packet(sr,packet,len,interface);
        printf("----- sent arp reply ----\n");
        print_hdrs(packet, len);

      }
    } else {
      /* if arp reply */
      struct sr_arpreq* req;
      req= sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

      if(req != NULL){
         struct sr_packet *packets;
         packets = req->packets;

         sr_ethernet_hdr_t *ph;

         while(packets != NULL){
          printf("%s---sending the queue packets----\n",packets->iface);
          ph = (sr_ethernet_hdr_t*)packets->buf;
          for(i=0; i<ETHER_ADDR_LEN; i++){
            ph->ether_dhost[i] = arp_hdr->ar_sha[i];
            ph->ether_shost[i] = arp_hdr->ar_tha[i];
          }
          sr_send_packet(sr, packets->buf, packets->len, interface);
          print_hdrs(packets->buf, packets->len);
          packets = packets->next;
         }
      }
    }

  } else {

    sr_ip_hdr_t *packet_ip_header;
    packet_ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

    /* packet_ip_header->ip_ttl = packet_ip_header->ip_ttl-1; */
    /* printf("---ip packet---- %d ",packet_ip_header->ip_sum); */
    int ip_sum_back = packet_ip_header->ip_sum;
    packet_ip_header->ip_sum = 0;
    /* printf(" %d \n",cksum(packet_ip_header,sizeof(sr_ip_hdr_t))); */
    if(ip_sum_back != cksum(packet_ip_header,sizeof(sr_ip_hdr_t))) return;

    /* packet_ip_header->ip_sum = cksum((void*)&packet_ip_header,sizeof(sr_ip_hdr_t)); */

    /* if icmp */

    if(packet_ip_header->ip_p == ip_protocol_icmp && 
        is_own(sr->if_list,packet_ip_header)){

      printf("router ping handling-----\n");
      sr_icmp_t3_hdr_t *icmp_header;
      icmp_header = (sr_icmp_t3_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) 
          + sizeof(sr_ip_hdr_t));

      int icmp_sum_back = icmp_header->icmp_sum;
      icmp_header->icmp_sum = 0;
      if(icmp_sum_back != cksum(icmp_header,len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t))) return;

      if(icmp_header->icmp_type == 8){

        memcpy(packet_header->ether_dhost, packet_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(packet_header->ether_shost, inter_f->addr, ETHER_ADDR_LEN);

        int dst = packet_ip_header->ip_src;
        packet_ip_header->ip_src = packet_ip_header->ip_dst;
        packet_ip_header->ip_dst = dst;

        icmp_header->icmp_type = 0;

        icmp_header->icmp_sum = 0;
        icmp_header->icmp_sum = cksum(icmp_header,len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

        packet_ip_header->ip_sum = cksum(packet_ip_header,sizeof(sr_ip_hdr_t));
        sr_send_packet(sr,packet,len,interface);
      }

    }
    else {
      printf("packet forwarding-----\n");
      struct sr_arpentry *entry;
      entry = sr_arpcache_lookup(&sr->cache, packet_ip_header->ip_dst);

      struct sr_if* dest_interface = corresponding_interface(sr, 
          packet_ip_header->ip_dst);

      if(entry!=NULL){

        for(i=0; i<ETHER_ADDR_LEN; i++){
          packet_header->ether_dhost[i] = entry->mac[i];
          packet_header->ether_shost[i] = dest_interface->addr[i];
        }

        sr_send_packet(sr, packet, len, dest_interface->name);
        printf("---packet sent after cache lookup---\n");
        print_hdrs(packet, len);
      } else {
        struct sr_arpreq* req;

        printf("adding to queue----\n");

        req = sr_arpcache_queuereq(&sr->cache, packet_ip_header->ip_dst, 
            packet, len,dest_interface->name);
        handle_arpreq(sr, req);
      }
    }
  }

  /* TODO: Add forwarding logic here */
 
  


}/* -- sr_handlepacket -- */

