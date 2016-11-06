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


struct sr_rt* largest_prefix_match(struct sr_rt * rtable,uint32_t ip) {
  ip=htonl(ip);
  uint32_t mx = 0, temp_ip;
  struct sr_rt* result =0;
  while(rtable) {
    temp_ip=htonl(rtable->dest.s_addr);
    unsigned int temp=(~(temp_ip ^ ip));
    if(temp>mx){mx=temp;result=rtable;}
    rtable=rtable->next;
  }
  if(mx==0) return NULL;
  return result;
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

struct sr_if* lookup_interface(struct sr_instance *sr, uint32_t ip){
  uint32_t mx = 0,temp_ip;
  ip = htonl(ip);
  struct sr_if* interface, *destination;
  interface = sr->if_list;
  while(interface != NULL){
    temp_ip = htonl(interface->ip);
    unsigned int temp=(~(temp_ip ^ ip));
    if(temp > mx) {
      destination = interface;
      mx = temp;
    }
    interface = interface->next;
  }
  return destination;
}


void send_icmp_error(struct sr_instance* sr, int type, int code,
               uint8_t * packet/* lent */,
               struct sr_if* interface/* lent */) {

      int icmp_packet_len= sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_t3_hdr_t);
      uint8_t* reply_icmp=(uint8_t*)malloc(icmp_packet_len);
      memset(reply_icmp,0,icmp_packet_len);
      sr_ethernet_hdr_t * packet_header = (sr_ethernet_hdr_t *)packet;
      sr_ip_hdr_t * packet_ip_header = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      sr_ethernet_hdr_t *reply_ether_hdr=(sr_ethernet_hdr_t*)reply_icmp;
      sr_ip_hdr_t *reply_ip_hdr=(sr_ip_hdr_t*)(reply_icmp+sizeof(sr_ethernet_hdr_t));
      sr_icmp_t3_hdr_t *reply_icmp_hdr=(sr_icmp_t3_hdr_t*)(reply_icmp+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));


      memcpy(reply_icmp,packet,sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));

      memcpy(reply_ether_hdr->ether_dhost,packet_header->ether_shost,ETHER_ADDR_LEN);
      memcpy(reply_ether_hdr->ether_shost,interface->addr,ETHER_ADDR_LEN);
      reply_ether_hdr->ether_type=htons(ethertype_ip);

      reply_ip_hdr->ip_p=ip_protocol_icmp;
      struct sr_if *intended;
      if(is_own(sr->if_list, packet_ip_header) == 1) {
        intended = lookup_interface(sr, packet_ip_header->ip_dst);
        reply_ip_hdr->ip_src=intended->ip;
      } else reply_ip_hdr->ip_src=interface->ip;

      reply_ip_hdr->ip_dst=packet_ip_header->ip_src;
      reply_ip_hdr->ip_len=ntohs(icmp_packet_len-sizeof(sr_ethernet_hdr_t));
      reply_ip_hdr->ip_id=8;
      reply_ip_hdr->ip_sum=0;
      reply_ip_hdr->ip_sum=cksum((void*)reply_ip_hdr,sizeof(struct sr_ip_hdr));

      reply_icmp_hdr->icmp_type=type;
      reply_icmp_hdr->icmp_code=code;

      memcpy(reply_icmp_hdr->data,packet+sizeof(sr_ethernet_hdr_t),ICMP_DATA_SIZE);
      reply_icmp_hdr->icmp_sum=0;
      reply_icmp_hdr->icmp_sum=cksum((void*)reply_icmp_hdr,icmp_packet_len-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t));


      sr_send_packet(sr,reply_icmp,icmp_packet_len,interface->name);
      free(reply_icmp);
      return;
}


void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  /* TODO: Fill this in */
  if(difftime(time(NULL), req->sent) > 1.0){
    if(req->times_sent >=5){
      struct sr_packet *packets;
      packets = req->packets;
      while(packets!=NULL){
        struct sr_if *interface = lookup_interface(sr,req->ip);
        send_icmp_error(sr, 3, 1, packets->buf, interface);
        printf("i321s the ttl\n");
        packets = packets->next;
      }
      sr_arpreq_destroy(&(sr->cache),req);
    }
    else {

      struct sr_if *interface = lookup_interface(sr,req->ip);
      int size_req = sizeof(sr_ethernet_hdr_t) +
        sizeof(sr_arp_hdr_t);


      uint8_t *packet;
      packet = (uint8_t*)malloc(size_req);

      sr_ethernet_hdr_t* ethernet_header;
      ethernet_header = (sr_ethernet_hdr_t*)packet;

      sr_arp_hdr_t* arp_header;
      arp_header = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

      memset(ethernet_header->ether_dhost,0xFF,ETHER_ADDR_LEN);
      memset(arp_header->ar_tha,0x00,ETHER_ADDR_LEN);
      memcpy(ethernet_header->ether_shost,interface->addr,ETHER_ADDR_LEN);
      memcpy(arp_header->ar_sha,interface->addr,ETHER_ADDR_LEN);

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

      free(packet);
      req->sent = time(NULL);
      req->times_sent++;
    }
  }
}





void process_ip(struct sr_instance* sr,
                uint8_t * packet/* lent */,
                unsigned int len,
                struct sr_if* interface/* lent */) {
  int i;
  sr_ethernet_hdr_t *packet_header = (sr_ethernet_hdr_t*)packet;
  sr_ip_hdr_t *packet_ip_header = (sr_ip_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t));

  int ip_sum_back = packet_ip_header->ip_sum;
  packet_ip_header->ip_sum = 0;

  assert(ip_sum_back == cksum(packet_ip_header,sizeof(sr_ip_hdr_t)));



  if(is_own(sr->if_list,packet_ip_header)){
    if (packet_ip_header->ip_p == ip_protocol_icmp) {
      sr_icmp_t3_hdr_t *icmp_header;
      icmp_header = (sr_icmp_t3_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t)
                                        + sizeof(sr_ip_hdr_t));

      int icmp_sum_back = icmp_header->icmp_sum;
      icmp_header->icmp_sum = 0;
      if(icmp_sum_back != cksum(icmp_header,len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t))) return;

      if(icmp_header->icmp_type == 8){

        memcpy(packet_header->ether_dhost, packet_header->ether_shost, ETHER_ADDR_LEN);
        memcpy(packet_header->ether_shost, interface->addr, ETHER_ADDR_LEN);

        int dst = packet_ip_header->ip_src;
        packet_ip_header->ip_src = packet_ip_header->ip_dst;
        packet_ip_header->ip_dst = dst;
        icmp_header->icmp_type = 0;
        icmp_header->icmp_sum = 0;
        icmp_header->icmp_sum = cksum(icmp_header,len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
        packet_ip_header->ip_sum = cksum(packet_ip_header,sizeof(sr_ip_hdr_t));
        sr_send_packet(sr,packet,len,interface->name);
        return;
      }
    } else if (packet_ip_header->ip_p == 17 || packet_ip_header->ip_p == 6){
      send_icmp_error(sr, 3, 3, packet, interface);
      return;
    }

  }

  if(packet_ip_header->ip_ttl <= 1) {
    send_icmp_error(sr, 11, 0, packet, interface);
    return;
  }
  else {
    struct sr_arpentry *entry;
    packet_ip_header->ip_ttl--;
    struct sr_rt * rt_entry =  largest_prefix_match(sr->routing_table, packet_ip_header->ip_dst);
    if(rt_entry != NULL) {
      entry = sr_arpcache_lookup(&sr->cache, rt_entry->dest.s_addr);

      struct sr_if* dest_interface = sr_get_interface(sr, rt_entry->interface );

      if(entry!=NULL){

        for(i=0; i<ETHER_ADDR_LEN; i++){
          packet_header->ether_dhost[i] = entry->mac[i];
          packet_header->ether_shost[i] = dest_interface->addr[i];
        }
        packet_ip_header->ip_sum = cksum(packet_ip_header,sizeof(sr_ip_hdr_t));
        sr_send_packet(sr, packet, len, dest_interface->name);
        /* print_hdrs(packet, len); */
      } else {
        struct sr_arpreq* req;
        packet_ip_header->ip_sum = cksum(packet_ip_header,sizeof(sr_ip_hdr_t));
        req = sr_arpcache_queuereq(&sr->cache, packet_ip_header->ip_dst,
                                   packet, len,dest_interface->name);
        handle_arpreq(sr, req);
      }
    } else send_icmp_error(sr, 3, 0, packet, interface);
  }
  return;
}



void process_arp(struct sr_instance* sr,
                uint8_t * packet/* lent */,
                unsigned int len,
                struct sr_if* interface/* lent */) {
  int i;
  sr_ethernet_hdr_t *packet_header;
  packet_header = (sr_ethernet_hdr_t*)packet;
  sr_arp_hdr_t *arp_hdr;
  arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  if(ntohs(arp_hdr->ar_op) == arp_op_request){
    if(interface->ip == arp_hdr->ar_tip){
      memcpy(packet_header->ether_dhost,arp_hdr->ar_sha,ETHER_ADDR_LEN);
      memcpy(packet_header->ether_shost,interface->addr,ETHER_ADDR_LEN);
      memcpy(arp_hdr->ar_tha,arp_hdr->ar_sha,ETHER_ADDR_LEN);
      memcpy(arp_hdr->ar_sha,interface->addr,ETHER_ADDR_LEN);
      arp_hdr->ar_op = htons(arp_op_reply);
      arp_hdr->ar_tip = arp_hdr->ar_sip;
      arp_hdr->ar_sip = interface->ip;
      sr_send_packet(sr,packet,len,interface->name);
    }
  } else {
    struct sr_arpreq* req;
    req= sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
    if(req != NULL){
      struct sr_packet *packets;
      packets = req->packets;
      sr_ethernet_hdr_t *ph;
      while(packets != NULL){
        ph = (sr_ethernet_hdr_t*)packets->buf;
        for(i=0; i<ETHER_ADDR_LEN; i++){
          ph->ether_dhost[i] = arp_hdr->ar_sha[i];
          ph->ether_shost[i] = arp_hdr->ar_tha[i];
        }
        sr_send_packet(sr, packets->buf, packets->len, interface->name);
        packets = packets->next;
      }
    }
  }
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

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  struct sr_if* inter_f = sr_get_interface(sr, interface);
  if(ethertype(packet) == ethertype_arp) process_arp(sr, packet, len, inter_f);
  else process_ip(sr, packet, len, inter_f);
  return;
}
