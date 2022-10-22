#include "queue.h"
#include "skel.h"

/* Functie de sortare folosita la qsort pentru a
sorta tabela de rutare in functie de prefix si masca */
int compare_fct(const void *a, const void *b) {
	struct route_table_entry *a_entry = (struct route_table_entry*) a;
	struct route_table_entry *b_entry = (struct route_table_entry*) b;
	if (ntohl((a_entry->prefix & a_entry->mask)) != ntohl((b_entry->prefix & b_entry->mask))) {
		return ntohl(a_entry->prefix & a_entry->mask) > ntohl(b_entry->prefix & b_entry->mask);
	} else {
		return ntohl(a_entry->mask) > ntohl(b_entry->mask);
	}
}

/* Functie de cautare binara a intrarii din tabela de rutare pentru cea mai buna ruta
in procesul de forwarding */
struct route_table_entry* get_best_route(struct route_table_entry* route_table, int start, int stop, uint32_t ip) {
	// Avem route_table sortata dupa val prefixului, apoi dupa lungimea mastii
	// asa ca facem o cautare binara iterativa
	int max_len = stop;
	int max = 0;
	while (start <= stop) {
		int mid = start + (stop - start) / 2;
		if ((route_table[mid].prefix & route_table[mid].mask) == (ip & route_table[mid].mask)) {
			max = mid;
			// Criteriul LPM - cautam intrarea orespunzatoare cu masca cea mai mare
			max = mid;
			int max_mask = ntohl(route_table[mid].mask);
			int pos = mid;
			while (max <= max_len) {
				if ((route_table[max].prefix & route_table[max].mask) == (ip & route_table[max].mask)) {
					if (max_mask <= ntohl(route_table[max].mask)) {
						pos = max;
						max_mask = ntohl(route_table[max].mask);
					}
				}
				max++;
			}
			return &route_table[pos];
		}
		if (ntohl(route_table[mid].prefix & route_table[mid].mask) < ntohl(ip & route_table[mid].mask)) {
			// a doua jumatate
			start = mid + 1;
		} else {
			// prima jumatate
			stop = mid - 1;
		}
	}
	return NULL;
}

struct arp_entry *get_arp_entry(struct arp_entry *arp_table, int arp_table_len, uint32_t dest_ip) {
    for (int i = 0; i < arp_table_len; ++i) {
		if (dest_ip == arp_table[i].ip)
			return &arp_table[i];
	}
	return NULL;
}


int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	struct route_table_entry *route_table;
	int rtable_len;


	// Alocare si citire tabela de rutare
	route_table = malloc(100000 * sizeof(struct route_table_entry));
	rtable_len = read_rtable(argv[1], route_table);

	// Sortare tabela de rutare folosind functia qsort
	qsort(route_table, rtable_len, sizeof(struct route_table_entry), compare_fct);

	// Alocare si parsare tabela ARP statica
	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 100);
	int arp_table_len;
	arp_table_len = parse_arp_table("arp_table.txt", arp_table);
	

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		// Headere Ethernet, IPv4 si ICMP
		struct ether_header *eth_hdr = (struct ether_header *) m.payload;
		struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));
		struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

		// pachetul primit e de tip ip
		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			if (icmp_hdr != NULL) {
				if (icmp_hdr->code == 0 && icmp_hdr->type == ICMP_ECHO) {
					if (inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr) {
						// Routerul a primit Echo Request si trimite Echo Reply						
						send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_ECHOREPLY, ICMP_ECHOREPLY, 
							m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
						continue;
					}
				}
			}

			// Suma nu este corecta, ignoram pachetul primit
			if (ip_checksum((void *) ip_hdr, sizeof(struct iphdr)) != 0)
				continue;
			

			if (ip_hdr->ttl <= 1) {
				// eroare ICMP de tipul 11, codul 0 - TTL expirat
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 11, 0, m.interface);
				continue;
			}
			
			struct route_table_entry *best_route = get_best_route(route_table, 0, rtable_len - 1, ip_hdr->daddr);
			
			if (best_route == NULL) {
				uint8_t mac[6];
				get_interface_mac(m.interface, mac);
				// eroare ICMP de tipul 3, codul 0 - nu exista ruta
				send_icmp_error(ip_hdr->saddr, inet_addr(get_interface_ip(m.interface)), mac, eth_hdr->ether_shost, 3, 0, m.interface);
				continue;
			}

			// BONUS UPDATE CHECKSUM RFC 1624
			// ========
			uint16_t new_check = ~((~ip_hdr->check) + (~(ip_hdr->ttl & 0xffff)) + ((ip_hdr->ttl - 1) & 0xffff) + 1);

			ip_hdr->ttl--;
			ip_hdr->check = 0;
			ip_hdr->check = new_check;

			// ========

			struct arp_entry *arp_ent = get_arp_entry(arp_table, arp_table_len, best_route->next_hop);
			
			if (arp_ent == NULL) {
				// Tabela statica
				continue;
			}

			// Trimitere pachet catre urmatorul hop
			memcpy(eth_hdr->ether_dhost, arp_ent->mac, ETH_ALEN);
			get_interface_mac(best_route->interface, eth_hdr->ether_shost);
			m.interface = best_route->interface;

			send_packet(&m);
		}
	}
	// Eliberare memorie
	free(route_table);
	free(arp_table);
}
