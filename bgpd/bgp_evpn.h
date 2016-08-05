/* BGP EVPN
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GN5U General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _QUAGGA_BGP_EVPN_H
#define _QUAGGA_BGP_EVPN_H

#include "vxlan.h"
#include "zebra.h"
#include "hash.h"
#include "vty.h"

#include "bgpd/bgpd.h"

/* EVPN route types. */
typedef enum
{
  BGP_EVPN_AD_ROUTE = 1,          /* Ethernet Auto-Discovery (A-D) route */
  BGP_EVPN_MAC_IP_ROUTE,          /* MAC/IP Advertisement route */
  BGP_EVPN_IMET_ROUTE,            /* Inclusive Multicast Ethernet Tag route */
  BGP_EVPN_ES_ROUTE,              /* Ethernet Segment route */
  BGP_EVPN_IP_PREFIX_ROUTE,       /* IP Prefix route */
} bgp_evpn_route_type;

extern void bgp_evpn_update_vni (struct bgp*, vni_t, int);
extern int bgp_evpn_local_vni_add (struct bgp *bgp, vni_t vni);
extern int bgp_evpn_local_vni_del (struct bgp *bgp, vni_t vni);
extern void bgp_evpn_show_vni (struct hash_backet *backet, struct vty *vty);
extern void bgp_evpn_encode_prefix (struct stream *s, struct prefix *p,
           struct prefix_rd *prd, int addpath_encode, u_int32_t addpath_tx_id);
extern int bgp_evpn_nlri_sanity_check (struct peer *peer, int afi, safi_t safi,
                                 u_char *pnt, bgp_size_t length, int *numpfx);
extern int bgp_evpn_nlri_parse (struct peer *peer, struct attr *attr,
                                struct bgp_nlri *packet);
extern void bgp_evpn_init (struct bgp *);
extern void bgp_evpn_cleanup (struct bgp *bgp);
extern void bgp_evpn_update_advertise_vni (struct bgp *);

#endif /* _QUAGGA_BGP_EVPN_H */
