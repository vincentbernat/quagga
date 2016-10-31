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
#include "bgpd/bgp_ecommunity.h"

/* EVPN route types. */
typedef enum
{
  BGP_EVPN_AD_ROUTE = 1,          /* Ethernet Auto-Discovery (A-D) route */
  BGP_EVPN_MAC_IP_ROUTE,          /* MAC/IP Advertisement route */
  BGP_EVPN_IMET_ROUTE,            /* Inclusive Multicast Ethernet Tag route */
  BGP_EVPN_ES_ROUTE,              /* Ethernet Segment route */
  BGP_EVPN_IP_PREFIX_ROUTE,       /* IP Prefix route */
} bgp_evpn_route_type;

/*
 * Hash table of VNIs - configured, learnt and local.
 * TODO: Configuration is not supported right now.
 */
struct bgpevpn
{
  vni_t                     vni;
  u_int32_t                 flags;
#define VNI_FLAG_LIVE              0x1  /* VNI is "live" */
#define VNI_FLAG_RD_CFGD           0x2  /* RD is configured. */
#define VNI_FLAG_IMPRT_CFGD        0x4  /* Import RT is configured */
#define VNI_FLAG_EXPRT_CFGD        0x8  /* Export RT is configured */

  /* RD for this VNI. */
  struct prefix_rd          prd;

  /* Route type 3 field */
  struct in_addr            originator_ip;

  /* Import and Export RTs. */
  struct list               *import_rtl;

  /* TODO: Only 1 supported. */
  struct ecommunity_val     export_rt;

  QOBJ_FIELDS
};

DECLARE_QOBJ_TYPE(bgpevpn)

#define EVPN_ROUTE_LEN 50

static inline int
is_vni_live (struct bgpevpn *vpn)
{
  return (CHECK_FLAG (vpn->flags, VNI_FLAG_LIVE));
}

static inline int
is_rd_configured (struct bgpevpn *vpn)
{
  return (CHECK_FLAG (vpn->flags, VNI_FLAG_RD_CFGD));
}

static inline int
bgp_evpn_rd_matches_existing (struct bgpevpn *vpn, struct prefix_rd *prd)
{
  return(memcmp (&vpn->prd.val, prd->val, ECOMMUNITY_SIZE) == 0);
}

static inline int
is_import_rt_configured (struct bgpevpn *vpn)
{
  return (CHECK_FLAG (vpn->flags, VNI_FLAG_IMPRT_CFGD));
}

static inline int
is_export_rt_configured (struct bgpevpn *vpn)
{
  return (CHECK_FLAG (vpn->flags, VNI_FLAG_EXPRT_CFGD));
}

extern struct bgpevpn *bgp_evpn_lookup_vni (struct bgp *bgp, vni_t vni);
extern struct bgpevpn *bgp_evpn_create_vni (struct bgp *bgp, vni_t vni);
extern int bgp_evpn_delete_vni (struct bgp *bgp, struct bgpevpn *vpn);
extern int bgp_evpn_is_vni_configured (struct bgpevpn *vpn);
extern int bgp_evpn_local_vni_add (struct bgp *bgp, vni_t vni, struct in_addr);
extern int bgp_evpn_local_vni_del (struct bgp *bgp, vni_t vni);
extern void bgp_evpn_show_vni (struct hash_backet *backet, struct vty *vty);
extern void bgp_evpn_encode_prefix (struct stream *s, struct prefix *p,
           struct prefix_rd *prd, int addpath_encode, u_int32_t addpath_tx_id);
extern int bgp_evpn_nlri_sanity_check (struct peer *peer, int afi, safi_t safi,
                                 u_char *pnt, bgp_size_t length, int *numpfx);
extern int bgp_evpn_nlri_parse (struct peer *peer, struct attr *attr,
                                struct bgp_nlri *packet);
extern int bgp_evpn_install_route (struct bgp *bgp, afi_t afi, safi_t safi,
                                   struct prefix *p, struct bgp_info *ri);
extern int bgp_evpn_uninstall_route (struct bgp *bgp, afi_t afi, safi_t safi,
                                     struct prefix *p, struct bgp_info *ri);
extern void bgp_evpn_update_advertise_vni (struct bgp *);
extern void bgp_evpn_init (struct bgp *);
extern void bgp_evpn_cleanup (struct bgp *bgp);
extern int bgp_evpn_print_prefix (struct vty *, struct prefix_evpn *);
extern void bgp_evpn_show_one_vni (struct vty *, struct bgp *, vni_t);
extern char *bgp_evpn_route2str (struct prefix_evpn *, char *);
extern void bgp_evpn_handle_router_id_update (struct bgp *, int);
extern void bgp_evpn_update_rd (struct bgp *, struct bgpevpn *, struct prefix_rd *, int);
extern int bgp_evpn_check_configured_rd (struct bgpevpn *, struct prefix_rd *);
extern int bgp_evpn_check_auto_rd_flag (struct bgpevpn *);
extern int bgp_evpn_process_rt_config (struct vty *, struct bgp *, struct bgpevpn *,
                                       struct prefix_rd *, const char *, int, int);
extern void bgp_evpn_show_import_rt (struct hash_backet *, struct vty *);
extern void bgp_evpn_check_uninstall_evpn_route (struct bgp *, afi_t, safi_t,
                                                 struct prefix_evpn *, struct bgp_info *);
extern void bgp_config_write_advertise_vni (struct vty *, struct bgp *, afi_t, 
                                            safi_t, int *);
extern int bgp_evpn_local_macip_add (struct bgp *bgp, vni_t vni,
                                     struct ethaddr *mac);
extern int bgp_evpn_local_macip_del (struct bgp *bgp, vni_t vni,
                                     struct ethaddr *mac);
#endif /* _QUAGGA_BGP_EVPN_H */
