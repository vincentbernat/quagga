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

#include "command.h"
#include "stream.h"
#include "memory.h"
#include "log.h"
#include "hash.h"
#include "prefix.h"
#include "zclient.h"
#include "vxlan.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_zebra.h"

#define EVPN_TYPE_3_ROUTE_PREFIXLEN      192

/*
 * Hash table of VNIs - configured, learnt and local.
 * TODO: Configuration is not supported right now.
 */
struct bgpevpn
{
  vni_t                     vni;
  u_int32_t                 flags;
#define VNI_FLAG_CONFIGURED   0x0
#define VNI_FLAG_LOCAL        0x1

  /* RD for this VNI. */
  struct prefix_rd          prd;

  /* Import and Export RTs. */
  /* TODO: Only 1 each supported. */
  struct ecommunity_val     import_rt;
  struct ecommunity_val     export_rt;
};


extern struct zclient *zclient;

/*
 * Private functions.
 */

/*
 * Build EVPN type-3 prefix (for route node)
 */
static inline void
build_evpn_type3_prefix (struct prefix_evpn *p, struct in_addr router_id)
{
  memset (p, 0, sizeof (struct prefix_evpn));
  p->family = AF_ETHERNET;
  p->prefixlen = EVPN_TYPE_3_ROUTE_PREFIXLEN;
  p->prefix.route_type = BGP_EVPN_IMET_ROUTE;
  SET_FLAG (p->prefix.flags, IP_ADDR_V4);
  p->prefix.ip.v4_addr = router_id;
}

/*
 * vni_hash_key_make
 *
 * Make vni hash key.
 */
static unsigned int
vni_hash_key_make(void *p)
{
  struct bgpevpn *vpn = p;
  return vpn->vni;
}

/*
 * vni_hash_cmp
 *
 * Comparison function for vni hash
 */
static int
vni_hash_cmp (const void *p1, const void *p2)
{
  const struct bgpevpn *vpn1 = p1;
  const struct bgpevpn *vpn2 = p2;

  if (!vpn1 && !vpn2)
    return 1;
  if (!vpn1 || !vpn2)
    return 0;
  return(vpn1->vni == vpn2->vni);
}

/*
 * bgp_evpn_derive_rd_rt
 *
 * Function to derive RD and RT from the VNI.
 * RD = Router Id:VNI
 * RT = AS:VNI
 * TODO: Cannot handle VNI larger than UINT16_MAX
 */
static void
bgp_evpn_derive_rd_rt (struct bgp *bgp, struct bgpevpn *vpn)
{
  char buf[100];
  u_char rt_type;
  struct in_addr ip;

  vpn->prd.family = AF_UNSPEC;
  vpn->prd.prefixlen = 64;
  sprintf (buf, "%s:%u", inet_ntoa (bgp->router_id), vpn->vni);
  str2prefix_rd (buf, &vpn->prd);
  if (bgp->as > BGP_AS_MAX)
    rt_type = ECOMMUNITY_ENCODE_AS4;
  else
    rt_type = ECOMMUNITY_ENCODE_AS;
  ecommunity_encode (rt_type, ECOMMUNITY_ROUTE_TARGET, 1, bgp->as,
                     ip, vpn->vni, &vpn->import_rt);
  memcpy (&vpn->export_rt, &vpn->import_rt, sizeof (struct ecommunity_val));
}

/*
 * bgp_evpn_new
 *
 * Create a new vpn
 */
static struct bgpevpn *
bgp_evpn_new (struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;

  if (!bgp)
    return NULL;

  /*
   * Allocate new vpn
   */
  vpn = XCALLOC (MTYPE_BGP_EVPN, sizeof (struct bgpevpn));

  if (!vpn)
    return NULL;

  /* Set values - RD and RT set to defaults. */
  vpn->vni = vni;
  bgp_evpn_derive_rd_rt (bgp, vpn);

  /* Add to hash */
  if (!hash_get(bgp->vnihash, vpn, hash_alloc_intern))
    {
      XFREE(MTYPE_BGP_EVPN, vpn);
      return NULL;
    }

  return(vpn);
}

/*
 * bgp_evpn_free
 *
 * Free a given VPN
 */
static void
bgp_evpn_free (struct bgp *bgp, struct bgpevpn *vpn)
{
  if (vpn)
  {
    hash_release(bgp->vnihash, vpn);
    XFREE(MTYPE_BGP_EVPN, vpn);
  }
}

/*
 * bgp_evpn_lookup_vpn
 *
 * Function to lookup vpn for the given vni
 */
static struct bgpevpn *
bgp_evpn_lookup_vpn (struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;
  struct bgpevpn tmp;

  memset(&tmp, 0, sizeof(struct bgpevpn));
  tmp.vni = vni;
  vpn = hash_lookup(bgp->vnihash, &tmp);
  return(vpn);
}

/*
 * bgp_evpn_free_all_vni_iterator
 *
 * Iterate through the hash and free VPNs.
 */
static void
bgp_evpn_free_all_vni_iterator (struct hash_backet *backet, struct bgp *bgp)
{
  struct bgpevpn *vpn;

  vpn = (struct bgpevpn *) backet->data;
  bgp_evpn_free(bgp, vpn);
  return;
}

static int
bgp_evpn_create_type3_route (struct bgp *bgp, struct bgpevpn *vpn)
{
  struct prefix_evpn p;
  struct bgp_node *rn;
  struct attr attr;
  struct bgp_info *ri;
  struct attr *attr_new;
  afi_t afi = AFI_L2VPN;
  safi_t safi = SAFI_EVPN;

  memset (&attr, 0, sizeof (struct attr));

  /* Build prefix and create route node. EVPN routes have a 2-level
   * tree (RD-level + Prefix-level) similar to L3VPN routes.
   */
  build_evpn_type3_prefix (&p, bgp->router_id);
  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi,
                         (struct prefix *)&p, &vpn->prd);

  /* Build path-attribute for this route. */
  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);
  /* Set up RT extended community. */
  /* TODO: Only 1 RT supported now. */
  (bgp_attr_extra_get (&attr))->ecommunity =
    ecommunity_parse ((u_int8_t *)&vpn->export_rt.val, ECOMMUNITY_SIZE);
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);

  /* Add to hash. */
  attr_new = bgp_attr_intern (&attr);

  /* See if this is an update of an existing route, or a new add. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
        && ri->type == ZEBRA_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* TODO: Handle update -- when does this happen? */
  if (ri)
    {
      zlog_err ("Found existing type-3 route for VNI %u at Add", vpn->vni);
      return -1;
    }

  /* Create new route. */
  ri = info_make (ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
                  bgp->peer_self, attr_new, rn);
  SET_FLAG (ri->flags, BGP_INFO_VALID);
  bgp_info_add (rn, ri);
  bgp_unlock_node (rn);

  /* Schedule for processing. */
  bgp_process (bgp, rn, afi, safi);

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);

  return 0;
}

static int
bgp_evpn_delete_type3_route (struct bgp *bgp, struct bgpevpn *vpn)
{
  struct prefix_evpn p;
  struct bgp_node *rn;
  struct bgp_info *ri;
  afi_t afi = AFI_L2VPN;
  safi_t safi = SAFI_EVPN;

  /* Build prefix and locate route node. */
  build_evpn_type3_prefix (&p, bgp->router_id);
  rn = bgp_afi_node_lookup (bgp->rib[afi][safi], afi, safi,
                         (struct prefix *)&p, &vpn->prd);

  if (!rn)
    {
      /* TODO: Temporary, can ignore entry not found at delete. */
      zlog_err ("Could not find type-3 route for VNI %u at Del", vpn->vni);
      return -1;
    }

  /* Now, find matching route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
	&& ri->type == ZEBRA_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  if (!ri)
    {
      /* TODO: Temporary, can ignore entry not found at delete. */
      zlog_err ("Could not find type-3 route info for VNI %u at Del, RN %p",
                vpn->vni, rn);
      bgp_unlock_node (rn);
      return -1;
    }

  /* Mark route for delete and schedule for processing. */
  bgp_info_delete (rn, ri);
  bgp_process (bgp, rn, afi, safi);

  return 0;
}

static int
bgp_evpn_process_type3_route (struct peer *peer, afi_t afi, safi_t safi,
                              struct attr *attr, u_char *pfx, int psize,
                              u_int32_t addpath_id)
{
  struct prefix_rd prd;
  struct prefix_evpn p;
  u_char ipaddr_len;
  int ret;

  /* Type-3 route should be either 17 or 29 bytes: RD (8), Eth Tag (4),
   * IP len (1) and IP (4 or 16).
   */
  if (psize != 17 && psize != 29)
    {
      zlog_err ("%u:%s - Rx EVPN NLRI with invalid length %d",
                peer->bgp->vrf_id, peer->host, psize);
      return -1;
    }

  /* Make prefix_rd */
  prd.family = AF_UNSPEC;
  prd.prefixlen = 64;
  memcpy (&prd.val, pfx, 8);
  pfx += 8;

  /* Make EVPN prefix. */
  memset (&p, 0, sizeof (struct prefix_evpn));
  p.family = AF_ETHERNET;
  p.prefixlen = EVPN_TYPE_3_ROUTE_PREFIXLEN;
  p.prefix.route_type = BGP_EVPN_IMET_ROUTE;

  /* Skip over Ethernet Tag for now. */
  pfx += 4;

  /* Get the IP. */
  ipaddr_len = *pfx++;
  if (ipaddr_len == 4)
    p.prefix.flags = IP_ADDR_V4;
  else
    p.prefix.flags = IP_ADDR_V6;
  memcpy (&p.prefix.ip, pfx, ipaddr_len);

  /* Process the route. */
  if (attr)
    ret = bgp_update (peer, (struct prefix *)&p, addpath_id, attr, afi, safi,
                      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0);
  else
    ret = bgp_withdraw (peer, (struct prefix *)&p, addpath_id, attr, afi, safi,
                        ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL);
  return ret;
}

static int
bgp_evpn_extract_vni_from_rt (struct attr *attr, vni_t *vni)
{
  struct attr_extra *attre = attr->extra;
  u_char *pnt;
  u_char rt_type;
  vni_t route_vni = 0;

  assert (attre);
  assert (attre->ecommunity);
  assert (attre->ecommunity->val);
  pnt = attre->ecommunity->val;
  rt_type = *pnt;
  if (rt_type == ECOMMUNITY_ENCODE_AS)
    {
      u_char *c = pnt + 4;
      u_int32_t val;

      val = ((u_int32_t) *c++ << 24);
      val |= ((u_int32_t) *c++ << 16);
      val |= ((u_int32_t) *c++ << 8);
      val |= (u_int32_t) *c;
      if (val > UINT16_MAX)
        {
          zlog_err ("Received RT value %u too large", val);
          return -1;
        }
      route_vni = (vni_t) val;
    }
  else if (rt_type == ECOMMUNITY_ENCODE_IP
           || rt_type == ECOMMUNITY_ENCODE_AS4)
    {
      u_char *c = pnt + 6;
      u_int16_t val;

      val = ((u_int16_t) *c++ << 8);
      val |= (u_int16_t) *c;

      route_vni = (vni_t) val;
    }

  *vni = route_vni;
  return 0;
}

static int
bgp_zebra_send_remote_vtep (struct bgp *bgp, struct bgpevpn *vpn,
                            struct prefix_evpn *p, int add)
{
  struct stream *s;

  /* Check socket. */
  if (!zclient || zclient->sock < 0)
    return 0;

  /* Don't try to register if Zebra doesn't know of this instance. */
  if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp))
    return 0;

  s = zclient->obuf;
  stream_reset (s);

  zclient_create_header (s, add ? ZEBRA_REMOTE_VTEP_ADD : ZEBRA_REMOTE_VTEP_DEL,
                         bgp->vrf_id);
  stream_putl(s, vpn->vni);
  stream_putc(s, 0); // flags - unused
  if (p->prefix.flags & IP_ADDR_V4)
    {
      stream_putw(s, AF_INET);
      stream_putc(s, IPV4_MAX_BITLEN);
      stream_put_in_addr(s, &p->prefix.ip.v4_addr);
    }
  else if (p->prefix.flags & IP_ADDR_V6)
    {
      stream_putw(s, AF_INET6);
      stream_putc(s, IPV6_MAX_BITLEN);
      stream_put(s, &p->prefix.ip.v6_addr, IPV6_MAX_BYTELEN);
    }

  stream_putw_at (s, 0, stream_get_endp (s));

  return zclient_send_message(zclient);
}

/*
 * Install type-3 route into zebra (as remote VTEP). If VNI is non-zero,
 * install only routes matching this VNI.
 */
static int
bgp_evpn_install_type3_route (struct bgp *bgp, afi_t afi, safi_t safi,
                              struct prefix_evpn *evp, struct bgp_info *ri,
                              vni_t vni)
{
  struct attr *attr = ri->attr;
  vni_t route_vni;
  struct bgpevpn *vpn;

  assert (attr);
  /* If we don't have Route Target, nothing much to do. */
  if (!(attr->flag & ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES)))
    return 0;

  /* Extract VNI from RT */
  if (bgp_evpn_extract_vni_from_rt (attr, &route_vni))
    {
      zlog_err ("%u: Failed to extract VNI from RT in type-3 route",
                bgp->vrf_id);
      return -1;
    }

  /* If a VNI is specified to match on, it means it is already known locally
   * and we want to install only matching routes.
   */
  if (vni && vni == route_vni)
    {
      vpn = bgp_evpn_lookup_vpn (bgp, vni);
      assert (vpn);
      return bgp_zebra_send_remote_vtep (bgp, vpn, evp, 1);
    }

  /* We are dealing with a received type-3 route. Inform zebra if this
   * is a "live" VNI - i.e., known locally.
   */
  vpn = bgp_evpn_lookup_vpn (bgp, route_vni);
  if (vpn && CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
    return bgp_zebra_send_remote_vtep (bgp, vpn, evp, 1);

  return 0;
}

/*
 * Uninstall type-3 route from zebra.
 */
static int
bgp_evpn_uninstall_type3_route (struct bgp *bgp, afi_t afi, safi_t safi,
                              struct prefix_evpn *evp, struct bgp_info *ri)
{
  struct attr *attr = ri->attr;
  vni_t route_vni;
  struct bgpevpn *vpn;

  assert (attr);
  /* If we don't have Route Target, nothing much to do. */
  if (!(attr->flag & ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES)))
    return 0;

  /* Extract VNI from RT */
  if (bgp_evpn_extract_vni_from_rt (attr, &route_vni))
    {
      zlog_err ("%u: Failed to extract VNI from RT in type-3 route",
                bgp->vrf_id);
      return -1;
    }

  /* If this is already a "live" VNI, remove remote VTEP from zebra. */
  vpn = bgp_evpn_lookup_vpn (bgp, route_vni);
  if (vpn && CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
    return bgp_zebra_send_remote_vtep (bgp, vpn, evp, 0);

  return 0;
}

/*
 * VNI is known locally, install any existing type-3 routes (remote VTEPs)
 * for this VNI.
 */
static int
bgp_evpn_install_existing_type3_routes (struct bgp *bgp, struct bgpevpn *vpn)
{
  vni_t vni;
  afi_t afi;
  safi_t safi;
  struct bgp_node *rd_rn, *rn;
  struct bgp_table *table;
  struct bgp_info *ri;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;
  vni = vpn->vni;

  /* TODO: We're walking entire table, this should be optimized later. */
  /* EVPN routes are a 2-level table. */
  for (rd_rn = bgp_table_top(bgp->rib[afi][safi]); rd_rn; rd_rn = bgp_route_next (rd_rn))
    {
      table = (struct bgp_table *)(rd_rn->info);
      if (table)
        {
          for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
            {
              struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

              if (evp->prefix.route_type != BGP_EVPN_IMET_ROUTE)
                continue;

              for (ri = rn->info; ri; ri = ri->next)
                {
                   if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
                       && ri->type == ZEBRA_ROUTE_BGP
                       && ri->sub_type == BGP_ROUTE_NORMAL)
                     bgp_evpn_install_type3_route (bgp, afi, safi,
                                                   evp, ri, vni);
                }
            }
        }
    }

  return 0;
}

/*
 * Public functions.
 */

/*
 * bgp_evpn_update_vni
 *
 * Create vpn for the given vni if not already created.
 */
void
bgp_evpn_update_vni (struct bgp *bgp, vni_t vni, int add)
{
  struct bgpevpn *vpn;

  if (!bgp->vnihash)
    return;

  vpn = bgp_evpn_lookup_vpn(bgp, vni);
  if (add)
    {
      if (!vpn)
        {
          vpn = bgp_evpn_new(bgp, vni);
          if (vpn)
            hash_get(bgp->vnihash, vpn, hash_alloc_intern);
        }
    }
  else
    {
      bgp_evpn_free(bgp, vpn);
    }
  return;
}

/*
 * Handle add of a local VNI.
 * TODO: Cannot handle VNI larger than UINT16_MAX
 */
int
bgp_evpn_local_vni_add (struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;

  if (!bgp->vnihash)
    {
      zlog_err ("%u: VNI hash not created", bgp->vrf_id);
      return -1;
    }

  if (vni > UINT16_MAX)
    {
      zlog_err ("%u: VNI %u too large, cannot be handled by EVPN",
                bgp->vrf_id, vni);
      return -1;
    }

  /* Add VNI hash (or update, if already present (e.g., configured) */
  vpn = bgp_evpn_lookup_vpn (bgp, vni);
  if (!vpn)
    {
      vpn = bgp_evpn_new (bgp, vni);
      if (!vpn)
        {
          zlog_err ("%u: Failed to allocate VNI entry for VNI %u",
                    bgp->vrf_id, vni);
          return -1;
        }
    }

  /* Mark as locally "learnt" */
  SET_FLAG (vpn->flags, VNI_FLAG_LOCAL);

  /* Create EVPN type-3 route and schedule for processing. */
  if (bgp_evpn_create_type3_route (bgp, vpn))
    {
      zlog_err ("%u: Type3 route creation failure for VNI %u",
                bgp->vrf_id, vni);
      return -1;
    }

  /* If we have already learnt remote VTEPs for this VNI, install them. */
  bgp_evpn_install_existing_type3_routes (bgp, vpn);

  return 0;
}

/*
 * Handle del of a local VNI.
 */
int
bgp_evpn_local_vni_del (struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;

  if (!bgp->vnihash)
    {
      zlog_err ("%u: VNI hash not created", bgp->vrf_id);
      return -1;
    }

  /* Locate VNI hash */
  vpn = bgp_evpn_lookup_vpn (bgp, vni);
  if (!vpn)
    {
      zlog_warn ("%u: VNI hash entry for VNI %u not found at DEL",
                 bgp->vrf_id, vni);
      return 0;
    }

  /* Remove EVPN type-3 route and schedule for processing. */
  bgp_evpn_delete_type3_route (bgp, vpn);

  /* Clear locally "learnt" flag and see if hash needs to be freed. */
  UNSET_FLAG (vpn->flags, VNI_FLAG_LOCAL);
  if (!CHECK_FLAG (vpn->flags, VNI_FLAG_CONFIGURED))
    bgp_evpn_free(bgp, vpn);

  return 0;
}

static void
bgp_evpn_display_vni (struct vty *vty, struct bgpevpn *vpn)
{
  char buf1[INET6_ADDRSTRLEN];
  struct rd_as rd_as;

  vty_out (vty, "VNI: %d%s", vpn->vni, VTY_NEWLINE);
  vty_out (vty, "  RD: %s%s", prefix_rd2str (&vpn->prd, buf1, RD_ADDRSTRLEN), 
                VTY_NEWLINE);
  decode_rd_as((u_char *)vpn->import_rt.val+2, &rd_as);
  vty_out (vty, "  Import Route Target: %u:%d%s", rd_as.as, rd_as.val, 
                VTY_NEWLINE);
  decode_rd_as((u_char *)vpn->export_rt.val+2, &rd_as);
  vty_out (vty, "  Export Route Target: %u:%d%s", rd_as.as, rd_as.val,
                VTY_NEWLINE);
}

void
bgp_evpn_show_one_vni (struct vty *vty, struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;

  vpn = bgp_evpn_lookup_vpn (bgp, vni);
  if (!vpn)
    {
      vty_out (vty, "VNI not found%s", VTY_NEWLINE);
      return;
    }
  bgp_evpn_display_vni (vty, vpn);
}

/*
 * Display a VNI (upon user query).
 */
void
bgp_evpn_show_vni (struct hash_backet *backet, struct vty *vty)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  bgp_evpn_display_vni (vty, vpn);
}

/*
 * Encode EVPN prefix in Update (MP_REACH)
 */
void
bgp_evpn_encode_prefix (struct stream *s, struct prefix *p,
                        struct prefix_rd *prd, int addpath_encode,
                        u_int32_t addpath_tx_id)
{
  struct prefix_evpn *evp = (struct prefix_evpn *)p;

  if (addpath_encode)
    stream_putl (s, addpath_tx_id);

  /* Route type */
  stream_putc (s, evp->prefix.route_type);

  switch (evp->prefix.route_type)
    {
      case BGP_EVPN_IMET_ROUTE:
        stream_putc (s, 17); // TODO: Hardcoded for now
        stream_put (s, prd->val, 8); /* RD */
        stream_putl (s, 0); /* Ethernet Tag ID */
        stream_putc (s, 4); /* IP address Length */
        /* Originating Router's IP Addr */
        stream_put_in_addr (s, &evp->prefix.ip.v4_addr);
        break;

      default:
        break;
    }
}

/*
 * Perform sanity check on EVPN NLRI.
 * TODO: Not yet implemented.
 */
int
bgp_evpn_nlri_sanity_check (struct peer *peer, int afi, safi_t safi,
                            u_char *pnt, bgp_size_t length, int *numpfx)
{
  return 0;
}

/*
 * Process EVPN NLRI, create/update/delete route and schedule for processing.
 */
int
bgp_evpn_nlri_parse (struct peer *peer, struct attr *attr, struct bgp_nlri *packet)
{
  u_char *pnt;
  u_char *lim;
  afi_t afi;
  safi_t safi;
  u_int32_t addpath_id;
  int addpath_encoded;
  int psize = 0;
  u_char rtype;
  u_char rlen;
  struct prefix p;

  /* Check peer status. */
  if (peer->status != Established)
    {
      zlog_err ("%u:%s - EVPN update received in state %d",
                peer->bgp->vrf_id, peer->host, peer->status);
      return -1;
    }

  /* Start processing the NLRI - there may be multiple in the MP_REACH */
  pnt = packet->nlri;
  lim = pnt + packet->length;
  afi = packet->afi;
  safi = packet->safi;
  addpath_id = 0;

  addpath_encoded = (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) &&
                     CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV));

#define VPN_PREFIXLEN_MIN_BYTES (3 + 8) /* label + RD */
  for (; pnt < lim; pnt += psize)
    {
      /* Clear prefix structure. */
      memset (&p, 0, sizeof (struct prefix));

      /* Deal with path-id if AddPath is supported. */
      if (addpath_encoded)
        {
          /* When packet overflow occurs return immediately. */
          if (pnt + BGP_ADDPATH_ID_LEN > lim)
            return -1;

          addpath_id = ntohl(*((uint32_t*) pnt));
          pnt += BGP_ADDPATH_ID_LEN;
        }

      /* All EVPN NLRI types start with type and length. */
      if (pnt + 2 > lim)
        return -1;

      rtype = *pnt++;
      psize = rlen = *pnt++;

      /* When packet overflow occur return immediately. */
      if (pnt + psize > lim)
        return -1;

      switch (rtype)
        {
          case BGP_EVPN_IMET_ROUTE:
            if (bgp_evpn_process_type3_route (peer, afi, safi, attr,
                                              pnt, psize, addpath_id))
              {
                zlog_err ("%u:%s - Error in processing EVPN type-3 NLRI size %d",
                          peer->bgp->vrf_id, peer->host, psize);
                return -1;
              }

            break;

          default:
            break;
        }

    }

  /* Packet length consistency check. */
  if (pnt != lim)
    return -1;

  return 0;
}

/*
 * Install EVPN route into zebra, if appropriate.
 * TODO: There are some assumptions here such as auto-RD and auto-RT.
 */
int
bgp_evpn_install_route (struct bgp *bgp, afi_t afi, safi_t safi,
                        struct prefix *p, struct bgp_info *ri)
{
  struct prefix_evpn *evp = (struct prefix_evpn *)p;
  int ret = 0;

  switch (evp->prefix.route_type)
    {
      case BGP_EVPN_IMET_ROUTE:
        ret = bgp_evpn_install_type3_route (bgp, afi, safi, evp, ri, 0);
        break;

      default:
        break;
    }

  return ret;
}

/*
 * Uninstall EVPN route from zebra, if appropriate.
 */
int
bgp_evpn_uninstall_route (struct bgp *bgp, afi_t afi, safi_t safi,
                          struct prefix *p, struct bgp_info *ri)
{
  struct prefix_evpn *evp = (struct prefix_evpn *)p;
  int ret = 0;

  switch (evp->prefix.route_type)
    {
      case BGP_EVPN_IMET_ROUTE:
        ret = bgp_evpn_uninstall_type3_route (bgp, afi, safi, evp, ri);
        break;

      default:
        break;
    }

  return ret;
}

/*
 * bgp_evpn_init
 *
 * Initialize vnihash.
 */
void
bgp_evpn_init (struct bgp *bgp)
{
  bgp->vnihash = hash_create(vni_hash_key_make, vni_hash_cmp);
}

/*
 * bgp_evpn_cleanup
 *
 * Cleanup all BGP EVPN cache.
 */
void
bgp_evpn_cleanup (struct bgp *bgp)
{
  hash_iterate (bgp->vnihash,
                (void (*) (struct hash_backet *, void *))
                bgp_evpn_free_all_vni_iterator,
                bgp);
  hash_free(bgp->vnihash);
  bgp->vnihash = NULL;
}

static void
bgp_evpn_cleanup_local_vni_and_withdraw_route_iterator (struct hash_backet *backet, 
                                                        struct bgp *bgp)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  
  /* Remove EVPN type-3 route and schedule for processing. */
  bgp_evpn_delete_type3_route (bgp, vpn);

  /* Clear locally "learnt" flag and see if hash needs to be freed. */
  UNSET_FLAG (vpn->flags, VNI_FLAG_LOCAL);
  if (!CHECK_FLAG (vpn->flags, VNI_FLAG_CONFIGURED))
    bgp_evpn_free(bgp, vpn);
}

/* Function to register/deregister advertise_vni with zebra */
void
bgp_evpn_update_advertise_vni (struct bgp *bgp)
{
  zlog_debug("%s:Update advertise vni flag:%d in zebra\n", __FUNCTION__,
                                                        bgp->advertise_vni);
  bgp_zebra_advertise_vni (bgp, bgp->advertise_vni);

  /* Cleanup for 'no advertise-vni' */
  if (!bgp->advertise_vni)
    {
      hash_iterate (bgp->vnihash,
                (void (*) (struct hash_backet *, void *))
                bgp_evpn_cleanup_local_vni_and_withdraw_route_iterator,
                bgp);
    } 
}

int
bgp_evpn_print_prefix (struct vty *vty, struct prefix_evpn *p)
{
  int len = 0;

  if (p->prefix.route_type == BGP_EVPN_IMET_ROUTE)
    {
      len = vty_out (vty, "[%d]:[0]:[%d]:[%s]",p->prefix.route_type,
                     (p->prefix.flags == IP_ADDR_V4)? IP_ADDR_V4:IP_ADDR_V6,
                     inet_ntoa(p->prefix.ip.v4_addr));
    }
  return len;
}
