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

#define EVPN_TYPE_3_ROUTE_PREFIXLEN      192

#if defined(HAVE_EVPN)

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
#define VNI_FLAG_LEARNT       0x2

  /* RD for this VNI. */
  struct prefix_rd          prd;

  /* Import and Export RTs. */
  /* TODO: Only 1 each supported. */
  struct ecommunity_val     import_rt;
  struct ecommunity_val     export_rt;
};


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

  /* Mark as "learnt" */
  SET_FLAG (vpn->flags, VNI_FLAG_LEARNT);

  /* Create EVPN type-3 route and schedule for processing. */
  return bgp_evpn_create_type3_route (bgp, vpn);
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

  /* Clear "learnt" flag and see if hash needs to be freed. */
  UNSET_FLAG (vpn->flags, VNI_FLAG_LEARNT);
  if (!CHECK_FLAG (vpn->flags, (VNI_FLAG_CONFIGURED | VNI_FLAG_LEARNT)))
    bgp_evpn_free(bgp, vpn);

  return 0;
}

/*
 * Display a VNI (upon user query).
 */
void
bgp_evpn_show_vni (struct hash_backet *backet, struct vty *vty)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  vty_out (vty, "%d     %s%s", vpn->vni, "local", VTY_NEWLINE);
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
  return 0;
}

/*
 * bgp_evpn_init
 *
 * Initialize vnihash. Do this only if HAVE_EVPN flag is enabled.
 */
void
bgp_evpn_init (struct bgp *bgp)
{
  bgp->vnihash = hash_create(vni_hash_key_make, vni_hash_cmp);
  bgp->advertise_vni = 1; // TODO: Temporary initialization
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

#else

void
bgp_evpn_update_vni (struct bgp* bgp, vni_t vni, int add)
{
}

int
bgp_evpn_local_vni_add (struct bgp *bgp, vni_t vni)
{
  return 0;
}

int
bgp_evpn_local_vni_del (struct bgp *bgp, vni_t vni)
{
  return 0;
}

void
bgp_evpn_show_vni (struct hash_backet *backet, struct vty *vty)
{
}

void
bgp_evpn_encode_prefix (struct stream *s, struct prefix *p,
                        struct prefix_rd *prd, int addpath_encode,
                        u_int32_t addpath_tx_id)
{
}

int
bgp_evpn_nlri_sanity_check (struct peer *peer, int afi, safi_t safi,
                            u_char *pnt, bgp_size_t length, int *numpfx)
{
  return 0;
}

int
bgp_evpn_nlri_parse (struct peer *peer, struct attr *attr, struct bgp_nlri *packet)
{
  return 0;
}

void
bgp_evpn_init (struct bgp *bgp)
{
}

void
bgp_evpn_cleanup (struct bgp *bgp)
{
}

#endif /* HAVE_EVPN */
