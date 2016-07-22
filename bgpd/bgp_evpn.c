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
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"

#if defined(HAVE_EVPN)

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
 * decode_rd_as
 *
 * Function to decode rd with AS
 * type == RD_TYPE_AS
 */
static void
decode_rd_as (u_char *pnt, struct rd_as *rd_as)
{
  rd_as->as = (u_int16_t) *pnt++ << 8;
  rd_as->as |= (u_int16_t) *pnt++;

  rd_as->val = ((u_int32_t) *pnt++ << 24);
  rd_as->val |= ((u_int32_t) *pnt++ << 16);
  rd_as->val |= ((u_int32_t) *pnt++ << 8);
  rd_as->val |= (u_int32_t) *pnt;
}

/*
 * bgp_evpn_print_rd
 *
 * Function to print prefix_rd.
 */
void
bgp_evpn_print_rd (struct prefix_rd *rd)
{
  struct rd_as rd_as;
  u_char *pnt;

  pnt = rd->val;

  decode_rd_as (pnt + RD_TYPE, &rd_as);
  zlog_debug("%u:%d", rd_as.as, rd_as.val);
  return;
}

/*
 * bgp_evpn_update_rd_rt
 *
 * Function to set default asn:vni to rd and rt.
 */
void
bgp_evpn_update_rd_rt (struct bgp *bgp, struct bgpevpn *vpn)
{
  struct stream *s;

  s = stream_new (RD_VAL);

  vpn->prd.family = AF_UNSPEC;
  vpn->prd.prefixlen = 64;

  stream_putw (s, RD_TYPE_AS);
  stream_putw (s, bgp->as);
  stream_putw (s, vpn->vni);
  memcpy(&vpn->prd.val, s->data, RD_VAL);
  memcpy(&vpn->rt_prd.val, s->data, RD_VAL);
  return;
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

  /* Set values */
  vpn->bgp = bgp;
  vpn->vni = vni;
  bgp_evpn_update_rd_rt(bgp, vpn);
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
struct bgpevpn *
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
 * bgp_evpn_init
 *
 * Initialize vnihash. Do this only if HAVE_EVPN flag is enabled.
 */
void
bgp_evpn_init (struct bgp *bgp)
{
#ifdef HAVE_EVPN
  bgp->vnihash = hash_create(vni_hash_key_make, vni_hash_cmp);
#endif
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

/*
 * bgp_evpn_cleanup
 *
 * Cleanup all BGP EVPN cache.
 */
void
bgp_evpn_cleanup (struct bgp *bgp)
{
#ifdef HAVE_EVPN
  hash_iterate (bgp->vnihash,
                (void (*) (struct hash_backet *, void *))
                bgp_evpn_free_all_vni_iterator,
                bgp);
  hash_free(bgp->vnihash);
  bgp->vnihash = NULL;
#endif
}

#else

void
bgp_evpn_init (struct bgp *bgp)
{
  return;
}

void 
bgp_evpn_update_vni (struct bgp*, vni_t, int)
{
  return;
}

void 
bgp_evpn_print_rd (struct prefix_rd *)
{
  return;
}

void 
bgp_evpn_update_rd_rt (struct bgp *, struct bgpevpn *)
{
  return;
}

struct bgpevpn *
bgp_evpn_lookup_vpn (struct bgp *, vni_t)
{
  return(NULL);
}

void
bgp_evpn_cleanup (struct bgp *bgp)
{
  return;
}

#endif /* HAVE_EVPN */
