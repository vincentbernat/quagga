/*
 * Zebra EVPN for VxLAN code
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#if defined(HAVE_EVPN)

#include "if.h"
#include "prefix.h"
#include "table.h"
#include "memory.h"
#include "log.h"
#include "linklist.h"
#include "stream.h"
#include "hash.h"
#include "jhash.h"

#include "zebra/rib.h"
#include "zebra/rt.h"
#include "zebra/zebra_ns.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/interface.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_vxlan.h"

/* definitions */
typedef struct zebra_vni_t_ zebra_vni_t;

/*
 * VNI hash table
 *
 * For each VNI that is locally defined, this table has the pointer to the
 * local interface.
 */
struct zebra_vni_t_
{
  /* VNI - key */
  vni_t vni;

  /* Corresponding VxLAN interface. */
  struct interface *vxlan_if;
};


/* static function declarations */
static unsigned int
vni_hash_keymake (void *p);
static int
vni_hash_cmp (const void *p1, const void *p2);
static void *
zvni_alloc (void *p);
static zebra_vni_t *
zvni_lookup (struct zebra_vrf *zvrf, vni_t vni);
static zebra_vni_t *
zvni_add (struct zebra_vrf *zvrf, vni_t vni);
static int
zvni_del (struct zebra_vrf *zvrf, zebra_vni_t *zvni);
static void
zserv_encode_vni (struct stream *s, vni_t vni);
static int
zvni_send_add_to_client (struct zebra_vrf *zvrf, vni_t vni);
static int
zvni_send_del_to_client (struct zebra_vrf *zvrf, vni_t vni);

/* Private functions */
/*
 * Hash function for VNI.
 */
static unsigned int
vni_hash_keymake (void *p)
{
  const zebra_vni_t *zvni = p;

  return (jhash_1word(zvni->vni, 0));
}

/*
 * Compare 2 VNI hash entries.
 */
static int
vni_hash_cmp (const void *p1, const void *p2)
{
  const zebra_vni_t *zvni1 = p1;
  const zebra_vni_t *zvni2 = p2;

  return (zvni1->vni == zvni2->vni);
}

/*
 * Callback to allocate VNI hash entry.
 */
static void *
zvni_alloc (void *p)
{
  const zebra_vni_t *tmp_vni = p;
  zebra_vni_t *zvni;

  zvni = XCALLOC (MTYPE_ZVNI, sizeof(zebra_vni_t));
  zvni->vni = tmp_vni->vni;
  return ((void *)zvni);
}

static zebra_vni_t *
zvni_lookup (struct zebra_vrf *zvrf, vni_t vni)
{
  zebra_vni_t tmp_vni;
  zebra_vni_t *zvni = NULL;

  memset (&tmp_vni, 0, sizeof (zebra_vni_t));
  tmp_vni.vni = vni;
  zvni = hash_lookup (zvrf->vni_table, &tmp_vni);

  return zvni;
}

/*
 * Add VNI hash entry.
 */
static zebra_vni_t *
zvni_add (struct zebra_vrf *zvrf, vni_t vni)
{
  zebra_vni_t tmp_zvni;
  zebra_vni_t *zvni = NULL;

  memset (&tmp_zvni, 0, sizeof (zebra_vni_t));
  tmp_zvni.vni = vni;
  zvni = hash_get (zvrf->vni_table, &tmp_zvni, zvni_alloc);
  assert (zvni);

  return zvni;
}

/*
 * Delete VNI hash entry.
 */
static int
zvni_del (struct zebra_vrf *zvrf, zebra_vni_t *zvni)
{
  zebra_vni_t *tmp_zvni;

  zvni->vxlan_if = NULL;

  /* TODO: Handle remote VTEPs. */

  /* Free the VNI hash entry and allocated memory. */
  tmp_zvni = hash_release (zvrf->vni_table, zvni);
  if (tmp_zvni)
    XFREE(MTYPE_ZVNI, tmp_zvni);

  return 0;
}

/*
 * Encode VNI in client message.
 */
static void
zserv_encode_vni (struct stream *s, vni_t vni)
{
  stream_putl (s, vni);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));
}

/*
 * Inform BGP about local VNI addition.
 */
static int
zvni_send_add_to_client (struct zebra_vrf *zvrf, vni_t vni)
{
  struct zserv *client;
  struct stream *s;

  client = zebra_find_client (ZEBRA_ROUTE_BGP);
  /* BGP may not be running. */
  if (!client)
    return 0;

  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, ZEBRA_VNI_ADD, zvrf->vrf_id);
  zserv_encode_vni (s, vni);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Send VNI_ADD %u to BGP", zvrf->vrf_id, vni);

  client->vniadd_cnt++;
  return zebra_server_send_message(client);
}

/*
 * Inform BGP about local VNI deletion.
 */
static int
zvni_send_del_to_client (struct zebra_vrf *zvrf, vni_t vni)
{
  struct zserv *client;
  struct stream *s;

  client = zebra_find_client (ZEBRA_ROUTE_BGP);
  /* BGP may not be running. */
  if (!client)
    return 0;

  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, ZEBRA_VNI_DEL, zvrf->vrf_id);
  zserv_encode_vni (s, vni);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Send VNI_DEL %u to BGP", zvrf->vrf_id, vni);

  client->vnidel_cnt++;
  return zebra_server_send_message(client);
}


/* Public functions */

/*
 * Handle VxLAN interface add. Store the VNI (in hash table) and update BGP,
 * if required.
 */
int
zebra_vxlan_if_add (struct interface *ifp, vni_t vni)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  zebra_vni_t *zvni;

  zif = ifp->info;
  assert(zif);

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Add intf %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);

  /* Store VNI in interface. */
  zif->vni = vni;

  /* If hash entry exists (how?), nothing to do; else, add. */
  if (zvni_lookup (zvrf, vni))
    return 0;

  zvni = zvni_add (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to add VNI hash, VRF %d IF %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);
      return -1;
    }

  zvni->vxlan_if = ifp;

  /* Inform BGP if required. */
  if (!zvrf->advertise_vni)
    return 0;

  zvni_send_add_to_client (zvrf, vni);
  return 0;
}

/*
 * Handle VxLAN interface delete. Locate and remove entry in hash table
 * and update BGP, if required.
 */
int
zebra_vxlan_if_del (struct interface *ifp)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  vni_t vni;
  zebra_vni_t *zvni;

  zif = ifp->info;
  assert(zif);

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  vni = vni_from_intf (ifp);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Del intf %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);

  /* Locate hash entry; it is expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to locate VNI hash at del, VRF %d IF %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);
      return 0;
    }

  /* Inform BGP if required. */
  if (zvrf->advertise_vni)
    zvni_send_del_to_client (zvrf, zvni->vni);

  /* Delete the hash entry. */
  if (zvni_del (zvrf, zvni))
    {
      zlog_err ("Failed to del VNI hash %p, VRF %d IF %s(%u) VNI %u",
                zvni, ifp->vrf_id, ifp->name, ifp->ifindex, zvni->vni);
      return -1;
    }

  /* Clear VNI in interface. */
  zif->vni = 0;

  return 0;
}

/*
 * Allocate VNI hash table for this VRF and do other initialization.
 * NOTE: Currently supported only for default VRF.
 */
void
zebra_vxlan_init_tables (struct zebra_vrf *zvrf)
{
  if (!zvrf)
    return;
  zvrf->vni_table = hash_create(vni_hash_keymake, vni_hash_cmp);
  zvrf->advertise_vni = 1; // TMP
}
#endif /* HAVE_EVPN */
