/*
 * Zebra Layer-2 interface handling code
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
#include "zebra/zebra_memory.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt_netlink.h"
#include "zebra/zebra_l2.h"

/* definitions */

/* static function declarations */

/* Private functions */
static void
map_slaves_to_bridge (struct interface *br_if, int link)
{
  struct listnode *node;
  struct interface *ifp;
  vrf_iter_t iter;

  for (iter = vrf_first (); iter != VRF_ITER_INVALID; iter = vrf_next (iter))
    {
      for (ALL_LIST_ELEMENTS_RO (vrf_iter2iflist (iter), node, ifp))
        {
          struct zebra_l2info_brslave *br_slave;

          if (!ifp->info)
            continue;
          if (!IS_ZEBRA_IF_BRIDGE_SLAVE (ifp))
            continue;

          /* NOTE: This assumes 'zebra_l2info_brslave' is the first field
           * for any L2 interface.
           */
          br_slave = (struct zebra_l2info_brslave *)
                         (((struct zebra_if *)ifp->info)->l2if);
          assert (br_slave);

          if (link)
            {
              if (br_slave->bridge_ifindex == br_if->ifindex)
                br_slave->br_if = br_if;
            }
          else
            {
              if (br_slave->br_if == br_if)
                br_slave->br_if = NULL;
            }
        }
    }
}

static int
zl2if_del (struct interface *ifp)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;

  zif = ifp->info;
  assert(zif);

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* Free the L2 interface */
  if (zif->l2if)
    {
      XFREE (MTYPE_ZEBRA_L2IF, zif->l2if);
      zif->l2if = NULL;
    }

  return 0;
}

/* Public functions */
void
zebra_l2_map_slave_to_bridge (struct zebra_l2info_brslave *br_slave)
{
  struct interface *br_if;

  /* TODO: Handle change of master */
  br_if = if_lookup_by_index_per_ns (zebra_ns_lookup (NS_DEFAULT),
                                     br_slave->bridge_ifindex);
  if (br_if)
    br_slave->br_if = br_if;
}

/*
 * Handle Bridge interface add or update. Create/update Bridge L2
 * interface info.
 */
int
zebra_l2_bridge_add_update (struct interface *ifp,
                            struct zebra_l2if_bridge *zl2if)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  struct zebra_l2if_bridge *_zl2if;

  zif = ifp->info;
  assert(zif);

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* Allocate/update L2 interface */
  if (!zif->l2if)
    {
      zif->l2if = XCALLOC (MTYPE_ZEBRA_L2IF,
                           sizeof (struct zebra_l2if_bridge));
      if (!zif->l2if)
        {
          zlog_err ("Failed to alloc Bridge L2IF VRF %d IF %s(%u)",
                    ifp->vrf_id, ifp->name, ifp->ifindex);
          return -1;
        }
    }

  _zl2if = (struct zebra_l2if_bridge *)zif->l2if;
  *_zl2if = *zl2if;

  /* Link all slaves to this bridge */
  map_slaves_to_bridge (ifp, 1);

  return 0;
}

/*
 * Handle L2 physical interface add or update. Create/update L2
 * physical interface info.
 */
int
zebra_l2_physif_add_update (struct interface *ifp,
                            struct zebra_l2if_phys *zl2if)
{
  struct zebra_if *zif;
  struct zebra_l2if_phys *_zl2if;

  zif = ifp->info;
  assert(zif);

  /* Allocate/update L2 interface */
  if (!zif->l2if)
    {
      zif->l2if = XCALLOC (MTYPE_ZEBRA_L2IF,
                           sizeof (struct zebra_l2if_phys));
      if (!zif->l2if)
        {
          zlog_err ("Failed to alloc Port L2IF VRF %d IF %s(%u)",
                    ifp->vrf_id, ifp->name, ifp->ifindex);
          return -1;
        }
    }

  _zl2if = (struct zebra_l2if_phys *)zif->l2if;
  *_zl2if = *zl2if;

  /* If bridge (master) is already known, link to it. */
  zebra_l2_map_slave_to_bridge (&_zl2if->br_slave);

  return 0;
}

/*
 * Handle VLAN interface add or update. Create/update VLAN L2
 * interface info.
 */
int
zebra_l2_vlanif_add_update (struct interface *ifp,
                            struct zebra_l2if_vlan *zl2if)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  struct zebra_l2if_vlan *_zl2if;

  zif = ifp->info;
  assert(zif);

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* Allocate/update L2 interface */
  if (!zif->l2if)
    {
      zif->l2if = XCALLOC (MTYPE_ZEBRA_L2IF,
                           sizeof (struct zebra_l2if_vlan));
      if (!zif->l2if)
        {
          zlog_err ("Failed to alloc VLAN L2IF VRF %d IF %s(%u)",
                    ifp->vrf_id, ifp->name, ifp->ifindex);
          return -1;
        }
    }

  _zl2if = (struct zebra_l2if_vlan *)zif->l2if;
  *_zl2if = *zl2if;

  /* If bridge (master) is already known, link to it. */
  if (_zl2if->br_slave.bridge_ifindex != IFINDEX_INTERNAL)
    zebra_l2_map_slave_to_bridge (&_zl2if->br_slave);

  return 0;
}

/*
 * Handle Bridge interface delete.
 */
int
zebra_l2_bridge_del (struct interface *ifp)
{
  /* Unlink all slaves to this bridge */
  map_slaves_to_bridge (ifp, 0);

  return zl2if_del (ifp);
}

/*
 * Handle VLAN interface delete. Right now, just call L2
 * interface delete handler.
 */
int
zebra_l2_vlanif_del (struct interface *ifp)
{
  return zl2if_del (ifp);
}

/*
 * Handle L2 physical interface delete. Right now, just call L2
 * interface delete handler.
 */
int
zebra_l2_physif_del (struct interface *ifp)
{
  return zl2if_del (ifp);
}
