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

  return 0;
}

/*
 * Handle Bridge interface delete.
 */
int
zebra_l2_bridge_del (struct interface *ifp)
{
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
