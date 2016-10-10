/*
 * Zebra VxLAN (EVPN) Data structures and definitions
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

#ifndef _ZEBRA_VXLAN_H
#define _ZEBRA_VXLAN_H

#include <zebra.h>

#include "linklist.h"
#include "if.h"
#include "vxlan.h"

#include "zebra/interface.h"
#include "zebra/zebra_vrf.h"

extern int zebra_vxlan_if_up (struct interface *ifp);
extern int zebra_vxlan_if_down (struct interface *ifp);
extern int zebra_vxlan_if_add (struct interface *ifp, vni_t vni, struct in_addr vtep_ip);
extern int zebra_vxlan_if_del (struct interface *ifp);
extern int zebra_vxlan_remote_vtep_add (struct zserv *client, int sock,
                                     u_short length, struct zebra_vrf *zvrf);
extern int zebra_vxlan_remote_vtep_del (struct zserv *client, int sock,
                                     u_short length, struct zebra_vrf *zvrf);
extern int zebra_vxlan_advertise_vni (struct zserv *client, int sock,
                                      u_short length, struct zebra_vrf *zvrf);
extern void zebra_evpn_print_vni (struct vty *vty, struct zebra_vrf *zvrf, vni_t vni);
extern void zebra_evpn_print_vnis (struct vty *vty, struct zebra_vrf *zvrf);
extern void zebra_vxlan_init_tables (struct zebra_vrf *zvrf);
extern void zebra_zvni_close (struct zebra_vrf *);
extern int zebra_vxlan_remote_macip_add (struct zserv *client, int sock,
                                         u_short length, struct zebra_vrf *zvrf);
extern int zebra_vxlan_remote_macip_del (struct zserv *client, int sock,
                                         u_short length, struct zebra_vrf *zvrf);

static inline int
is_interface_vxlan (struct interface *ifp)
{
  return ((ifp->info && (((struct zebra_if *)(ifp->info))->vni != 0)) ? 1 : 0);
}

static inline vni_t
vni_from_intf (struct interface *ifp)
{
  return ((ifp->info) ? (((struct zebra_if *)(ifp->info))->vni) : 0);
}

#endif /* _ZEBRA_VXLAN_H */
