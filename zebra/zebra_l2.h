/*
 * Zebra Layer-2 interface Data structures and definitions
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

#ifndef _ZEBRA_L2_H
#define _ZEBRA_L2_H

#include <zebra.h>

#include "if.h"
#include "vxlan.h"

/* zebra L2 interface information - VXLAN interface */
struct zebra_l2if_vxlan
{
  vni_t vni;                     /* VNI */
  struct in_addr vtep_ip;        /* Local tunnel IP */
};

/* NOTE: This macro is to be invoked only in the "correct" context.
 * IOW, the macro VNI_FROM_ZEBRA_IF() will assume the interface is
 * of type ZEBRA_IF_VXLAN.
 */
#define VNI_FROM_ZEBRA_IF(zif) \
        (((struct zebra_l2if_vxlan *)(zif->l2if))->vni)
#endif /* _ZEBRA_L2_H */
