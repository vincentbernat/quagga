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

typedef enum
{
    BGP_RT_IMPORT,
    BGP_RT_EXPORT,
    BGP_RT_BOTH
} bgp_rt_type;

struct bgpevpn
{
    struct bgp *bgp;
    vni_t vni;
    int flag;
    struct prefix_rd prd;
    bgp_rt_type rt_type;
    struct prefix_rd rt_prd;
};

#define RD_TYPE 2
#define RD_VAL  8

extern void bgp_evpn_init (struct bgp *);
extern void bgp_evpn_update_vni (struct bgp*, vni_t, int);
extern void bgp_evpn_print_rd (struct prefix_rd *);
extern void bgp_evpn_update_rd_rt (struct bgp *, struct bgpevpn *);
extern struct bgpevpn *bgp_evpn_lookup_vpn (struct bgp *, vni_t);
extern void bgp_evpn_cleanup (struct bgp *bgp);

#endif /* _QUAGGA_BGP_EVPN_H */
