/* zebra connection and redistribute fucntions.
   Copyright (C) 1999 Kunihiro Ishiguro

This file is part of GNU Zebra.

GNU Zebra is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

GNU Zebra is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Zebra; see the file COPYING.  If not, write to the
Free Software Foundation, Inc., 59 Temple Place - Suite 330,
Boston, MA 02111-1307, USA.  */

#ifndef _QUAGGA_BGP_ZEBRA_H
#define _QUAGGA_BGP_ZEBRA_H

#define BGP_NEXTHOP_BUF_SIZE (8 * sizeof (struct in_addr *))
#define BGP_IFINDICES_BUF_SIZE (8 * sizeof (unsigned int))

/* Information for route install BGP to zebra - per AFI/SAFI */
struct bgp_route_install_info
{
  int install_route;
  int (*install_fn) (struct bgp *, afi_t, safi_t, struct prefix *, struct bgp_info *);
  int (*uninstall_fn) (struct bgp *, afi_t, safi_t, struct prefix *, struct bgp_info *);
};

extern struct stream *bgp_nexthop_buf;
extern struct stream *bgp_ifindices_buf;

extern void bgp_zebra_init (struct thread_master *master);
extern void bgp_zebra_destroy (void);
extern int bgp_if_update_all (void);
extern int bgp_config_write_maxpaths (struct vty *, struct bgp *, afi_t,
				      safi_t, int *);
extern int bgp_config_write_redistribute (struct vty *, struct bgp *, afi_t, safi_t,
				   int *);
extern int bgp_install_info_to_zebra (struct bgp *bgp);
extern int bgp_zebra_announce (struct bgp *, afi_t, safi_t, struct prefix *, struct bgp_info *);
extern int bgp_zebra_withdraw (struct bgp *, afi_t, safi_t, struct prefix *, struct bgp_info *);

extern void bgp_zebra_initiate_radv (struct bgp *bgp, struct peer *peer);
extern void bgp_zebra_terminate_radv (struct bgp *bgp, struct peer *peer);

extern void bgp_zebra_instance_register (struct bgp *);
extern void bgp_zebra_instance_deregister (struct bgp *);

extern struct bgp_redist *bgp_redist_lookup (struct bgp *, afi_t, u_char, u_short);
extern struct bgp_redist *bgp_redist_add (struct bgp *, afi_t, u_char, u_short);
extern int bgp_redistribute_set (struct bgp *, afi_t, int, u_short);
extern int bgp_redistribute_resend (struct bgp *, afi_t, int, u_short);
extern int bgp_redistribute_rmap_set (struct bgp_redist *, const char *);
extern int bgp_redistribute_metric_set(struct bgp *, struct bgp_redist *,
				       afi_t, int, u_int32_t);
extern int bgp_redistribute_unset (struct bgp *, afi_t, int, u_short);
extern int bgp_redistribute_unreg (struct bgp *, afi_t, int, u_short);

extern struct interface *if_lookup_by_ipv4 (struct in_addr *, vrf_id_t);
extern struct interface *if_lookup_by_ipv4_exact (struct in_addr *, vrf_id_t);
#ifdef HAVE_IPV6
extern struct interface *if_lookup_by_ipv6 (struct in6_addr *, ifindex_t, vrf_id_t);
extern struct interface *if_lookup_by_ipv6_exact (struct in6_addr *, ifindex_t, vrf_id_t);
#endif /* HAVE_IPV6 */

extern const struct bgp_route_install_info bgp_zebra_route_install[AFI_MAX][SAFI_MAX];

/* Should this route be announced to (or withdrawn from) the RIB? */
static inline int
is_bgp_zebra_rib_route (struct bgp *bgp, afi_t afi, safi_t safi)
{
  if ((bgp->inst_type == BGP_INSTANCE_TYPE_VIEW)
      || bgp_option_check (BGP_OPT_NO_FIB))
    return 0;

  return bgp_zebra_route_install[afi][safi].install_route;
}

extern int bgp_zebra_advertise_vni (struct bgp *, int); 
extern int bgp_zebra_num_connects(void);

#endif /* _QUAGGA_BGP_ZEBRA_H */
