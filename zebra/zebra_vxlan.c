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
#include "zebra/zebra_memory.h"
#include "zebra/zebra_l2.h"

DEFINE_MTYPE_STATIC(ZEBRA, ZVNI,      "VNI hash");
DEFINE_MTYPE_STATIC(ZEBRA, ZVNI_VTEP, "VNI remote VTEP");
DEFINE_MTYPE_STATIC(ZEBRA, MAC,       "VNI MAC");
DEFINE_MTYPE_STATIC(ZEBRA, NEIGH,     "VNI Neighbor");

/* definitions */
typedef struct zebra_vni_t_ zebra_vni_t;
typedef struct zebra_vtep_t_ zebra_vtep_t;
typedef struct zebra_mac_t_ zebra_mac_t;
typedef struct zebra_neigh_t_ zebra_neigh_t;

/*
 * VTEP info
 *
 * Right now, this just has each remote VTEP's IP address.
 */
struct zebra_vtep_t_
{
  /* Remote IP. */
  struct prefix vtep_ip;

  /* Links. */
  struct zebra_vtep_t_ *next;
  struct zebra_vtep_t_ *prev;
};


/*
 * VNI hash table
 *
 * Contains information pertaining to a VNI like the list of
 * remote VTEPs (with this VNI) and the MAC table corresponding
 * to this VNI (for both local and remote entries).
 */
struct zebra_vni_t_
{
  /* VNI - key */
  vni_t vni;

  /* Corresponding VxLAN interface. */
  struct interface *vxlan_if;

  /* List of remote VTEPs */
  zebra_vtep_t *vteps;

  /* Local IP */
  struct in_addr local_vtep_ip;

  /* List of local or remote MAC */
  struct hash *mac_table;

  /* List of local or remote neighbors (MAC+IP) */
  struct hash *neigh_table;
};

/*
 * MAC hash table.
 *
 * This table contains the MAC addresses pertaining to this VNI.
 * This includes local MACs learnt on an attached VLAN that maps
 * to this VNI as well as remote MACs learnt and installed by BGP.
 * Local MACs will be known either on a VLAN sub-interface or
 * on (port, VLAN); however, it is sufficient for zebra to maintain
 * against the VNI i.e., it does not need to retain the local "port"
 * information. The correct VNI will be obtained as zebra maintains
 * the mapping (of VLAN to VNI).
 */
struct zebra_mac_t_
{
  /* MAC address. */
  struct ethaddr  macaddr;

  u_int32_t       flags;
#define ZEBRA_MAC_LOCAL   0x01
#define ZEBRA_MAC_REMOTE  0x02
#define ZEBRA_MAC_AUTO    0x04  /* Auto created for neighbor. */

  /* Local or remote info. */
  union
    {
      struct
        {
          ifindex_t ifindex;
          vlanid_t  vid;
        } local;

      struct in_addr r_vtep_ip;
    } fwd_info;

  u_int32_t       neigh_refcnt;
};

/*
 * Context for MAC hash walk - used by callbacks.
 */
struct mac_walk_ctx
{
  zebra_vni_t *zvni;          /* VNI hash */
  struct zebra_vrf *zvrf;     /* VRF - for client notification. */
  int uninstall;              /* uninstall from kernel? */
  int upd_client;             /* uninstall from client? */

  u_int32_t flags;
#define DEL_LOCAL_MAC                0x1
#define DEL_REMOTE_MAC               0x2
#define DEL_ALL_MAC                  (DEL_LOCAL_MAC | DEL_REMOTE_MAC)
#define DEL_REMOTE_MAC_FROM_VTEP     0x4
#define SHOW_REMOTE_MAC_FROM_VTEP    0x8

  struct in_addr r_vtep_ip;   /* To walk MACs from specific VTEP */

  struct vty *vty;            /* Used by VTY handlers */
  u_int32_t  count;           /* Used by VTY handlers */
};

/*
 * Neighbor hash table.
 *
 * This table contains the neighbors (IP to MAC bindings) pertaining to
 * this VNI. This includes local neighbors learnt on the attached VLAN
 * device that maps to this VNI as well as remote neighbors learnt and
 * installed by BGP.
 * Local neighbors will be known against the VLAN device (SVI); however,
 * it is sufficient for zebra to maintain against the VNI. The correct
 * VNI will be obtained as zebra maintains the mapping (of VLAN to VNI).
 */
struct zebra_neigh_t_
{
  /* IP address. */
  struct ipaddr   ip;

  /* MAC address. */
  struct ethaddr  emac;

  /* Underlying interface. */
  ifindex_t ifindex;

  u_int32_t       flags;
#define ZEBRA_NEIGH_LOCAL   0x01
#define ZEBRA_NEIGH_REMOTE  0x02

  /* Remote VTEP IP - applicable only for remote neighbors. */
  struct in_addr r_vtep_ip;
};

/*
 * Context for neighbor hash walk - used by callbacks.
 */
struct neigh_walk_ctx
{
  zebra_vni_t *zvni;          /* VNI hash */
  struct zebra_vrf *zvrf;     /* VRF - for client notification. */
  int uninstall;              /* uninstall from kernel? */
  int upd_client;             /* uninstall from client? */

  u_int32_t flags;
#define DEL_LOCAL_NEIGH              0x1
#define DEL_REMOTE_NEIGH             0x2
#define DEL_ALL_NEIGH                (DEL_LOCAL_NEIGH | DEL_REMOTE_NEIGH)
#define DEL_REMOTE_NEIGH_FROM_VTEP   0x4
#define SHOW_REMOTE_NEIGH_FROM_VTEP  0x8

  struct in_addr r_vtep_ip;   /* To walk neighbors from specific VTEP */

  struct vty *vty;            /* Used by VTY handlers */
  u_int32_t  count;           /* Used by VTY handlers */
  u_char     addr_width;      /* Used by VTY handlers */
};


/* static function declarations */
static int
zvni_macip_send_msg_to_client (struct zebra_vrf *zvrf, vni_t vni,
                               struct ethaddr *macaddr,
                               struct ipaddr *ip, u_int16_t cmd);
static unsigned int
neigh_hash_keymake (void *p);
static int
neigh_cmp (const void *p1, const void *p2);
static void *
zvni_neigh_alloc (void *p);
static zebra_neigh_t *
zvni_neigh_add (zebra_vni_t *zvni, struct ipaddr *ip);
static int
zvni_neigh_del (zebra_vni_t *zvni, zebra_neigh_t *n);
static int
zvni_neigh_del_hash_entry (struct hash_backet *backet, void *arg);
static void
zvni_neigh_del_from_vtep (zebra_vni_t *zvni, int uninstall,
                          struct in_addr *r_vtep_ip);
static void
zvni_neigh_del_all (struct zebra_vrf *zvrf, zebra_vni_t *zvni,
                    int uninstall, int upd_client, u_int32_t flags);
static zebra_neigh_t *
zvni_neigh_lookup (zebra_vni_t *zvni, struct ipaddr *ip);
static int
zvni_neigh_send_add_to_client (struct zebra_vrf *zvrf, vni_t vni,
                               struct ipaddr *ip, struct ethaddr *macaddr);
static int
zvni_neigh_send_del_to_client (struct zebra_vrf *zvrf, vni_t vni,
                               struct ipaddr *ip, struct ethaddr *macaddr);
static int
zvni_neigh_install (zebra_vni_t *zvni, zebra_neigh_t *n);
static int
zvni_neigh_uninstall (zebra_vni_t *zvni, zebra_neigh_t *n);
static zebra_vni_t *
zvni_map_vlanif (struct interface *ifp, struct interface *br_if);
static struct interface *
zvni_map_to_vlanif (struct zebra_vrf *zvrf, vlanid_t vid,
                    struct interface *br_if);

static unsigned int
mac_hash_keymake (void *p);
static int
mac_cmp (const void *p1, const void *p2);
static void *
zvni_mac_alloc (void *p);
static zebra_mac_t *
zvni_mac_add (zebra_vni_t *zvni, struct ethaddr *macaddr);
static int
zvni_mac_del (zebra_vni_t *zvni, zebra_mac_t *mac);
static int
zvni_mac_del_hash_entry (struct hash_backet *backet, void *arg);
static void
zvni_mac_del_from_vtep (zebra_vni_t *zvni, int uninstall,
                          struct in_addr *r_vtep_ip);
static void
zvni_mac_del_all (struct zebra_vrf *zvrf, zebra_vni_t *zvni,
                    int uninstall, int upd_client, u_int32_t flags);
static zebra_mac_t *
zvni_mac_lookup (zebra_vni_t *zvni, struct ethaddr *macaddr);
static int
zvni_mac_send_add_to_client (struct zebra_vrf *zvrf, vni_t vni,
                               struct ethaddr *macaddr);
static int
zvni_mac_send_del_to_client (struct zebra_vrf *zvrf, vni_t vni,
                               struct ethaddr *macaddr);
static zebra_vni_t *
zvni_map_vlan (struct interface *ifp, struct interface *br_if, vlanid_t vid);
static int
zvni_mac_install (zebra_vni_t *zvni, zebra_mac_t *mac);
static int
zvni_mac_uninstall (zebra_vni_t *zvni, zebra_mac_t *mac);
static void
zvni_install_mac_hash (struct hash_backet *backet, void *ctxt);
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
static int
zvni_send_add_to_client (struct zebra_vrf *zvrf, zebra_vni_t *zvni);
static int
zvni_send_del_to_client (struct zebra_vrf *zvrf, vni_t vni);
static void
zvni_build_hash_table (struct zebra_vrf *zvrf);
static int
zvni_vtep_match (struct prefix *vtep, zebra_vtep_t *zvtep);
static zebra_vtep_t *
zvni_vtep_find (zebra_vni_t *zvni, struct prefix *vtep);
static zebra_vtep_t *
zvni_vtep_add (zebra_vni_t *zvni, struct prefix *vtep);
static int
zvni_vtep_del (zebra_vni_t *zvni, zebra_vtep_t *zvtep);
static int
zvni_vtep_del_all (zebra_vni_t *zvni, int uninstall);
static int
kernel_add_vni_flood_list (struct interface *ifp, struct prefix *vtep);
static int
kernel_del_vni_flood_list (struct interface *ifp, struct prefix *vtep);
static int
zvni_vtep_install (zebra_vni_t *zvni, struct prefix *vtep);
static int
zvni_vtep_uninstall (zebra_vni_t *zvni, struct prefix *vtep);
static int
zebra_vxlan_if_add (struct zebra_vrf *zvrf, struct interface *ifp,
                    struct zebra_l2if_vxlan *zl2if);
static int
zebra_vxlan_if_update (struct zebra_vrf *zvrf, struct interface *ifp,
                       struct zebra_l2if_vxlan *zl2if);
static void
zvni_print (zebra_vni_t *zvni, void *ctxt);
static void
zvni_print_hash (struct hash_backet *backet, void *ctxt);



/* Private functions */

/*
 * Inform BGP about local MACIP.
 */
static int
zvni_macip_send_msg_to_client (struct zebra_vrf *zvrf, vni_t vni,
                               struct ethaddr *macaddr,
                               struct ipaddr *ip, u_int16_t cmd)
{
  struct zserv *client;
  struct stream *s;
  int ipa_len;
  char buf[MACADDR_STRLEN];
  char buf2[INET6_ADDRSTRLEN];

  client = zebra_find_client (ZEBRA_ROUTE_BGP);
  /* BGP may not be running. */
  if (!client)
    return 0;

  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, cmd, zvrf->vrf_id);
  stream_putl (s, vni);
  stream_put (s, macaddr->octet, ETHER_ADDR_LEN);
  if (ip)
    {
      ipa_len = 0;
      if (IS_IPADDR_V4(ip))
        ipa_len = IPV4_MAX_BYTELEN;
      else if (IS_IPADDR_V6(ip))
        ipa_len = IPV6_MAX_BYTELEN;

      stream_putl (s, ipa_len); /* IP address length */
      if (ipa_len)
        stream_put (s, &ip->ip.addr, ipa_len); /* IP address */
    }
  else
    stream_putl (s, 0); /* Just MAC. */

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Send MACIP %s MAC %s IP %s VNI %u to %s",
                zvrf->vrf_id, (cmd == ZEBRA_MACIP_ADD) ? "Add" : "Del",
                mac2str (macaddr, buf, sizeof (buf)),
                ipaddr2str (ip, buf2, sizeof(buf2)), vni,
                zebra_route_string (client->proto));

  if (cmd == ZEBRA_MACIP_ADD)
    client->macipadd_cnt++;
  else
    client->macipdel_cnt++;

  return zebra_server_send_message(client);
}

/*
 * Make hash key for neighbors.
 */
static unsigned int
neigh_hash_keymake (void *p)
{
  zebra_neigh_t *n = p;
  struct ipaddr *ip = &n->ip;

  if (IS_IPADDR_V4(ip))
    return jhash_1word (ip->ip.v4_addr.s_addr, 0);

  return jhash2 (ip->ip.v6_addr.s6_addr32,
                 ZEBRA_NUM_OF(ip->ip.v6_addr.s6_addr32), 0);
}

/*
 * Compare two neighbor hash structures.
 */
static int
neigh_cmp (const void *p1, const void *p2)
{
  const zebra_neigh_t *n1 = p1;
  const zebra_neigh_t *n2 = p2;

  if (n1 == NULL && n2 == NULL)
    return 1;

  if (n1 == NULL || n2 == NULL)
    return 0;

  return (memcmp(&n1->ip, &n2->ip, sizeof (struct ipaddr)) == 0);
}

/*
 * Callback to allocate neighbor hash entry.
 */
static void *
zvni_neigh_alloc (void *p)
{
  const zebra_neigh_t *tmp_n = p;
  zebra_neigh_t *n;

  n = XCALLOC (MTYPE_NEIGH, sizeof(zebra_neigh_t));
  *n = *tmp_n;

  return ((void *)n);
}

/*
 * Add neighbor entry.
 */
static zebra_neigh_t *
zvni_neigh_add (zebra_vni_t *zvni, struct ipaddr *ip)
{
  zebra_neigh_t tmp_n;
  zebra_neigh_t *n = NULL;

  memset (&tmp_n, 0, sizeof (zebra_neigh_t));
  memcpy (&tmp_n.ip, ip, sizeof (struct ipaddr));
  n = hash_get (zvni->neigh_table, &tmp_n, zvni_neigh_alloc);
  assert (n);

  return n;
}

/*
 * Delete neighbor entry.
 */
static int
zvni_neigh_del (zebra_vni_t *zvni, zebra_neigh_t *n)
{
  zebra_neigh_t *tmp_n;

  /* Free the VNI hash entry and allocated memory. */
  tmp_n = hash_release (zvni->neigh_table, n);
  if (tmp_n)
    XFREE(MTYPE_NEIGH, tmp_n);

  return 0;
}

/*
 * Free neighbor hash entry (callback)
 */
static int
zvni_neigh_del_hash_entry (struct hash_backet *backet, void *arg)
{
  struct neigh_walk_ctx *wctx = arg;
  zebra_neigh_t *n = backet->data;

  if (((wctx->flags & DEL_LOCAL_NEIGH) && (n->flags & ZEBRA_NEIGH_LOCAL)) ||
      ((wctx->flags & DEL_REMOTE_NEIGH) && (n->flags & ZEBRA_NEIGH_REMOTE)) ||
      ((wctx->flags & DEL_REMOTE_NEIGH_FROM_VTEP) &&
       (n->flags & ZEBRA_NEIGH_REMOTE) &&
       IPV4_ADDR_SAME(&n->r_vtep_ip, &wctx->r_vtep_ip)
      ))
    {
      if (wctx->upd_client && (n->flags & ZEBRA_NEIGH_LOCAL))
        zvni_neigh_send_del_to_client (wctx->zvrf, wctx->zvni->vni, &n->ip,
                                       &n->emac);

      if (wctx->uninstall)
        zvni_neigh_uninstall (wctx->zvni, n);

      return zvni_neigh_del (wctx->zvni, n);
    }

  return 0;
}

/*
 * Delete all neighbor entries from specific VTEP for a particular VNI.
 */
static void
zvni_neigh_del_from_vtep (zebra_vni_t *zvni, int uninstall,
                          struct in_addr *r_vtep_ip)
{
  struct neigh_walk_ctx wctx;

  if (!zvni->neigh_table)
    return;

  memset (&wctx, 0, sizeof (struct neigh_walk_ctx));
  wctx.zvni = zvni;
  wctx.uninstall = uninstall;
  wctx.flags = DEL_REMOTE_NEIGH_FROM_VTEP;
  wctx.r_vtep_ip = *r_vtep_ip;

  hash_iterate (zvni->neigh_table,
                (void (*) (struct hash_backet *, void *))
                zvni_neigh_del_hash_entry, &wctx);
}

/*
 * Delete all neighbor entries for this VNI.
 */
static void
zvni_neigh_del_all (struct zebra_vrf *zvrf, zebra_vni_t *zvni,
                    int uninstall, int upd_client, u_int32_t flags)
{
  struct neigh_walk_ctx wctx;

  if (!zvni->neigh_table)
    return;

  memset (&wctx, 0, sizeof (struct neigh_walk_ctx));
  wctx.zvni = zvni;
  wctx.zvrf = zvrf;
  wctx.uninstall = uninstall;
  wctx.upd_client = upd_client;
  wctx.flags = flags;

  hash_iterate (zvni->neigh_table,
                (void (*) (struct hash_backet *, void *))
                zvni_neigh_del_hash_entry, &wctx);
}

/*
 * Look up neighbor hash entry.
 */
static zebra_neigh_t *
zvni_neigh_lookup (zebra_vni_t *zvni, struct ipaddr *ip)
{
  zebra_neigh_t tmp;
  zebra_neigh_t *n;

  memset (&tmp, 0, sizeof(tmp));
  memcpy (&tmp.ip, ip, sizeof (struct ipaddr));
  n = hash_lookup (zvni->neigh_table, &tmp);

  return n;
}

/*
 * Inform BGP about local neighbor addition.
 */
static int
zvni_neigh_send_add_to_client (struct zebra_vrf *zvrf, vni_t vni,
                               struct ipaddr *ip, struct ethaddr *macaddr)
{
  return zvni_macip_send_msg_to_client (zvrf, vni, macaddr, ip,
                                        ZEBRA_MACIP_ADD);
}

/*
 * Inform BGP about local neighbor deletion.
 */
static int
zvni_neigh_send_del_to_client (struct zebra_vrf *zvrf, vni_t vni,
                               struct ipaddr *ip, struct ethaddr *macaddr)
{
  return zvni_macip_send_msg_to_client (zvrf, vni, macaddr, ip,
                                        ZEBRA_MACIP_DEL);
}

/*
 * Install remote neighbor into the kernel.
 */
static int
zvni_neigh_install (zebra_vni_t *zvni, zebra_neigh_t *n)
{
  struct zebra_vrf *zvrf;
  struct zebra_if *zif;
  struct zebra_l2if_vxlan *zl2if;
  struct interface *vlan_if;

  if (!(n->flags & ZEBRA_NEIGH_REMOTE))
    return 0;

  zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
  assert(zvrf);
  zif = zvni->vxlan_if->info;
  zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  if (!zl2if)
    return -1;

  vlan_if = zvni_map_to_vlanif (zvrf, zl2if->access_vlan,
                                zl2if->br_slave.br_if);
  if (!vlan_if)
    return -1;

  return kernel_add_neigh (vlan_if, &n->ip, &n->emac);
}

/*
 * Uninstall remote neighbor from the kernel.
 */
static int
zvni_neigh_uninstall (zebra_vni_t *zvni, zebra_neigh_t *n)
{
  struct zebra_vrf *zvrf;
  struct zebra_if *zif;
  struct zebra_l2if_vxlan *zl2if;
  struct interface *vlan_if;

  if (!(n->flags & ZEBRA_NEIGH_REMOTE))
    return 0;

  zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
  assert(zvrf);
  if (!zvni->vxlan_if)
    {
      zlog_err ("VNI %u hash %p couldn't be uninstalled - no intf",
                zvni->vni, zvni);
      return -1;
    }

  zif = zvni->vxlan_if->info;
  zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  if (!zl2if)
    return -1;
  vlan_if = zvni_map_to_vlanif (zvrf, zl2if->access_vlan,
                                zl2if->br_slave.br_if);
  if (!vlan_if)
    return -1;

  return kernel_del_neigh (vlan_if, &n->ip);
}

/*
 * Install neighbor hash entry - called upon access VLAN change.
 */
static void
zvni_install_neigh_hash (struct hash_backet *backet, void *ctxt)
{
  zebra_neigh_t *n;
  struct neigh_walk_ctx *wctx = ctxt;

  n = (zebra_neigh_t *) backet->data;
  if (!n)
    return;

  if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
    zvni_neigh_install (wctx->zvni, n);
}

/*
 * Make hash key for MAC.
 */
static unsigned int
mac_hash_keymake (void *p)
{
  zebra_mac_t *pmac = p;
  char *pnt = (char *) pmac->macaddr.octet;
  unsigned int key = 0;
  int c = 0;
  
  key += pnt[c];
  key += pnt[c + 1];
  key += pnt[c + 2];
  key += pnt[c + 3];
  key += pnt[c + 4];
  key += pnt[c + 5];

  return (key);
}

/*
 * Compare two MAC addresses.
 */
static int
mac_cmp (const void *p1, const void *p2)
{
  const zebra_mac_t *pmac1 = p1;
  const zebra_mac_t *pmac2 = p2;

  if (pmac1 == NULL && pmac2 == NULL)
    return 1;

  if (pmac1 == NULL || pmac2 == NULL)
    return 0;

  return(memcmp(pmac1->macaddr.octet, pmac2->macaddr.octet, ETHER_ADDR_LEN) == 0);
}

/*
 * Callback to allocate MAC hash entry.
 */
static void *
zvni_mac_alloc (void *p)
{
  const zebra_mac_t *tmp_mac = p;
  zebra_mac_t *mac;

  mac = XCALLOC (MTYPE_MAC, sizeof(zebra_mac_t));
  *mac = *tmp_mac;

  return ((void *)mac);
}

/*
 * Add MAC entry.
 */
static zebra_mac_t *
zvni_mac_add (zebra_vni_t *zvni, struct ethaddr *macaddr)
{
  zebra_mac_t tmp_mac;
  zebra_mac_t *mac = NULL;

  memset (&tmp_mac, 0, sizeof (zebra_mac_t));
  memcpy(&tmp_mac.macaddr, macaddr, ETHER_ADDR_LEN);
  mac = hash_get (zvni->mac_table, &tmp_mac, zvni_mac_alloc);
  assert (mac);

  return mac;
}

/*
 * Delete MAC entry.
 */
static int
zvni_mac_del (zebra_vni_t *zvni, zebra_mac_t *mac)
{
  zebra_mac_t *tmp_mac;

  /* Free the VNI hash entry and allocated memory. */
  tmp_mac = hash_release (zvni->mac_table, mac);
  if (tmp_mac)
    XFREE(MTYPE_MAC, tmp_mac);

  return 0;
}

/*
 * Free MAC hash entry (callback)
 */
static int
zvni_mac_del_hash_entry (struct hash_backet *backet, void *arg)
{
  struct mac_walk_ctx *wctx = arg;
  zebra_mac_t *mac = backet->data;

  if (((wctx->flags & DEL_LOCAL_MAC) && (mac->flags & ZEBRA_MAC_LOCAL)) ||
      ((wctx->flags & DEL_REMOTE_MAC) && (mac->flags & ZEBRA_MAC_REMOTE)) ||
      ((wctx->flags & DEL_REMOTE_MAC_FROM_VTEP) &&
       (mac->flags & ZEBRA_MAC_REMOTE) &&
       IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip, &wctx->r_vtep_ip)
      ))
    {
      if (wctx->upd_client && (mac->flags & ZEBRA_MAC_LOCAL))
        zvni_mac_send_del_to_client (wctx->zvrf, wctx->zvni->vni,
                                       &mac->macaddr);

      if (wctx->uninstall)
        zvni_mac_uninstall (wctx->zvni, mac);

      return zvni_mac_del (wctx->zvni, mac);
    }

  return 0;
}

/*
 * Delete all MAC entries from specific VTEP for a particular VNI.
 */
static void
zvni_mac_del_from_vtep (zebra_vni_t *zvni, int uninstall,
                          struct in_addr *r_vtep_ip)
{
  struct mac_walk_ctx wctx;

  if (!zvni->mac_table)
    return;

  memset (&wctx, 0, sizeof (struct mac_walk_ctx));
  wctx.zvni = zvni;
  wctx.uninstall = uninstall;
  wctx.flags = DEL_REMOTE_MAC_FROM_VTEP;
  wctx.r_vtep_ip = *r_vtep_ip;

  hash_iterate (zvni->mac_table,
                (void (*) (struct hash_backet *, void *))
                zvni_mac_del_hash_entry, &wctx);
}

/*
 * Delete all MAC entries for this VNI.
 */
static void
zvni_mac_del_all (struct zebra_vrf *zvrf, zebra_vni_t *zvni,
                    int uninstall, int upd_client, u_int32_t flags)
{
  struct mac_walk_ctx wctx;

  if (!zvni->mac_table)
    return;

  memset (&wctx, 0, sizeof (struct mac_walk_ctx));
  wctx.zvni = zvni;
  wctx.zvrf = zvrf;
  wctx.uninstall = uninstall;
  wctx.upd_client = upd_client;
  wctx.flags = flags;

  hash_iterate (zvni->mac_table,
                (void (*) (struct hash_backet *, void *))
                zvni_mac_del_hash_entry, &wctx);
}

/*
 * Look up MAC hash entry.
 */
static zebra_mac_t *
zvni_mac_lookup (zebra_vni_t *zvni, struct ethaddr *mac)
{
  zebra_mac_t tmp;
  zebra_mac_t *pmac;

  memset(&tmp, 0, sizeof(tmp));
  memcpy(&tmp.macaddr, mac, ETHER_ADDR_LEN);
  pmac = hash_lookup (zvni->mac_table, &tmp);

  return pmac;
}

/*
 * Inform BGP about local MAC addition.
 */
static int
zvni_mac_send_add_to_client (struct zebra_vrf *zvrf, vni_t vni,
                             struct ethaddr *macaddr)
{
  return zvni_macip_send_msg_to_client (zvrf, vni, macaddr, NULL,
                                        ZEBRA_MACIP_ADD);
}

/*
 * Inform BGP about local MAC deletion.
 */
static int
zvni_mac_send_del_to_client (struct zebra_vrf *zvrf, vni_t vni,
                             struct ethaddr *macaddr)
{
  return zvni_macip_send_msg_to_client (zvrf, vni, macaddr, NULL,
                                        ZEBRA_MACIP_DEL);
}

/*
 * Map port or (port, VLAN) to a VNI. This is invoked upon getting MAC
 * notifications, to see if there are of interest.
 * TODO: Need to make this as a hash table.
 */
static zebra_vni_t *
zvni_map_vlan (struct interface *ifp, struct interface *br_if, vlanid_t vid)
{
  struct zebra_vrf *zvrf;
  struct listnode *node;
  struct interface *tmp_if;
  struct zebra_if *zif;
  struct zebra_l2if_bridge *zl2if_br;
  struct zebra_l2if_vxlan *zl2if;
  u_char bridge_vlan_aware;
  zebra_vni_t *zvni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* Determine if bridge is VLAN-aware or not */
  zif = br_if->info;
  assert (zif);
  zl2if_br = (struct zebra_l2if_bridge *)zif->l2if;
  bridge_vlan_aware = zl2if_br->vlan_aware;

  /* See if this interface (or interface plus VLAN Id) maps to a VxLAN */
  /* TODO: Optimize with a hash. */
  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (zvrf->vrf_id), node, tmp_if))
    {
      zif = tmp_if->info;
      if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
        continue;
      if (!if_is_operative (tmp_if))
        continue;
      zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
      if (!zl2if)
        continue;

      if (zl2if->br_slave.br_if != br_if)
        continue;

      if (!bridge_vlan_aware)
        break;

      if (zl2if->access_vlan == vid)
        break;
    }

  if (!tmp_if)
    return NULL;

  zvni = zvni_lookup (zvrf, zl2if->vni);
  return zvni;
}

/*
 * Map VLAN/L3 interface to a VNI. This is invoked upon getting neighbor
 * notifications, to see if they are of interest.
 * TODO: Need to make this as a hash table.
 */
static zebra_vni_t *
zvni_map_vlanif (struct interface *ifp, struct interface *br_if)
{
  struct zebra_vrf *zvrf;
  struct listnode *node;
  struct interface *tmp_if;
  struct zebra_if *zif;
  struct zebra_l2if_bridge *zl2if_br;
  struct zebra_l2if_vxlan *zl2if;
  u_char bridge_vlan_aware;
  vlanid_t vid = 0;
  zebra_vni_t *zvni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* Determine if bridge is VLAN-aware or not */
  zif = br_if->info;
  assert (zif);
  zl2if_br = (struct zebra_l2if_bridge *)zif->l2if;
  bridge_vlan_aware = zl2if_br->vlan_aware;
  if (bridge_vlan_aware)
    {
      struct zebra_l2if_vlan *zl2if_tmp;

      if (!IS_ZEBRA_IF_VLAN(ifp))
        return NULL;

      zif = ifp->info;
      assert (zif);
      zl2if_tmp = (struct zebra_l2if_vlan *)zif->l2if;
      if (!zl2if_tmp)
        return NULL;
      vid = zl2if_tmp->vid;
    }

  /* See if this interface (or interface plus VLAN Id) maps to a VxLAN */
  /* TODO: Optimize with a hash. */
  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (zvrf->vrf_id), node, tmp_if))
    {
      zif = tmp_if->info;
      if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
        continue;
      if (!if_is_operative (tmp_if))
        continue;
      zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
      if (!zl2if)
        continue;

      if (zl2if->br_slave.br_if != br_if)
        continue;

      if (!bridge_vlan_aware)
        break;

      if (zl2if->access_vlan == vid)
        break;
    }

  if (!tmp_if)
    return NULL;

  zvni = zvni_lookup (zvrf, zl2if->vni);
  return zvni;
}

/* Map to VLAN interface on bridge. */
static struct interface *
zvni_map_to_vlanif (struct zebra_vrf *zvrf, vlanid_t vid,
                    struct interface *br_if)
{
  struct listnode *node;
  struct interface *tmp_if;
  struct zebra_if *zif;
  struct zebra_l2if_bridge *zl2if_br;
  struct zebra_l2if_vlan *zl2if;
  u_char bridge_vlan_aware;

  /* Determine if bridge is VLAN-aware or not */
  zif = br_if->info;
  assert (zif);
  zl2if_br = (struct zebra_l2if_bridge *)zif->l2if;
  bridge_vlan_aware = zl2if_br->vlan_aware;

  /* Identify corresponding VLAN interface. */
  /* TODO: Optimize with a hash. */
  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (zvrf->vrf_id), node, tmp_if))
    {
      zif = tmp_if->info;
      if (!zif ||
          zif->zif_type != ZEBRA_IF_VLAN ||
          zif->link != br_if)
        continue;
      zl2if = (struct zebra_l2if_vlan *)zif->l2if;
      if (!zl2if)
        continue;

      if (!bridge_vlan_aware)
        break;

      if (zl2if->vid == vid)
        break;
    }

  return tmp_if;
}

/*
 * Install remote MAC into the kernel.
 */
static int
zvni_mac_install (zebra_vni_t *zvni, zebra_mac_t *mac)
{
  struct zebra_if *zif;
  struct zebra_l2if_vxlan *zl2if;

  if (!(mac->flags & ZEBRA_MAC_REMOTE))
    return 0;

  zif = zvni->vxlan_if->info;
  zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  if (!zl2if)
    return -1;

  return kernel_add_mac (zvni->vxlan_if, zl2if->access_vlan,
                         &mac->macaddr, mac->fwd_info.r_vtep_ip);
}

/*
 * Uninstall remote MAC from the kernel.
 */
static int
zvni_mac_uninstall (zebra_vni_t *zvni, zebra_mac_t *mac)
{
  struct zebra_if *zif;
  struct zebra_l2if_vxlan *zl2if;

  if (!(mac->flags & ZEBRA_MAC_REMOTE))
    return 0;

  if (!zvni->vxlan_if)
    {
      zlog_err ("VNI %u hash %p couldn't be uninstalled - no intf",
                zvni->vni, zvni);
      return -1;
    }

  zif = zvni->vxlan_if->info;
  zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  if (!zl2if)
    return -1;

  return kernel_del_mac (zvni->vxlan_if, zl2if->access_vlan,
                         &mac->macaddr, mac->fwd_info.r_vtep_ip);
}

/*
 * Install MAC hash entry - called upon access VLAN change.
 */
static void
zvni_install_mac_hash (struct hash_backet *backet, void *ctxt)
{
  zebra_mac_t *mac;
  struct mac_walk_ctx *wctx = ctxt;

  mac = (zebra_mac_t *) backet->data;
  if (!mac)
    return;

  if (CHECK_FLAG(mac->flags, ZEBRA_MAC_REMOTE))
    zvni_mac_install (wctx->zvni, mac);
}

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

/*
 * Look up VNI hash entry.
 */
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

  /* Create hash table for MAC */
  zvni->mac_table = hash_create(mac_hash_keymake, mac_cmp);

  /* Create hash table for neighbors */
  zvni->neigh_table = hash_create(neigh_hash_keymake, neigh_cmp);

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

  /* Free the neighbor hash table. */
  hash_free(zvni->neigh_table);
  zvni->neigh_table = NULL;

  /* Free the MAC hash table. */
  hash_free(zvni->mac_table);
  zvni->mac_table = NULL;

  /* Free the VNI hash entry and allocated memory. */
  tmp_zvni = hash_release (zvrf->vni_table, zvni);
  if (tmp_zvni)
    XFREE(MTYPE_ZVNI, tmp_zvni);

  return 0;
}

/*
 * Inform BGP about local VNI addition.
 */
static int
zvni_send_add_to_client (struct zebra_vrf *zvrf,
                         zebra_vni_t *zvni)
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
  stream_putl (s, zvni->vni);
  stream_put_in_addr (s, &zvni->local_vtep_ip);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Send VNI_ADD %u %s to %s",
                zvrf->vrf_id, zvni->vni, inet_ntoa(zvni->local_vtep_ip),
                zebra_route_string (client->proto));

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
  stream_putl (s, vni);

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Send VNI_DEL %u to %s", zvrf->vrf_id, vni,
                zebra_route_string (client->proto));

  client->vnidel_cnt++;
  return zebra_server_send_message(client);
}

/*
 * Build the VNI hash table by going over the VxLAN interfaces. This
 * is called when EVPN (advertise-all-vni) is enabled.
 */
static void
zvni_build_hash_table (struct zebra_vrf *zvrf)
{
  struct listnode *node;
  struct interface *ifp;

  /* Walk VxLAN interfaces and create VNI hash. */
  for (ALL_LIST_ELEMENTS_RO (vrf_iflist (zvrf->vrf_id), node, ifp))
    {
      struct zebra_if *zif;
      struct zebra_l2if_vxlan *zl2if;
      zebra_vni_t *zvni;
      vni_t vni;

      zif = ifp->info;
      if (!zif || zif->zif_type != ZEBRA_IF_VXLAN)
        continue;
      zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
      if (!zl2if)
        continue;

      vni = zl2if->vni;

      if (IS_ZEBRA_DEBUG_VXLAN)
        zlog_debug ("%u:Create VNI hash for intf %s(%u) VNI %u local IP %s",
                    zvrf->vrf_id, ifp->name, ifp->ifindex, vni,
                    inet_ntoa (zl2if->vtep_ip));

      /* VNI hash entry is not expected to exist. */
      zvni = zvni_lookup (zvrf, vni);
      if (zvni)
        {
          zlog_err ("VNI hash already present for VRF %d IF %s(%u) VNI %u",
                    zvrf->vrf_id, ifp->name, ifp->ifindex, vni);
          continue;
        }

      zvni = zvni_add (zvrf, vni);
      if (!zvni)
        {
          zlog_err ("Failed to add VNI hash, VRF %d IF %s(%u) VNI %u",
                    zvrf->vrf_id, ifp->name, ifp->ifindex, vni);
          return;
        }

      zvni->local_vtep_ip = zl2if->vtep_ip;
      zvni->vxlan_if = ifp;

      /* Inform BGP if interface is up and mapped to bridge. */
      if (if_is_operative (ifp) &&
          zl2if->br_slave.br_if)
        zvni_send_add_to_client (zvrf, zvni);
    }
}

/*
 * See if remote VTEP matches with prefix.
 */
static int
zvni_vtep_match (struct prefix *vtep, zebra_vtep_t *zvtep)
{
  return (prefix_same (vtep, &zvtep->vtep_ip));
}

/*
 * Locate remote VTEP in VNI hash table.
 */
static zebra_vtep_t *
zvni_vtep_find (zebra_vni_t *zvni, struct prefix *vtep)
{
  zebra_vtep_t *zvtep;

  if (!zvni)
    return NULL;

  for (zvtep = zvni->vteps; zvtep; zvtep = zvtep->next)
    {
      if (zvni_vtep_match (vtep, zvtep))
        break;
    }

  return zvtep;
}

/*
 * Add remote VTEP to VNI hash table.
 */
static zebra_vtep_t *
zvni_vtep_add (zebra_vni_t *zvni, struct prefix *vtep)
{
  zebra_vtep_t *zvtep;

  zvtep = XCALLOC (MTYPE_ZVNI_VTEP, sizeof(zebra_vtep_t));
  if (!zvtep)
    {
      zlog_err ("Failed to alloc VTEP entry, VNI %u", zvni->vni);
      return NULL;
    }

  memcpy (&zvtep->vtep_ip, vtep, sizeof (struct prefix));

  if (zvni->vteps)
    zvni->vteps->prev = zvtep;
  zvtep->next = zvni->vteps;
  zvni->vteps = zvtep;

  return zvtep;
}

/*
 * Remove remote VTEP from VNI hash table.
 */
static int
zvni_vtep_del (zebra_vni_t *zvni, zebra_vtep_t *zvtep)
{
  if (zvtep->next)
    zvtep->next->prev = zvtep->prev;
  if (zvtep->prev)
    zvtep->prev->next = zvtep->next;
  else
    zvni->vteps = zvtep->next;

  zvtep->prev = zvtep->next = NULL;
  XFREE (MTYPE_ZVNI_VTEP, zvtep);

  return 0;
}

/*
 * Delete all remote VTEPs for this VNI (upon VNI delete). Also
 * uninstall from kernel if asked to.
 */
static int
zvni_vtep_del_all (zebra_vni_t *zvni, int uninstall)
{
  zebra_vtep_t *zvtep, *zvtep_next;

  if (!zvni)
    return -1;

  for (zvtep = zvni->vteps; zvtep; zvtep = zvtep_next)
    {
      zvtep_next = zvtep->next;
      if (uninstall)
        zvni_vtep_uninstall (zvni, &zvtep->vtep_ip);
      zvni_vtep_del (zvni, zvtep);
    }

  return 0;
}

/*
 * Add remote VTEP to the flood list for this VxLAN interface (VNI). This
 * is currently implemented only for the netlink interface.
 */
static int
kernel_add_vni_flood_list (struct interface *ifp, struct prefix *vtep)
{
  char pbuf[PREFIX2STR_BUFFER];

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("Install %s into flood list for intf %s(%u)",
                prefix2str (vtep, pbuf, sizeof(pbuf)), ifp->name, ifp->ifindex);

  return netlink_vxlan_flood_list_update (ifp, vtep, RTM_NEWNEIGH);
}

/*
 * Remove remote VTEP from the flood list for this VxLAN interface (VNI). This
 * is currently implemented only for the netlink interface.
 */
static int
kernel_del_vni_flood_list (struct interface *ifp, struct prefix *vtep)
{
  char pbuf[PREFIX2STR_BUFFER];

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("Uninstall %s from flood list for intf %s(%u)",
                prefix2str (vtep, pbuf, sizeof(pbuf)), ifp->name, ifp->ifindex);

  return netlink_vxlan_flood_list_update (ifp, vtep, RTM_DELNEIGH);
}

/*
 * Install remote VTEP into the kernel.
 */
static int
zvni_vtep_install (zebra_vni_t *zvni, struct prefix *vtep)
{
  kernel_add_vni_flood_list (zvni->vxlan_if, vtep);
  return 0;
}

/*
 * Uninstall remote VTEP from the kernel.
 */
static int
zvni_vtep_uninstall (zebra_vni_t *zvni, struct prefix *vtep)
{
  if (!zvni->vxlan_if)
    {
      zlog_err ("VNI %u hash %p couldn't be uninstalled - no intf",
                zvni->vni, zvni);
      return -1;
    }

  kernel_del_vni_flood_list (zvni->vxlan_if, vtep);

  return 0;
}

/*
 * Handle VxLAN interface add. Create VxLAN L2 interface info.
 * If EVPN is enabled, create VNI hash entry. If the interface is
 * a member of a bridge and is up, read bridge FDB and populate
 * local MACs associated with this bridge (and VLAN, if vlan-aware).
 * Likewise, read local neighbors associated with corresponding
 * VLAN device.
 */
static int
zebra_vxlan_if_add (struct zebra_vrf *zvrf, struct interface *ifp,
                    struct zebra_l2if_vxlan *zl2if)
{
  struct zebra_if *zif;
  struct zebra_l2if_vxlan *_zl2if;
  zebra_vni_t *zvni;
  vni_t vni;
  struct interface *vlan_if;

  zif = ifp->info;
  vni = zl2if->vni;

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Add intf %s(%u) VNI %u local IP %s master %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni,
                inet_ntoa (zl2if->vtep_ip),
                zl2if->br_slave.bridge_ifindex);

  /* Allocate L2 interface and copy over information. */
  zif->l2if = XCALLOC (MTYPE_ZEBRA_L2IF,
                       sizeof (struct zebra_l2if_vxlan));
  if (!zif->l2if)
    {
      zlog_err ("Failed to alloc VxLAN L2IF VRF %d IF %s(%u)",
                ifp->vrf_id, ifp->name, ifp->ifindex);
      return -1;
    }

  _zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  *_zl2if = *zl2if;

  /* Set up link with master. */
  if (_zl2if->br_slave.bridge_ifindex != IFINDEX_INTERNAL)
    zebra_l2_map_slave_to_bridge (&_zl2if->br_slave);

  /* If EVPN is not enabled, nothing further to be done. */
  if (!EVPN_ENABLED(zvrf))
    return 0;

  /* Create or update VNI hash. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zvni = zvni_add (zvrf, vni);
      if (!zvni)
        {
          zlog_err ("Failed to add VNI hash, VRF %d IF %s(%u) VNI %u",
                    ifp->vrf_id, ifp->name, ifp->ifindex, vni);
          return -1;
        }
    }

  zvni->local_vtep_ip = zl2if->vtep_ip;
  zvni->vxlan_if = ifp;

  /* If down or not mapped to a bridge, we're done. */
  if (!if_is_operative (ifp) || !_zl2if->br_slave.br_if)
    return 0;

  /* Inform BGP and read and populate local MACs and neighbors. */
  zvni_send_add_to_client (zvrf, zvni);

  /* Read and populate local MACs and neighbors corresponding to this VxLAN. */
  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Reading MAC FDB and Neighbors for intf %s(%u) VNI %u master %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni,
                _zl2if->br_slave.bridge_ifindex);

  macfdb_read_for_bridge (zvrf->zns, ifp, _zl2if->br_slave.br_if);
  vlan_if = zvni_map_to_vlanif (zvrf, _zl2if->access_vlan,
                                _zl2if->br_slave.br_if);
  if (vlan_if)
    neigh_read_for_vlan (zvrf->zns, vlan_if);

  return 0;
}


/*
 * Handle VxLAN interface update. The only changes we're concerned with
 * are the "master" or local tunnel IP. Update these fields and link or
 * unlink from master. If EVPN is enabled, take additional necessary actions.
 */
static int
zebra_vxlan_if_update (struct zebra_vrf *zvrf, struct interface *ifp,
                       struct zebra_l2if_vxlan *zl2if)
{
  struct zebra_if *zif;
  struct zebra_l2if_vxlan *_zl2if;
  ifindex_t old_bridge_ifindex, new_bridge_ifindex;
  struct in_addr old_vtep_ip, new_vtep_ip;
  zebra_vni_t *zvni;
  vni_t vni;
  struct interface *vlan_if;

  zif = ifp->info;
  _zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  assert (_zl2if);
  vni = zl2if->vni;
  old_bridge_ifindex = _zl2if->br_slave.bridge_ifindex;
  old_vtep_ip = _zl2if->vtep_ip;
  new_bridge_ifindex = zl2if->br_slave.bridge_ifindex;
  new_vtep_ip = zl2if->vtep_ip;

  /* Any change of interest? */
  if (old_bridge_ifindex == new_bridge_ifindex &&
      IPV4_ADDR_SAME(&old_vtep_ip, &new_vtep_ip))
    return 0;

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Update intf %s(%u) VNI %u local IP %s master %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni,
                inet_ntoa (new_vtep_ip), new_bridge_ifindex);

  /* If EVPN is not enabled, just update fields and return. */
  if (!EVPN_ENABLED(zvrf))
    {
      _zl2if->br_slave.bridge_ifindex = new_bridge_ifindex;
      _zl2if->vtep_ip = new_vtep_ip;

      /* Set up or remove link with master */
      if (new_bridge_ifindex != IFINDEX_INTERNAL)
        zebra_l2_map_slave_to_bridge (&_zl2if->br_slave);
      else
        zebra_l2_unmap_slave_from_bridge (&_zl2if->br_slave);

      return 0;
    }

  _zl2if->vtep_ip = new_vtep_ip;

  /* Removed from bridge? */
  if (old_bridge_ifindex != new_bridge_ifindex &&
      new_bridge_ifindex == IFINDEX_INTERNAL)
    {
      /* Delete from BGP and free up all neighbors and MAC and remote VTEPs. */
      zvni = zvni_lookup (zvrf, vni);
      if (zvni)
        {
          zvni_send_del_to_client (zvrf, zvni->vni);
          zvni_neigh_del_all (zvrf, zvni, 1, 0, DEL_ALL_NEIGH);
          zvni_mac_del_all (zvrf, zvni, 1, 0, DEL_ALL_MAC);
          zvni_vtep_del_all (zvni, 1);
          zvni->local_vtep_ip = new_vtep_ip;
        }

      /* Remove link from master. */
      _zl2if->br_slave.bridge_ifindex = new_bridge_ifindex;
      zebra_l2_unmap_slave_from_bridge (&_zl2if->br_slave);
      return 0;
    }

  /* Set up link with master, if needed. */
  if (old_bridge_ifindex != new_bridge_ifindex)
    {
      _zl2if->br_slave.bridge_ifindex = new_bridge_ifindex;
      zebra_l2_map_slave_to_bridge (&_zl2if->br_slave);
    }

  /* Update VNI hash. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to find VNI hash on update, VRF %d IF %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);
      return -1;
    }

  zvni->local_vtep_ip = zl2if->vtep_ip;
  zvni->vxlan_if = ifp;

  /* Take further actions needed. Note that if we are here, either there
   * is a local IP change or we're mapped to a bridge.
   */
  /* If down or not mapped to a bridge, we're done. */
  if (!if_is_operative (ifp) || !_zl2if->br_slave.br_if)
    return 0;

  /* Inform BGP. */
  zvni_send_add_to_client (zvrf, zvni);

  /* If mapped to a bridge, read and populate local MACs corresponding
   * to this VxLAN. Also, read local neighbors on corresponding VLAN
   * device.
   */
  if (old_bridge_ifindex != new_bridge_ifindex)
    {
      if (IS_ZEBRA_DEBUG_VXLAN)
        zlog_debug ("%u:Reading MAC FDB and Neighbors for intf %s(%u) VNI %u master %u",
                    ifp->vrf_id, ifp->name, ifp->ifindex, vni,
                    _zl2if->br_slave.bridge_ifindex);

      macfdb_read_for_bridge (zvrf->zns, ifp, _zl2if->br_slave.br_if);
      vlan_if = zvni_map_to_vlanif (zvrf, _zl2if->access_vlan,
                                    _zl2if->br_slave.br_if);
      if (vlan_if)
        neigh_read_for_vlan (zvrf->zns, vlan_if);
    }

  return 0;
}

/*
 * Helper function to determine maximum width of neighbor IP address for
 * display - just because we're dealing with IPv6 addresses that can
 * widely vary.
 */
static void
zvni_find_neigh_addr_width (struct hash_backet *backet, void *ctxt)
{
  zebra_neigh_t *n;
  char buf[INET6_ADDRSTRLEN];
  struct neigh_walk_ctx *wctx = ctxt;
  int width;

  n = (zebra_neigh_t *) backet->data;
  if (!n)
    return;

  ipaddr2str (&n->ip, buf, sizeof(buf)),
  width = strlen (buf);
  if (width > wctx->addr_width)
    wctx->addr_width = width;
}

/*
 * Decrement neighbor refcount of MAC; uninstall and free it if
 * appropriate.
 */
static void
zvni_deref_ip2mac (zebra_vni_t *zvni, zebra_mac_t *mac, int uninstall)
{
  if (mac->neigh_refcnt)
    mac->neigh_refcnt--;

  if (!CHECK_FLAG (mac->flags, ZEBRA_MAC_AUTO) ||
      mac->neigh_refcnt > 0)
    return;

  if (uninstall)
    zvni_mac_uninstall (zvni, mac);

  zvni_mac_del (zvni, mac);
}

/*
 * Print a specific neighbor entry.
 */
static void
zvni_print_neigh (zebra_neigh_t *n, void *ctxt)
{
  struct vty *vty;
  char buf1[MACADDR_STRLEN];
  char buf2[INET6_ADDRSTRLEN];

  ipaddr2str (&n->ip, buf2, sizeof(buf2)),
  vty = (struct vty *) ctxt;
  vty_out(vty, "IP: %s%s",
          ipaddr2str (&n->ip, buf2, sizeof(buf2)), VTY_NEWLINE);
  vty_out(vty, " MAC: %s", mac2str (&n->emac, buf1, sizeof (buf1)));
  if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_REMOTE))
    vty_out(vty, " Remote VTEP: %s", inet_ntoa (n->r_vtep_ip));
  vty_out(vty, "%s", VTY_NEWLINE);
}

/*
 * Print neighbor hash entry - called for display of all neighbors.
 */
static void
zvni_print_neigh_hash (struct hash_backet *backet, void *ctxt)
{
  struct vty *vty;
  zebra_neigh_t *n;
  char buf1[MACADDR_STRLEN];
  char buf2[INET6_ADDRSTRLEN];
  struct neigh_walk_ctx *wctx = ctxt;

  vty = wctx->vty;
  n = (zebra_neigh_t *) backet->data;
  if (!n)
    return;

  mac2str (&n->emac, buf1, sizeof (buf1));
  ipaddr2str (&n->ip, buf2, sizeof(buf2));
  if (CHECK_FLAG(n->flags, ZEBRA_NEIGH_LOCAL) &&
      !(wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP))
    {
      vty_out(vty, "%*s %-6s %-17s %s",
              -wctx->addr_width, buf2, "local", buf1, VTY_NEWLINE);
      wctx->count++;
    }
  else
    {
      if (wctx->flags & SHOW_REMOTE_NEIGH_FROM_VTEP)
        {
          if (IPV4_ADDR_SAME(&n->r_vtep_ip, &wctx->r_vtep_ip))
            {
              if (wctx->count == 0)
                vty_out(vty, "%*s %-6s %-17s %-21s%s",
                        -wctx->addr_width, "Neighbor", "Type", "MAC",
                        "Remote VTEP", VTY_NEWLINE);
              vty_out(vty, "%*s %-6s %-17s %-21s%s",
                      -wctx->addr_width, buf2, "remote", buf1,
                      inet_ntoa (n->r_vtep_ip), VTY_NEWLINE);
              wctx->count++;
            }
        }
      else
        {
          vty_out(vty, "%*s %-6s %-17s %-21s%s",
                  -wctx->addr_width, buf2, "remote", buf1,
                  inet_ntoa (n->r_vtep_ip), VTY_NEWLINE);
          wctx->count++;
        }
    }
}

/*
 * Print neighbors for all VNI.
 */
static void
zvni_print_neigh_hash_all_vni (struct hash_backet *backet, void *ctxt)
{
  struct vty *vty;
  zebra_vni_t *zvni;
  u_int32_t num_neigh;
  struct neigh_walk_ctx wctx;

  vty = (struct vty *) ctxt;
  zvni = (zebra_vni_t *) backet->data;
  if (!zvni)
    return;

  num_neigh = hashcount(zvni->neigh_table);
  vty_out(vty, "%sVNI %u #ARP (IPv4 and IPv6, local and remote) %u%s%s",
          VTY_NEWLINE, zvni->vni, num_neigh, VTY_NEWLINE, VTY_NEWLINE);
  if (!num_neigh)
    return;

  /* Since we have IPv6 addresses to deal with which can vary widely in
   * size, we try to be a bit more elegant in display by first computing
   * the maximum width.
   */
  memset (&wctx, 0, sizeof (struct neigh_walk_ctx));
  wctx.zvni = zvni;
  wctx.vty = vty;
  wctx.addr_width = 15;
  hash_iterate(zvni->neigh_table, zvni_find_neigh_addr_width, &wctx);

  vty_out(vty, "%*s %-6s %-17s %-21s%s",
          -wctx.addr_width, "IP", "Type", "MAC",
          "Remote VTEP", VTY_NEWLINE);
  hash_iterate(zvni->neigh_table, zvni_print_neigh_hash, &wctx);
}

/*
 * Print a specific MAC entry.
 */
static void
zvni_print_mac (zebra_mac_t *mac, void *ctxt)
{
  struct vty *vty;
  char buf1[20];

  vty = (struct vty *) ctxt;
  vty_out(vty, "MAC: %s%s",
          mac2str (&mac->macaddr, buf1, sizeof (buf1)), VTY_NEWLINE);
  if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL))
    {
      struct zebra_ns *zns;
      struct interface *ifp;
      ifindex_t ifindex;

      ifindex = mac->fwd_info.local.ifindex;
      zns = zebra_ns_lookup (NS_DEFAULT);
      ifp = if_lookup_by_index_per_ns (zns, ifindex);
      if (!ifp) // unexpected
        return;
      vty_out(vty, " Intf: %s(%u)", ifp->name, ifindex);
      if (mac->fwd_info.local.vid)
        vty_out(vty, " VLAN: %u", mac->fwd_info.local.vid);
    }
  else
    {
      vty_out(vty, " Remote VTEP: %s",
              inet_ntoa (mac->fwd_info.r_vtep_ip));
    }
  vty_out(vty, " ARP ref: %u", mac->neigh_refcnt);
  vty_out(vty, "%s", VTY_NEWLINE);
}

/*
 * Print MAC hash entry - called for display of all MACs.
 */
static void
zvni_print_mac_hash (struct hash_backet *backet, void *ctxt)
{
  struct vty *vty;
  zebra_mac_t *mac;
  char buf1[20];
  struct mac_walk_ctx *wctx = ctxt;

  vty = wctx->vty;
  mac = (zebra_mac_t *) backet->data;
  if (!mac)
    return;

  mac2str (&mac->macaddr, buf1, sizeof (buf1));
  if (CHECK_FLAG(mac->flags, ZEBRA_MAC_LOCAL) &&
      !(wctx->flags & SHOW_REMOTE_MAC_FROM_VTEP))
    {
      struct zebra_ns *zns;
      ifindex_t ifindex;
      struct interface *ifp;
      vlanid_t vid;

      zns = zebra_ns_lookup (NS_DEFAULT);
      ifindex = mac->fwd_info.local.ifindex;
      ifp = if_lookup_by_index_per_ns (zns, ifindex);
      if (!ifp) // unexpected
        return;
      vid = mac->fwd_info.local.vid;
      vty_out(vty, "%-17s %-6s %-21s",
              buf1, "local", ifp->name);
      if (vid)
        vty_out(vty, " %-5u", vid);
      vty_out(vty, "%s", VTY_NEWLINE);
      wctx->count++;
    }
  else
    {
      if (wctx->flags & SHOW_REMOTE_MAC_FROM_VTEP)
        {
          if (IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip,
                             &wctx->r_vtep_ip))
            {
              if (wctx->count == 0)
                vty_out(vty, "%-17s %-6s %-21s %-5s%s",
                        "MAC", "Type", "Intf/Remote VTEP",
                        "VLAN", VTY_NEWLINE);

              vty_out(vty, "%-17s %-6s %-21s%s",
                      buf1, "remote",
                      inet_ntoa (mac->fwd_info.r_vtep_ip),
                      VTY_NEWLINE);
              wctx->count++;
            }
        }
      else
        {
          vty_out(vty, "%-17s %-6s %-21s%s",
                  buf1, "remote",
                  inet_ntoa (mac->fwd_info.r_vtep_ip), VTY_NEWLINE);
          wctx->count++;
        }
    }

}

/*
 * Print MACs for all VNI.
 */
static void
zvni_print_mac_hash_all_vni (struct hash_backet *backet, void *ctxt)
{
  struct vty *vty;
  zebra_vni_t *zvni;
  u_int32_t num_macs;
  struct mac_walk_ctx wctx;

  vty = (struct vty *) ctxt;
  zvni = (zebra_vni_t *) backet->data;
  if (!zvni)
    return;

  num_macs = hashcount(zvni->mac_table);
  vty_out(vty, "%sVNI %u #MACs (local and remote) %u%s%s",
          VTY_NEWLINE, zvni->vni, num_macs, VTY_NEWLINE, VTY_NEWLINE);
  if (!num_macs)
    return;

  memset (&wctx, 0, sizeof (struct mac_walk_ctx));
  wctx.zvni = zvni;
  wctx.vty = vty;

  vty_out(vty, "%-17s %-6s %-21s %-5s%s",
          "MAC", "Type", "Intf/Remote VTEP", "VLAN", VTY_NEWLINE);
  hash_iterate(zvni->mac_table, zvni_print_mac_hash, &wctx);
}

/*
 * Print a specific VNI entry.
 */
static void
zvni_print (zebra_vni_t *zvni, void *ctxt)
{
  struct vty *vty;
  zebra_vtep_t *zvtep;
  char buf[PREFIX_STRLEN];
  u_int32_t num_macs;
  u_int32_t num_neigh;

  vty = (struct vty *) ctxt;

  vty_out(vty, "VNI: %u%s", zvni->vni, VTY_NEWLINE);
  if (!zvni->vxlan_if)
    { // unexpected
      vty_out(vty, " VxLAN interface: unknown%s", VTY_NEWLINE);
      return;
    }
  vty_out(vty, " VxLAN interface: %s ifIndex: %u VTEP IP: %s%s",
          zvni->vxlan_if->name, zvni->vxlan_if->ifindex, 
          inet_ntoa(zvni->local_vtep_ip), VTY_NEWLINE);

  if (!zvni->vteps)
    {
      vty_out(vty, " No remote VTEPs known for this VNI%s", VTY_NEWLINE);
    }
  else
    {
      vty_out(vty, " Remote VTEPs for this VNI:%s", VTY_NEWLINE);
      for (zvtep = zvni->vteps; zvtep; zvtep = zvtep->next)
        {
          struct prefix *p = &zvtep->vtep_ip;
          vty_out(vty, "  %s%s",
                  inet_ntop (p->family, &p->u.prefix, buf, sizeof (buf)),
                  VTY_NEWLINE);
        }
    }
  num_macs = hashcount(zvni->mac_table);
  vty_out(vty, " Number of MACs (local and remote) known for this VNI: %u%s",
          num_macs, VTY_NEWLINE);
  num_neigh = hashcount(zvni->neigh_table);
  vty_out(vty, " Number of ARPs (IPv4 and IPv6, local and remote) "
          "known for this VNI: %u%s", num_neigh, VTY_NEWLINE);
}

/*
 * Print a VNI hash entry - called for display of all VNIs.
 */
static void
zvni_print_hash (struct hash_backet *backet, void *ctxt)
{
  struct vty *vty;
  zebra_vni_t *zvni;
  zebra_vtep_t *zvtep;
  struct prefix *p;
  u_int32_t num_macs;
  u_int32_t num_neigh;
  char buf[PREFIX_STRLEN];

  vty = (struct vty *) ctxt;
  zvni = (zebra_vni_t *) backet->data;
  if (!zvni)
    return;

  zvtep = zvni->vteps;
  buf[0] = '\0';
  if (zvtep)
    {
      p = &zvtep->vtep_ip;
      inet_ntop (p->family, &p->u.prefix, buf, sizeof (buf));
    }
  num_macs = hashcount(zvni->mac_table);
  num_neigh = hashcount(zvni->neigh_table);
  vty_out(vty, "%-10u %-21s %-15s %-8u %-8u %-15s%s",
          zvni->vni,
          zvni->vxlan_if ? zvni->vxlan_if->name : "unknown",
          inet_ntoa(zvni->local_vtep_ip),
          num_macs, num_neigh, buf, VTY_NEWLINE);

  /* Additional remote VTEPs go one per line. */
  if (zvtep)
    {
      zvtep = zvtep->next;
      for (; zvtep; zvtep = zvtep->next)
        {
          p = &zvtep->vtep_ip;
          vty_out(vty, "%*s %-15s%s", 66, " ",
                  inet_ntop (p->family, &p->u.prefix, buf, sizeof (buf)),
                  VTY_NEWLINE);
        }
    }
}

/* Cleanup VNI/VTEP and update kernel */
static void
zvni_cleanup_all (struct hash_backet *backet, void *zvrf)
{
  zebra_vni_t *zvni;

  zvni = (zebra_vni_t *) backet->data;
  if (!zvni)
    return;

  /* Free up all neighbors and MACs, if any. */
  zvni_neigh_del_all (zvrf, zvni, 1, 0, DEL_ALL_NEIGH);
  zvni_mac_del_all (zvrf, zvni, 1, 0, DEL_ALL_MAC);

  /* Free up all remote VTEPs, if any. */
  zvni_vtep_del_all (zvni, 1);

  /* Delete the hash entry. */
  zvni_del (zvrf, zvni);
}


/* Public functions */

/*
 * Handle VxLAN interface up - update BGP if required.
 */
int
zebra_vxlan_if_up (struct interface *ifp)
{
  struct zebra_if *zif;
  struct zebra_l2if_vxlan *zl2if;
  struct zebra_vrf *zvrf;
  zebra_vni_t *zvni;
  vni_t vni;
  struct interface *vlan_if;

  zif = ifp->info;
  assert(zif);
  zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  assert(zl2if);

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  if (!EVPN_ENABLED(zvrf))
    return 0;

  vni = VNI_FROM_ZEBRA_IF (zif);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Intf %s(%u) VNI %u is UP",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);

  /* Locate hash entry; it is expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to locate VNI hash at UP, VRF %d IF %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);
      return -1;
    }

  assert (zvni->vxlan_if == ifp);

  /* If part of a bridge, inform BGP about this VNI, learn local MACs and
   * local neighbors.
   */
  if (zl2if->br_slave.br_if)
    {
      zvni_send_add_to_client (zvrf, zvni);

      if (IS_ZEBRA_DEBUG_VXLAN)
        zlog_debug ("%u:Reading MAC FDB and Neighbors for intf %s(%u) VNI %u master %u",
                    ifp->vrf_id, ifp->name, ifp->ifindex, vni,
                    zl2if->br_slave.bridge_ifindex);

      macfdb_read_for_bridge (zvrf->zns, ifp, zl2if->br_slave.br_if);
      vlan_if = zvni_map_to_vlanif (zvrf, zl2if->access_vlan,
                                    zl2if->br_slave.br_if);
      if (vlan_if)
        neigh_read_for_vlan (zvrf->zns, vlan_if);
    }

  return 0;
}

/*
 * Handle VxLAN interface down - update BGP if required, and do
 * internal cleanup.
 */
int
zebra_vxlan_if_down (struct interface *ifp)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  zebra_vni_t *zvni;
  vni_t vni;

  zif = ifp->info;
  assert(zif);

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  if (!EVPN_ENABLED(zvrf))
    return 0;

  vni = VNI_FROM_ZEBRA_IF (zif);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Intf %s(%u) VNI %u is DOWN",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);

  /* Locate hash entry; it is expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to locate VNI hash at DOWN, VRF %d IF %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);
      return -1;
    }

  assert (zvni->vxlan_if == ifp);

  /* Delete this VNI from BGP. */
  zvni_send_del_to_client (zvrf, zvni->vni);

  /* Free up all neighbors and MACs, if any. */
  zvni_neigh_del_all (zvrf, zvni, 1, 0, DEL_ALL_NEIGH);
  zvni_mac_del_all (zvrf, zvni, 1, 0, DEL_ALL_MAC);

  /* Free up all remote VTEPs, if any. */
  zvni_vtep_del_all (zvni, 1);

  return 0;
}

/*
 * Handle VxLAN interface add or update. Create/update VxLAN L2
 * interface info and store VNI in hash table.
 * When the interface is added and is a member of a bridge, need
 * to read bridge FDB and populate local MACs associated with this
 * bridge (and VLAN, if vlan-aware). When removed from bridge, need
 * to clean up local MACs and purge remote MACs. The VNI is informed
 * to BGP only if up and a member of a bridge; it is to be removed
 * when either condition changes.
 */
int
zebra_vxlan_if_add_update (struct interface *ifp,
                           struct zebra_l2if_vxlan *zl2if)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;

  zif = ifp->info;
  assert(zif);

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  if (!zif->l2if)
    return zebra_vxlan_if_add (zvrf, ifp, zl2if);

  return zebra_vxlan_if_update (zvrf, ifp, zl2if);
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
  struct zebra_l2if_vxlan *_zl2if;
  vni_t vni;
  zebra_vni_t *zvni;

  zif = ifp->info;
  assert(zif);
  _zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  assert(_zl2if);
  vni = _zl2if->vni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* If EVPN is not enabled, just need to free the L2 interface. */
  if (!EVPN_ENABLED(zvrf))
    {
      XFREE (MTYPE_ZEBRA_L2IF, _zl2if);
      zif->l2if = NULL;
      return 0;
    }

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

  /* Delete VNI from BGP. */
  zvni_send_del_to_client (zvrf, zvni->vni);

  /* Free up all neighbors and MAC, if any. */
  zvni_neigh_del_all (zvrf, zvni, 0, 0, DEL_ALL_NEIGH);
  zvni_mac_del_all (zvrf, zvni, 0, 0, DEL_ALL_MAC);

  /* Free up all remote VTEPs, if any. */
  zvni_vtep_del_all (zvni, 0);

  /* Delete the hash entry. */
  if (zvni_del (zvrf, zvni))
    {
      zlog_err ("Failed to del VNI hash %p, VRF %d IF %s(%u) VNI %u",
                zvni, ifp->vrf_id, ifp->name, ifp->ifindex, zvni->vni);
      return -1;
    }

  /* Free the L2 interface */
  XFREE (MTYPE_ZEBRA_L2IF, _zl2if);
  zif->l2if = NULL;

  return 0;
}


/*
 * Update the access VLAN for a VNI. This is applicable for a VLAN-aware
 * bridge.
 */
int zebra_vxlan_update_access_vlan (struct interface *ifp,
                                    vlanid_t access_vlan)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  struct zebra_l2if_vxlan *zl2if;
  zebra_vni_t *zvni;
  vni_t vni;
  struct mac_walk_ctx m_wctx;
  struct neigh_walk_ctx n_wctx;
  struct interface *vlan_if;

  zif = ifp->info;
  assert(zif);
 
  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  assert(zl2if);

  if (zl2if->access_vlan == access_vlan)
    return 0;

  /* If not operational or not tied to a bridge or EVPN is not enabled, just
   * update the value.
   */
  if (!if_is_operative (ifp) ||
      !zl2if->br_slave.br_if ||
      !EVPN_ENABLED(zvrf))
    {
      zl2if->access_vlan = access_vlan;
      return 0;
    }

  vni = VNI_FROM_ZEBRA_IF (zif);

  /* Locate hash entry; it is expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to locate VNI hash upon VLAN update, VRF %d IF %s(%u) VNI %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni);
      zl2if->access_vlan = access_vlan;
      return -1;
    }

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Intf %s(%u) VNI %u access VLAN %u -> %u",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni,
                zl2if->access_vlan, access_vlan);

  /* Remove all existing local neighbors and MACs for this VNI
   * (including from BGP)
   */
  zvni_neigh_del_all (zvrf, zvni, 0, 1, DEL_LOCAL_MAC);
  zvni_mac_del_all (zvrf, zvni, 0, 1, DEL_LOCAL_MAC);

  /* Update the VLAN and read MAC FDB and Neighbors corresponding to this VNI. */
  zl2if->access_vlan = access_vlan;
  macfdb_read_for_bridge (zvrf->zns, ifp, zl2if->br_slave.br_if);
  vlan_if = zvni_map_to_vlanif (zvrf, zl2if->access_vlan,
                                zl2if->br_slave.br_if);
  if (vlan_if)
    neigh_read_for_vlan (zvrf->zns, vlan_if);

  /* Reinstall any remote MACs for this VNI - with new VLAN info. */
  memset (&m_wctx, 0, sizeof (struct mac_walk_ctx));
  m_wctx.zvni = zvni;
  hash_iterate(zvni->mac_table, zvni_install_mac_hash, &m_wctx);

  /* Reinstall any remote neighbors for this VNI - with new VLAN info. */
  memset (&n_wctx, 0, sizeof (struct neigh_walk_ctx));
  n_wctx.zvni = zvni;
  hash_iterate(zvni->neigh_table, zvni_install_neigh_hash, &n_wctx);

  return 0;
}
 
/*
 * Handle message from client to add a remote VTEP for a VNI.
 */
int zebra_vxlan_remote_vtep_add (struct zserv *client, int sock,
                                 u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  u_short l = 0;
  vni_t vni;
  struct prefix vtep;
  zebra_vni_t *zvni;
  char pbuf[PREFIX2STR_BUFFER];

  assert (EVPN_ENABLED (zvrf));

  s = client->ibuf;

  while (l < length)
    {
      /* Obtain each remote VTEP and process. */
      vni = (vni_t) stream_getl (s);
      stream_getc (s); // flags, currently unused
      vtep.family = stream_getw (s);
      vtep.prefixlen = stream_getc (s);
      l += 8;
      if (vtep.family == AF_INET)
        {
          vtep.u.prefix4.s_addr = stream_get_ipv4(s);
          l += IPV4_MAX_BYTELEN;
        }
      else if (vtep.family == AF_INET6)
        {
          stream_get(&vtep.u.prefix6, s, IPV6_MAX_BYTELEN);
          l += IPV6_MAX_BYTELEN;
        }
      else
        {
          zlog_err("remote-vtep-add: Received unknown family type %d\n",
                   vtep.family);
          return -1;
        }

      if (IS_ZEBRA_DEBUG_VXLAN)
        zlog_debug ("%u:Recv VTEP_ADD %s VNI %u from %s",
                    zvrf->vrf_id, prefix2str (&vtep, pbuf, sizeof(pbuf)),
                    vni, zebra_route_string (client->proto));

      /* Locate VNI hash entry - expected to exist. */
      zvni = zvni_lookup (zvrf, vni);
      if (!zvni)
        {
          zlog_err ("Failed to locate VNI hash upon remote VTEP ADD, VRF %d VNI %u",
                    zvrf->vrf_id, vni);
          continue;
        }
      if (!zvni->vxlan_if)
        {
          zlog_err ("VNI %u hash %p doesn't have intf upon remote VTEP ADD",
                    zvni->vni, zvni);
          continue;
        }


      /* If the remote VTEP already exists, or the local VxLAN interface is
       * not up (should be a transient event),  there's nothing more to do.
       * Otherwise, add and install the entry.
       */
      if (zvni_vtep_find (zvni, &vtep))
        continue;

      if (!if_is_operative (zvni->vxlan_if))
        continue;

      if (zvni_vtep_add (zvni, &vtep) == NULL)
        {
          zlog_err ("Failed to add remote VTEP, VRF %d VNI %u zvni %p",
                    zvrf->vrf_id, vni, zvni);
          continue;
        }

      zvni_vtep_install (zvni, &vtep);
    }

  return 0;
}

/*
 * Handle message from client to delete a remote VTEP for a VNI.
 */
int zebra_vxlan_remote_vtep_del (struct zserv *client, int sock,
                                 u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  u_short l = 0;
  vni_t vni;
  struct prefix vtep;
  zebra_vni_t *zvni;
  zebra_vtep_t *zvtep;
  char pbuf[PREFIX2STR_BUFFER];

  s = client->ibuf;

  while (l < length)
    {
      /* Obtain each remote VTEP and process. */
      vni = (vni_t) stream_getl (s);
      stream_getc (s); // flags, currently unused
      vtep.family = stream_getw (s);
      vtep.prefixlen = stream_getc (s);
      l += 8;
      if (vtep.family == AF_INET)
        {
          vtep.u.prefix4.s_addr = stream_get_ipv4(s);
          l += IPV4_MAX_BYTELEN;
        }
      else if (vtep.family == AF_INET6)
        {
          stream_get(&vtep.u.prefix6, s, IPV6_MAX_BYTELEN);
          l += IPV6_MAX_BYTELEN;
        }
      else
        {
          zlog_err("remote-vtep-del: Received unknown family type %d\n",
                   vtep.family);
          return -1;
        }

      if (IS_ZEBRA_DEBUG_VXLAN)
        zlog_debug ("%u:Recv VTEP_DEL %s VNI %u from %s",
                    zvrf->vrf_id, prefix2str (&vtep, pbuf, sizeof(pbuf)),
                    vni, zebra_route_string (client->proto));

      /* Locate VNI hash entry - expected to exist. */
      zvni = zvni_lookup (zvrf, vni);
      if (!zvni)
        {
          if (IS_ZEBRA_DEBUG_VXLAN)
            zlog_debug ("Failed to locate VNI hash upon remote VTEP DEL, "
                        "VRF %d VNI %u", zvrf->vrf_id, vni);
          continue;
        }

      /* If the remote VTEP does not exist, there's nothing more to do.
       * Otherwise, uninstall any remote MACs pointing to this VTEP and
       * then, the VTEP entry itself and remove it.
       */
      zvtep = zvni_vtep_find (zvni, &vtep);
      if (!zvtep)
        continue;

      /* TODO: Assumes VTEP IP can only be IPv4 */
      zvni_neigh_del_from_vtep (zvni, 1, &vtep.u.prefix4);
      zvni_mac_del_from_vtep (zvni, 1, &vtep.u.prefix4);
      zvni_vtep_uninstall (zvni, &vtep);
      zvni_vtep_del (zvni, zvtep);
    }

  return 0;
}

/*
 * Handle message from client to learn (or stop learning) about VNIs and MACs.
 * When enabled, the VNI hash table will be built and MAC FDB table read;
 * when disabled, the entries should be deleted and remote VTEPs and MACs
 * uninstalled from the kernel.
 */
int zebra_vxlan_advertise_all_vni (struct zserv *client, int sock,
                                   u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  int advertise;

  s = client->ibuf;
  advertise = stream_getc (s);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:EVPN VNI Adv %s, currently %s",
                zvrf->vrf_id, advertise ? "enabled" : "disabled",
                EVPN_ENABLED(zvrf) ? "enabled" : "disabled");

  if (zvrf->advertise_all_vni == advertise)
    return 0;

  zvrf->advertise_all_vni = advertise;
  if (EVPN_ENABLED(zvrf))
    {
      /* Build VNI hash table and inform BGP. */
      zvni_build_hash_table (zvrf);

      /* Read the MAC FDB */
      macfdb_read (zvrf->zns);

      /* Read neighbors */
      neigh_read (zvrf->zns);
    }
  else
    {
      /* Cleanup neighbors, MACs and VTEPs for all VNIs - uninstall from
       * kernel and free entries.
       */
      hash_iterate (zvrf->vni_table, zvni_cleanup_all, zvrf);
    }

  return 0;
}

/*
 * Handle local MAC add (on a port or VLAN corresponding to this VNI).
 */
int
zebra_vxlan_local_mac_add_update (struct interface *ifp, struct interface *br_if,
                                  struct ethaddr *macaddr, vlanid_t vid)
{
  zebra_vni_t *zvni;
  zebra_mac_t *mac;
  struct zebra_vrf *zvrf;
  char buf[MACADDR_STRLEN];
  int add = 1;

  /* We are interested in MACs only on ports or (port, VLAN) that
   * map to a VNI.
   */
  zvni = zvni_map_vlan (ifp, br_if, vid);
  if (!zvni)
    return 0;
  if (!zvni->vxlan_if)
    {
      zlog_err ("VNI %u hash %p doesn't have intf upon local MAC ADD",
                zvni->vni, zvni);
      return -1;
    }

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Add/Update MAC %s intf %s(%u) VID %u -> VNI %u",
                ifp->vrf_id, mac2str (macaddr, buf, sizeof (buf)),
                ifp->name, ifp->ifindex, vid, zvni->vni);

  /* If same entry already exists, nothing to do. */
  mac = zvni_mac_lookup (zvni, macaddr);
  if (mac)
    {
      if (CHECK_FLAG (mac->flags, ZEBRA_MAC_LOCAL) &&
          mac->fwd_info.local.ifindex == ifp->ifindex &&
          mac->fwd_info.local.vid == vid)
        return 0;
      if (CHECK_FLAG (mac->flags, ZEBRA_MAC_LOCAL))
        add = 0; /* This is an update of local interface. */
    }

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
  assert(zvrf);

  if (!mac)
    {
      mac = zvni_mac_add (zvni, macaddr);
      if (!mac)
        {
          zlog_err ("%u:Failed to add MAC %s intf %s(%u) VID %u",
                    ifp->vrf_id, mac2str (macaddr, buf, sizeof (buf)),
                  ifp->name, ifp->ifindex, vid);
          return -1;
        }
    }

  /* Set "local" forwarding info. */
  UNSET_FLAG (mac->flags, ZEBRA_MAC_REMOTE);
  memset (&mac->fwd_info, 0, sizeof (mac->fwd_info));
  SET_FLAG (mac->flags, ZEBRA_MAC_LOCAL);
  mac->fwd_info.local.ifindex = ifp->ifindex;
  mac->fwd_info.local.vid = vid;

  /* Inform BGP if required. */
  if (add)
    return zvni_mac_send_add_to_client (zvrf, zvni->vni, macaddr);

  return 0;
}

/*
 * Handle local MAC delete (on a port or VLAN corresponding to this VNI).
 */
int
zebra_vxlan_local_mac_del (struct interface *ifp, struct interface *br_if,
                           struct ethaddr *macaddr, vlanid_t vid)
{
  zebra_vni_t *zvni;
  zebra_mac_t *mac;
  struct zebra_vrf *zvrf;
  char buf[MACADDR_STRLEN];

  /* We are interested in MACs only on ports or (port, VLAN) that
   * map to a VNI.
   */
  zvni = zvni_map_vlan (ifp, br_if, vid);
  if (!zvni)
    return 0;
  if (!zvni->vxlan_if)
    {
      zlog_err ("VNI %u hash %p doesn't have intf upon local MAC DEL",
                zvni->vni, zvni);
      return -1;
    }

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Del MAC %s intf %s(%u) VID %u -> VNI %u",
                ifp->vrf_id, mac2str (macaddr, buf, sizeof (buf)),
                ifp->name, ifp->ifindex, vid, zvni->vni);

  /* If entry doesn't exist, nothing to do. */
  mac = zvni_mac_lookup (zvni, macaddr);
  if (!mac)
    return 0;

  /* Is it a local entry? */
  if (!CHECK_FLAG (mac->flags, ZEBRA_MAC_LOCAL))
    return 0;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
  assert(zvrf);

  /* Remove MAC from BGP. */
  zvni_mac_send_del_to_client (zvrf, zvni->vni, macaddr);

  /* Delete this MAC entry. */
  zvni_mac_del (zvni, mac);

  return 0;
}

/*
 * Handle remote MAC delete by kernel; readd the remote MAC if we have it.
 * This can happen because the remote MAC entries are also added as "dynamic",
 * so the kernel can ageout the entry.
 */
int
zebra_vxlan_check_readd_remote_mac (struct interface *ifp,
                                    struct interface *br_if,
                                    struct ethaddr *macaddr, vlanid_t vid)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  struct zebra_l2if_vxlan *_zl2if;
  vni_t vni;
  zebra_vni_t *zvni;
  zebra_mac_t *mac;
  char buf[MACADDR_STRLEN];

  zif = ifp->info;
  assert(zif);
  _zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  assert(_zl2if);
  vni = _zl2if->vni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* If EVPN is not enabled, nothing to do. */
  if (!EVPN_ENABLED(zvrf))
    return 0;

  /* Locate hash entry; it is expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    return 0;

  /* If entry doesn't exist, nothing to do. */
  mac = zvni_mac_lookup (zvni, macaddr);
  if (!mac)
    return 0;

  /* Is it a remote entry? */
  if (!CHECK_FLAG (mac->flags, ZEBRA_MAC_REMOTE))
    return 0;

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Del remote MAC %s intf %s(%u) VNI %u - readd",
                ifp->vrf_id, mac2str (macaddr, buf, sizeof (buf)),
                ifp->name, ifp->ifindex, vni);

  zvni_mac_install (zvni, mac);
  return 0;
}

/*
 * Handle notification of MAC add/update over VxLAN. If the kernel is notifying
 * us, this must involve a multihoming scenario. Treat this as implicit delete
 * of any prior local MAC.
 */
int
zebra_vxlan_check_del_local_mac (struct interface *ifp,
                                 struct interface *br_if,
                                 struct ethaddr *macaddr, vlanid_t vid)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  struct zebra_l2if_vxlan *_zl2if;
  vni_t vni;
  zebra_vni_t *zvni;
  zebra_mac_t *mac;
  char buf[MACADDR_STRLEN];

  zif = ifp->info;
  assert(zif);
  _zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  assert(_zl2if);
  vni = _zl2if->vni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  /* If EVPN is not enabled, nothing to do. */
  if (!EVPN_ENABLED(zvrf))
    return 0;

  /* Locate hash entry; it is expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    return 0;

  /* If entry doesn't exist, nothing to do. */
  mac = zvni_mac_lookup (zvni, macaddr);
  if (!mac)
    return 0;

  /* Is it a local entry? */
  if (!CHECK_FLAG (mac->flags, ZEBRA_MAC_LOCAL))
    return 0;

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Add/update remote MAC %s intf %s(%u) VNI %u - del local",
                ifp->vrf_id, mac2str (macaddr, buf, sizeof (buf)),
                ifp->name, ifp->ifindex, vni);

  /* Remove MAC from BGP. */
  zvni_mac_send_del_to_client (zvrf, zvni->vni, macaddr);

  /* Delete this MAC entry. */
  zvni_mac_del (zvni, mac);

  return 0;
}


/*
 * Handle message from client to add a remote MACIP for a VNI. This
 * could be just the add of a MAC address or the add of a neighbor
 * (IP+MAC).
 */
int 
zebra_vxlan_remote_macip_add (struct zserv *client, int sock,
                              u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  vni_t vni;
  struct ethaddr macaddr;
  struct ipaddr ip;
  struct prefix r_vtep;
  zebra_vni_t *zvni;
  zebra_vtep_t *zvtep;
  zebra_mac_t *mac, *old_mac;
  zebra_neigh_t *n;
  u_short l = 0, ipa_len;
  int update_mac = 0, update_neigh = 0;
  char buf[MACADDR_STRLEN];
  char buf1[INET6_ADDRSTRLEN];

  assert (EVPN_ENABLED (zvrf));

  s = client->ibuf;

  while (l < length)
    {
      /* Obtain each remote MACIP and process. */
      /* Message contains VNI, followed by MAC followed by IP (if any)
       * followed by remote VTEP IP.
       */
      update_mac = update_neigh = 0;
      mac = NULL;
      n = NULL;
      memset (&ip, 0, sizeof (ip));
      vni = (vni_t) stream_getl (s);
      stream_get (&macaddr.octet, s, ETHER_ADDR_LEN);
      ipa_len = stream_getl (s);
      if (ipa_len)
        {
          ip.ipa_type = (ipa_len == IPV4_MAX_BYTELEN) ? IPADDR_V4: IPADDR_V6;
          stream_get (&ip.ip.addr, s, ipa_len);
        }
      l += 4 + ETHER_ADDR_LEN + 4 + ipa_len;
      r_vtep.family = AF_INET;
      r_vtep.prefixlen = IPV4_MAX_BITLEN;
      r_vtep.u.prefix4.s_addr = stream_get_ipv4(s);
      l += IPV4_MAX_BYTELEN;

      if (IS_ZEBRA_DEBUG_VXLAN)
        zlog_debug ("%u:Recv MACIP Add MAC %s IP %s VNI %u Remote VTEP %s from %s",
                    zvrf->vrf_id,
                    mac2str (&macaddr, buf, sizeof (buf)),
                    ipaddr2str (&ip, buf1, sizeof (buf1)),
                    vni, inet_ntoa (r_vtep.u.prefix4),
                    zebra_route_string (client->proto));

      /* Locate VNI hash entry - expected to exist. */
      zvni = zvni_lookup (zvrf, vni);
      if (!zvni)
        {
          zlog_err ("Failed to locate VNI hash upon remote MACIP ADD, VRF %d VNI %u",
                    zvrf->vrf_id, vni);
          continue;
        }
      if (!zvni->vxlan_if)
        {
          zlog_err ("VNI %u hash %p doesn't have intf upon remote MACIP add",
                    vni, zvni);
          continue;
        }
      /* If the local VxLAN interface is not up (should be a transient
       * event),  there's nothing more to do.
       */
      if (!if_is_operative (zvni->vxlan_if))
        continue;

      /* The remote VTEP specified should normally exist, but it is possible
       * that when peering comes up, peer may advertise MACIP routes before
       * advertising type-3 routes.
       */
      zvtep = zvni_vtep_find (zvni, &r_vtep);
      if (!zvtep)
        {
          if (zvni_vtep_add (zvni, &r_vtep) == NULL)
            {
              zlog_err ("Failed to add remote VTEP, VRF %d VNI %u zvni %p",
                        zvrf->vrf_id, vni, zvni);
              continue;
            }

          zvni_vtep_install (zvni, &r_vtep);
        }

      /* First, check if the remote MAC is unknown or has a change. If so,
       * that needs to be updated first. Note that client could install
       * MAC and MACIP separately or just install the latter.
       */
      mac = zvni_mac_lookup (zvni, &macaddr);
      if (!mac || !CHECK_FLAG (mac->flags, ZEBRA_MAC_REMOTE) ||
          !IPV4_ADDR_SAME(&mac->fwd_info.r_vtep_ip, &r_vtep.u.prefix4))
        update_mac = 1;

      if (update_mac)
        {
          if (!mac)
            {
              mac = zvni_mac_add (zvni, &macaddr);
              if (!mac)
                {
                  zlog_warn ("%u:Failed to add MAC %s VNI %u Remote VTEP %s",
                             zvrf->vrf_id, mac2str (&macaddr, buf, sizeof (buf)),
                             vni, inet_ntoa (r_vtep.u.prefix4));
                  return -1;
                }

              /* Is this MAC created for a MACIP? */
              if (ipa_len)
                SET_FLAG (mac->flags, ZEBRA_MAC_AUTO);
            }

          /* Set "auto" and "remote" forwarding info. */
          UNSET_FLAG (mac->flags, ZEBRA_MAC_LOCAL);
          memset (&mac->fwd_info, 0, sizeof (mac->fwd_info));
          SET_FLAG (mac->flags, ZEBRA_MAC_REMOTE);
          mac->fwd_info.r_vtep_ip = r_vtep.u.prefix4;

          /* Install the entry. */
          zvni_mac_install (zvni, mac);
        }

      /* If there is no IP, continue - after clearing AUTO flag of MAC. */
      if (!ipa_len)
        {
          UNSET_FLAG (mac->flags, ZEBRA_MAC_AUTO);
          continue;
        }

      /* Check if the remote neighbor itself is unknown or has a change.
       * If so, create or update and then install the entry.
       */
      n = zvni_neigh_lookup (zvni, &ip);
      if (!n || !CHECK_FLAG (n->flags, ZEBRA_NEIGH_REMOTE) ||
          (memcmp(&n->emac, &macaddr, sizeof (macaddr)) != 0) ||
          !IPV4_ADDR_SAME(&n->r_vtep_ip, &r_vtep.u.prefix4))
        update_neigh = 1;

      if (update_neigh)
        {
          if (!n)
            {
              n = zvni_neigh_add (zvni, &ip);
              if (!n)
                {
                  zlog_warn ("%u:Failed to add Neigh %s MAC %s VNI %u Remote VTEP %s",
                             zvrf->vrf_id, ipaddr2str (&ip, buf1, sizeof (buf1)),
                             mac2str (&macaddr, buf, sizeof (buf)),
                             vni, inet_ntoa (r_vtep.u.prefix4));
                  return -1;
                }

              /* New neighbor referring to this MAC. */
              mac->neigh_refcnt++;
            }
          else if (memcmp(&n->emac, &macaddr, sizeof (macaddr)) != 0)
            {
              /* MAC change, update ref counts for old and new MAC. */
              old_mac = zvni_mac_lookup (zvni, &n->emac);
              if (old_mac && CHECK_FLAG (old_mac->flags, ZEBRA_MAC_LOCAL))
                zvni_deref_ip2mac (zvni, old_mac, 1);
              mac->neigh_refcnt++;
            }

          /* Set "remote" forwarding info. */
          UNSET_FLAG (n->flags, ZEBRA_NEIGH_LOCAL);
          /* TODO: Handle MAC change. */
          memcpy (&n->emac, &macaddr, ETHER_ADDR_LEN);
          n->r_vtep_ip = r_vtep.u.prefix4;
          SET_FLAG (n->flags, ZEBRA_NEIGH_REMOTE);

          /* Install the entry. */
          zvni_neigh_install (zvni, n);
        }
    }

  return 0;
}

/*
 * Handle message from client to delete a remote MACIP for a VNI.
 */
int zebra_vxlan_remote_macip_del (struct zserv *client, int sock,
                                  u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  vni_t vni;
  struct ethaddr macaddr;
  struct ipaddr ip;
  struct prefix r_vtep;
  zebra_vni_t *zvni;
  zebra_mac_t *mac;
  zebra_neigh_t *n;
  u_short l = 0, ipa_len;
  char buf[MACADDR_STRLEN];
  char buf1[INET6_ADDRSTRLEN];

  s = client->ibuf;

  while (l < length)
    {
      /* Obtain each remote MACIP and process. */
      /* Message contains VNI, followed by MAC followed by IP (if any)
       * followed by remote VTEP IP.
       */
      mac = NULL;
      n = NULL;
      memset (&ip, 0, sizeof (ip));
      vni = (vni_t) stream_getl (s);
      stream_get (&macaddr.octet, s, ETHER_ADDR_LEN);
      ipa_len = stream_getl (s);
      if (ipa_len)
        {
          ip.ipa_type = (ipa_len == IPV4_MAX_BYTELEN) ? IPADDR_V4: IPADDR_V6;
          stream_get (&ip.ip.addr, s, ipa_len);
        }
      l += 4 + ETHER_ADDR_LEN + 4 + ipa_len;
      r_vtep.family = AF_INET;
      r_vtep.prefixlen = IPV4_MAX_BITLEN;
      r_vtep.u.prefix4.s_addr = stream_get_ipv4(s);
      l += IPV4_MAX_BYTELEN;

      if (IS_ZEBRA_DEBUG_VXLAN)
        zlog_debug ("%u:Recv MACIP Del MAC %s IP %s VNI %u Remote VTEP %s from %s",
                    zvrf->vrf_id,
                    mac2str (&macaddr, buf, sizeof (buf)),
                    ipaddr2str (&ip, buf1, sizeof (buf1)),
                    vni, inet_ntoa (r_vtep.u.prefix4),
                    zebra_route_string (client->proto));

      /* Locate VNI hash entry - expected to exist. */
      zvni = zvni_lookup (zvrf, vni);
      if (!zvni)
        {
          if (IS_ZEBRA_DEBUG_VXLAN)
            zlog_debug ("Failed to locate VNI hash upon remote MACIP DEL, "
                        "VRF %d VNI %u", zvrf->vrf_id, vni);
          continue;
        }
      if (!zvni->vxlan_if)
        {
          zlog_err ("VNI %u hash %p doesn't have intf upon remote MACIP DEL",
                    vni, zvni);
          continue;
        }

      /* The remote VTEP specified is normally expected to exist, but it is
       * possible that the peer may delete the VTEP before deleting any MACs
       * referring to the VTEP, in which case the handler (see remote_vtep_del)
       * would have already deleted the MACs.
       */
      if (!zvni_vtep_find (zvni, &r_vtep))
        continue;

      /* If the local VxLAN interface is not up (should be a transient
       * event),  there's nothing more to do.
       */
      if (!if_is_operative (zvni->vxlan_if))
        continue;

      /* If the remote mac or neighbor doesn't exist there is nothing more
       * to do. Otherwise, uninstall the entry and then remove it.
       */
      mac = zvni_mac_lookup (zvni, &macaddr);
      if (ipa_len)
        n = zvni_neigh_lookup (zvni, &ip);
      if (!mac && !n)
        continue;

      /* Uninstall remote neighbor or MAC. */
      if (n)
        {
          if (CHECK_FLAG (n->flags, ZEBRA_NEIGH_REMOTE))
            {
              /* TODO: Assumes MAC in message and in entry match. */
              zvni_neigh_uninstall (zvni, n);
              zvni_neigh_del (zvni, n);
              zvni_deref_ip2mac (zvni, mac, 1);
            }
        }
      else
        {
          if (CHECK_FLAG (mac->flags, ZEBRA_MAC_REMOTE))
            {
              if (!mac->neigh_refcnt)
                {
                  zvni_mac_uninstall (zvni, mac);
                  zvni_mac_del (zvni, mac);
                }
              else
                SET_FLAG (mac->flags, ZEBRA_MAC_AUTO);
            }
        }
    }

  return 0;
}

/*
 * Handle local neighbor add (on a VLAN device / L3 interface).
 */
int
zebra_vxlan_local_neigh_add_update (struct interface *ifp,
                                    struct interface *link_if,
                                    struct ipaddr *ip,
                                    struct ethaddr *macaddr,
                                    u_int16_t neigh_state)
{
  zebra_vni_t *zvni;
  zebra_neigh_t *n;
  struct zebra_vrf *zvrf;
  char buf[MACADDR_STRLEN];
  char buf2[INET6_ADDRSTRLEN];
  int add = 1;

  /* We are only interested in neighbors on an interface that links to a
   * bridge and the VLAN maps to a VxLAN.
   */
  zvni = zvni_map_vlanif (ifp, link_if);
  if (!zvni)
    return 0;

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Add/Update neighbor %s MAC %s intf %s(%u) state %d -> VNI %u",
                ifp->vrf_id, ipaddr2str (ip, buf2, sizeof(buf2)),
                mac2str (macaddr, buf, sizeof (buf)),
                ifp->name, ifp->ifindex, neigh_state, zvni->vni);

  /* If same entry already exists, nothing to do. */
  n = zvni_neigh_lookup (zvni, ip);
  if (n)
    {
      if (CHECK_FLAG (n->flags, ZEBRA_NEIGH_REMOTE))
        return 0;

      if (CHECK_FLAG (n->flags, ZEBRA_NEIGH_LOCAL) &&
          (memcmp (n->emac.octet, macaddr->octet, ETHER_ADDR_LEN) == 0) &&
          n->ifindex == ifp->ifindex)
        return 0;
      if (CHECK_FLAG (n->flags, ZEBRA_NEIGH_LOCAL))
        add = 0; /* This is an update of local interface or MAC. */
    }

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
  assert(zvrf);

  if (!n)
    {
      n = zvni_neigh_add (zvni, ip);
      if (!n)
        {
          zlog_err ("%u:Failed to add neighbor %s MAC %s intf %s(%u) -> VNI %u",
                    ifp->vrf_id, ipaddr2str (ip, buf2, sizeof(buf2)),
                    mac2str (macaddr, buf, sizeof (buf)),
                    ifp->name, ifp->ifindex, zvni->vni);
          return -1;
        }
    }

  /* Set "local" forwarding info. */
  UNSET_FLAG (n->flags, ZEBRA_NEIGH_REMOTE);
  n->r_vtep_ip.s_addr = 0;
  SET_FLAG (n->flags, ZEBRA_NEIGH_LOCAL);
  memcpy (&n->emac, macaddr, ETHER_ADDR_LEN);
  n->ifindex = ifp->ifindex;

  /* Inform BGP if required. */
  if (add)
    return zvni_neigh_send_add_to_client (zvrf, zvni->vni, ip, macaddr);

  return 0;
}

/*
 * Handle local neighbor delete (on a VLAN device / L3 interface).
 */
int
zebra_vxlan_local_neigh_del (struct interface *ifp,
                             struct interface *link_if,
                             struct ipaddr *ip)
{
  zebra_vni_t *zvni;
  zebra_neigh_t *n;
  struct zebra_vrf *zvrf;
  char buf[INET6_ADDRSTRLEN];

  /* We are only interested in neighbors on an interface that links to a
   * bridge and the VLAN maps to a VxLAN.
   */
  zvni = zvni_map_vlanif (ifp, link_if);
  if (!zvni)
    return 0;
  if (!zvni->vxlan_if)
    {
      zlog_err ("VNI %u hash %p doesn't have intf upon local neighbor DEL",
                zvni->vni, zvni);
      return -1;
    }

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Del neighbor %s intf %s(%u) -> VNI %u",
                ifp->vrf_id, ipaddr2str (ip, buf, sizeof(buf)),
                ifp->name, ifp->ifindex, zvni->vni);

  /* If entry doesn't exist, nothing to do. */
  n = zvni_neigh_lookup (zvni, ip);
  if (!n)
    return 0;

  /* Is it a local entry? */
  if (!CHECK_FLAG (n->flags, ZEBRA_NEIGH_LOCAL))
    return 0;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(zvni->vxlan_if->vrf_id);
  assert(zvrf);

  /* Remove neighbor from BGP. */
  zvni_neigh_send_del_to_client (zvrf, zvni->vni, &n->ip, &n->emac);

  /* Delete this neighbor entry. */
  zvni_neigh_del (zvni, n);

  return 0;
}

/*
 * Display Neighbors for a VNI (VTY command handler).
 */
void
zebra_vxlan_print_neigh_vni (struct vty *vty, struct zebra_vrf *zvrf, vni_t vni)
{
  zebra_vni_t *zvni;
  u_int32_t num_neigh;
  struct neigh_walk_ctx wctx;

  if (!EVPN_ENABLED(zvrf))
    return;
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      vty_out (vty, "%% VNI %u does not exist%s", vni, VTY_NEWLINE);
      return;
    }
  num_neigh = hashcount(zvni->neigh_table);
  if (!num_neigh)
    return;

  /* Since we have IPv6 addresses to deal with which can vary widely in
   * size, we try to be a bit more elegant in display by first computing
   * the maximum width.
   */
  memset (&wctx, 0, sizeof (struct neigh_walk_ctx));
  wctx.zvni = zvni;
  wctx.vty = vty;
  wctx.addr_width = 15;
  hash_iterate(zvni->neigh_table, zvni_find_neigh_addr_width, &wctx);

  vty_out(vty, "Number of ARPs (local and remote) known for this VNI: %u%s",
          num_neigh, VTY_NEWLINE);
  vty_out(vty, "%*s %-6s %-17s %-21s%s",
          -wctx.addr_width, "IP", "Type", "MAC",
          "Remote VTEP", VTY_NEWLINE);

  hash_iterate(zvni->neigh_table, zvni_print_neigh_hash, &wctx);
}

/*
 * Display neighbors across all VNIs (VTY command handler).
 */
void
zebra_vxlan_print_neigh_all_vni (struct vty *vty, struct zebra_vrf *zvrf)
{
  if (!EVPN_ENABLED(zvrf))
    return;
  hash_iterate(zvrf->vni_table, zvni_print_neigh_hash_all_vni, vty);
}

/*
 * Display specific neighbor for a VNI, if present (VTY command handler).
 */
void
zebra_vxlan_print_specific_neigh_vni (struct vty *vty, struct zebra_vrf *zvrf,
                                      vni_t vni, struct ipaddr *ip)
{
  zebra_vni_t *zvni;
  zebra_neigh_t *n;

  if (!EVPN_ENABLED(zvrf))
    return;
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      vty_out (vty, "%% VNI %u does not exist%s", vni, VTY_NEWLINE);
      return;
    }
  n = zvni_neigh_lookup (zvni, ip);
  if (!n)
    {
      vty_out (vty, "%% Requested neighbor does not exist in VNI %u%s",
               vni, VTY_NEWLINE);
      return;
    }

  zvni_print_neigh (n, vty);
}

/*
 * Display neighbors for a VNI from specific VTEP (VTY command handler).
 * By definition, these are remote neighbors.
 */
void
zebra_vxlan_print_neigh_vni_vtep (struct vty *vty, struct zebra_vrf *zvrf,
                                  vni_t vni, struct in_addr vtep_ip)
{
  zebra_vni_t *zvni;
  u_int32_t num_neigh;
  struct neigh_walk_ctx wctx;

  if (!EVPN_ENABLED(zvrf))
    return;
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      vty_out (vty, "%% VNI %u does not exist%s", vni, VTY_NEWLINE);
      return;
    }
  num_neigh = hashcount(zvni->neigh_table);
  if (!num_neigh)
    return;

  memset (&wctx, 0, sizeof (struct neigh_walk_ctx));
  wctx.zvni = zvni;
  wctx.vty = vty;
  wctx.flags = SHOW_REMOTE_NEIGH_FROM_VTEP;
  wctx.r_vtep_ip = vtep_ip;

  hash_iterate(zvni->neigh_table, zvni_print_neigh_hash, &wctx);
}

/*
 * Display MACs for a VNI (VTY command handler).
 */
void
zebra_vxlan_print_macs_vni (struct vty *vty, struct zebra_vrf *zvrf, vni_t vni)
{
  zebra_vni_t *zvni;
  u_int32_t num_macs;
  struct mac_walk_ctx wctx;

  if (!EVPN_ENABLED(zvrf))
    return;
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      vty_out (vty, "%% VNI %u does not exist%s", vni, VTY_NEWLINE);
      return;
    }
  num_macs = hashcount(zvni->mac_table);
  if (!num_macs)
    return;

  memset (&wctx, 0, sizeof (struct mac_walk_ctx));
  wctx.zvni = zvni;
  wctx.vty = vty;

  vty_out(vty, "Number of MACs (local and remote) known for this VNI: %u%s",
          num_macs, VTY_NEWLINE);
  vty_out(vty, "%-17s %-6s %-21s %-5s%s",
          "MAC", "Type", "Intf/Remote VTEP", "VLAN", VTY_NEWLINE);

  hash_iterate(zvni->mac_table, zvni_print_mac_hash, &wctx);
}

/*
 * Display MACs for all VNIs (VTY command handler).
 */
void
zebra_vxlan_print_macs_all_vni (struct vty *vty, struct zebra_vrf *zvrf)
{
  if (!EVPN_ENABLED(zvrf))
    return;
  hash_iterate(zvrf->vni_table, zvni_print_mac_hash_all_vni, vty);
}

/*
 * Display specific MAC for a VNI, if present (VTY command handler).
 */
void
zebra_vxlan_print_specific_mac_vni (struct vty *vty, struct zebra_vrf *zvrf,
                                    vni_t vni, struct ethaddr *macaddr)
{
  zebra_vni_t *zvni;
  zebra_mac_t *mac;

  if (!EVPN_ENABLED(zvrf))
    return;
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      vty_out (vty, "%% VNI %u does not exist%s", vni, VTY_NEWLINE);
      return;
    }
  mac = zvni_mac_lookup (zvni, macaddr);
  if (!mac)
    {
      vty_out (vty, "%% Requested MAC does not exist in VNI %u%s",
               vni, VTY_NEWLINE);
      return;
    }

  zvni_print_mac (mac, vty);
}

/*
 * Display MACs for a VNI from specific VTEP (VTY command handler).
 */
void
zebra_vxlan_print_macs_vni_vtep (struct vty *vty, struct zebra_vrf *zvrf,
                                 vni_t vni, struct in_addr vtep_ip)
{
  zebra_vni_t *zvni;
  u_int32_t num_macs;
  struct mac_walk_ctx wctx;

  if (!EVPN_ENABLED(zvrf))
    return;
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      vty_out (vty, "%% VNI %u does not exist%s", vni, VTY_NEWLINE);
      return;
    }
  num_macs = hashcount(zvni->mac_table);
  if (!num_macs)
    return;

  memset (&wctx, 0, sizeof (struct mac_walk_ctx));
  wctx.zvni = zvni;
  wctx.vty = vty;
  wctx.flags = SHOW_REMOTE_MAC_FROM_VTEP;
  wctx.r_vtep_ip = vtep_ip;

  hash_iterate(zvni->mac_table, zvni_print_mac_hash, &wctx);
}


/*
 * Display VNI information (VTY command handler).
 */
void
zebra_vxlan_print_vni (struct vty *vty, struct zebra_vrf *zvrf, vni_t vni)
{
  zebra_vni_t *zvni;

  if (!EVPN_ENABLED(zvrf))
    return;
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      vty_out (vty, "%% VNI %u does not exist%s", vni, VTY_NEWLINE);
      return;
    }
  zvni_print (zvni, (void *)vty);
}

/*
 * Display VNI hash table (VTY command handler).
 */
void
zebra_vxlan_print_vnis (struct vty *vty, struct zebra_vrf *zvrf)
{
  u_int32_t num_vnis;

  if (!EVPN_ENABLED(zvrf))
    return;
  num_vnis = hashcount(zvrf->vni_table);
  if (!num_vnis)
    return;
  vty_out(vty, "Number of VNIs: %u%s", num_vnis, VTY_NEWLINE);
  vty_out(vty, "%-10s %-21s %-15s %-8s %-8s %-15s%s",
          "VNI", "VxLAN IF", "VTEP IP", "# MACs", "# ARPs",
          "Remote VTEPs", VTY_NEWLINE);
  hash_iterate(zvrf->vni_table, zvni_print_hash, vty);
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
}

/* Close all VNI handling */
void
zebra_vxlan_close_tables (struct zebra_vrf *zvrf)
{
  hash_iterate (zvrf->vni_table, zvni_cleanup_all, zvrf);
}
