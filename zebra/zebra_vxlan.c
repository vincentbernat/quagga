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
DEFINE_MTYPE_STATIC(ZEBRA, MACIP,     "VNI MACIP");

/* definitions */
typedef struct zebra_vni_t_ zebra_vni_t;
typedef struct zebra_vtep_t_ zebra_vtep_t;

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
 * For each VNI that is locally defined, this table has the pointer to the
 * local interface.
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

  /* List of local/remote MAC/IP */
  struct hash *macip_table;
};

struct macip
{
  struct ethaddr emac;
  struct in_addr  nw_ip;
  u_int32_t       flags;
#define LOCAL_MACIP_FLAG   0x01
#define REMOTE_MACIP_FLAG  0x02

  struct in_addr  remote_vtep_ip;
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
static int
zvni_send_add_to_client (struct zebra_vrf *zvrf, zebra_vni_t *zvni);
static int
zvni_send_del_to_client (struct zebra_vrf *zvrf, vni_t vni);
static void
zvni_propagate_this_vni (struct hash_backet *backet, void *ctxt);
static void
zvni_propagate_vnis (struct zebra_vrf *zvrf);
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
static void
zvni_print (zebra_vni_t *zvni, void *ctxt);
static void
zvni_print_hash (struct hash_backet *backet, void *ctxt);



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
 * macip_keymake
 *
 * Make hash key.
 */
static unsigned int
macip_keymake (void *p)
{
  struct macip *pmac = p;
  char *pnt = (char *) pmac->emac.octet;
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
 * macip_cmp
 *
 * Compare MAC addresses.
 */
static int
macip_cmp (const void *p1, const void *p2)
{
  const struct macip *pmac1 = p1;
  const struct macip *pmac2 = p2;

  if (pmac1 == NULL && pmac2 == NULL)
    return 1;

  if (pmac1 == NULL || pmac2 == NULL)
    return 0;

  return(memcmp(pmac1->emac.octet, pmac2->emac.octet, ETHER_ADDR_LEN) == 0);
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
  zvni->macip_table = hash_create(macip_keymake, macip_cmp);

  return zvni;
}

static void
zebra_evpn_macip_free (zebra_vni_t *zvni, struct macip *pmac)
{
  if (pmac)
    {
      hash_release (zvni->macip_table, pmac);
      XFREE(MTYPE_MACIP, pmac);
    }
  return;
}

static void
zebra_evpn_free_all_macip_iterator (struct hash_backet *backet, 
                                    zebra_vni_t *zvni)
{
  struct macip *pmac;

  pmac = (struct macip *) backet->data;
  zebra_evpn_macip_free(zvni, pmac);
  return;
}

static void
zebra_evpn_macip_cleanup (zebra_vni_t *zvni)
{
  hash_iterate (zvni->macip_table,
                (void (*) (struct hash_backet *, void *))
                zebra_evpn_free_all_macip_iterator,
                zvni);
  hash_free(zvni->macip_table);
  zvni->macip_table = NULL;
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
  zebra_evpn_macip_cleanup (zvni);

  /* Free the VNI hash entry and allocated memory. */
  tmp_zvni = hash_release (zvrf->vni_table, zvni);
  if (tmp_zvni)
    XFREE(MTYPE_ZVNI, tmp_zvni);

  return 0;
}

/*
 * zebra_evpn_new_macip
 *
 * Create a new mac ip entry.
 */
static void 
zebra_evpn_new_macip (zebra_vni_t *zvni, struct ethaddr mac, struct in_addr ip, 
                      struct in_addr remote_vtep_ip, int local)
{
  struct macip *new;

  /*
   * Allocate new import rt node
   */
  new = XCALLOC (MTYPE_MACIP, sizeof (struct macip));

  if (!new)
    return;

  memcpy(&new->emac.octet, &mac.octet, ETHER_ADDR_LEN);
  new->nw_ip = ip;
  new->remote_vtep_ip = remote_vtep_ip;

  if (local)
    SET_FLAG (new->flags, LOCAL_MACIP_FLAG);
  else 
    SET_FLAG (new->flags, REMOTE_MACIP_FLAG);

  /* Add to hash */
  if (!hash_get(zvni->macip_table, new, hash_alloc_intern))
    {
      XFREE(MTYPE_MACIP, new);
      return;
    }
  return;
}

static struct macip *
zebra_evpn_macip_lookup (zebra_vni_t *zvni, struct ethaddr mac)
{
  struct macip *pmac;
  struct macip tmp;

  memset(&tmp, 0, sizeof(struct macip));
  memcpy(&tmp.emac.octet, &mac.octet, ETHER_ADDR_LEN);
  pmac = hash_lookup(zvni->macip_table, &tmp);
  return(pmac);
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
    zlog_debug ("%u:Send VNI_ADD %u %s to BGP",
                zvrf->vrf_id, zvni->vni, inet_ntoa(zvni->local_vtep_ip));

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
    zlog_debug ("%u:Send VNI_DEL %u to BGP", zvrf->vrf_id, vni);

  client->vnidel_cnt++;
  return zebra_server_send_message(client);
}

/*
 * Propagate a VNI to client.
 */
static void
zvni_propagate_this_vni (struct hash_backet *backet, void *ctxt)
{
  zebra_vni_t *zvni;
  struct zebra_vrf *zvrf;

  zvni = (zebra_vni_t *) backet->data;
  zvrf = (struct zebra_vrf *)ctxt;
  zvni_send_add_to_client (zvrf, zvni);
}

/*
 * Propagate all known VNIs to client.
 */
static void
zvni_propagate_vnis (struct zebra_vrf *zvrf)
{
  hash_iterate(zvrf->vni_table, zvni_propagate_this_vni, (void *)zvrf);
}

#define macaddrtostring(mac) mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
#define MAC_STR "%02x:%02x:%02x:%02x:%02x:%02x"

#if 0
/*
 * Inform BGP about local MAC addition.
 */
static int
zvni_send_macip_add_to_client (struct zebra_vrf *zvrf, vni_t vni, 
                               struct ethaddr mac, struct in_addr ip)
{
  struct zserv *client;
  struct stream *s;

  zlog_debug ("%s: Add MAC" MAC_STR " for vni %u, and IP %s\n", __FUNCTION__,
              macaddrtostring(mac.octet),
              vni, inet_ntoa(ip));
  client = zebra_find_client (ZEBRA_ROUTE_BGP);
  /* BGP may not be running. */
  if (!client)
    return 0;

  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, ZEBRA_MACIP_ADD, zvrf->vrf_id);
  stream_putl (s, vni);
  stream_put_in_addr (s, &ip);
  stream_put (s, mac.octet, ETHER_ADDR_LEN); /* Mac Addr */

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Send MACIP_ADD %u %s to BGP", zvrf->vrf_id, vni,
                                               inet_ntoa(ip));

  client->macipadd_cnt++;
  return zebra_server_send_message(client);
}

/*
 * Inform BGP about local MAC deletion.
 */
static int
zvni_send_macip_del_to_client (struct zebra_vrf *zvrf, vni_t vni,
                               struct ethaddr mac, struct in_addr ip)
{
  struct zserv *client;
  struct stream *s;

  client = zebra_find_client (ZEBRA_ROUTE_BGP);
  /* BGP may not be running. */
  if (!client)
    return 0;

  s = client->obuf;
  stream_reset (s);

  zserv_create_header (s, ZEBRA_MACIP_DEL, zvrf->vrf_id);
  stream_putl (s, vni);
  stream_put_in_addr (s, &ip);
  stream_put (s, mac.octet, 6); /* Mac Addr */

  /* Write packet size. */
  stream_putw_at (s, 0, stream_get_endp (s));

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Send MACIP_DEL %u to BGP", zvrf->vrf_id, vni);

  client->vnidel_cnt++;
  return zebra_server_send_message(client);
}
#endif

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

static void
zvni_print_macip (struct macip *pmac, void *ctxt)
{
  struct vty *vty;
  char buf1[20];
  char buf2[20];

  vty = (struct vty *) ctxt;
  int local = CHECK_FLAG(pmac->flags, LOCAL_MACIP_FLAG);
  strcpy(buf1, inet_ntoa(pmac->nw_ip));
  strcpy(buf2, inet_ntoa(pmac->remote_vtep_ip));

  vty_out(vty, " " MAC_STR " %s %s   %s%s", macaddrtostring(pmac->emac.octet),
                                            buf1, buf2, 
                                            (local)? "LOCAL" : "REMOTE", 
                                            VTY_NEWLINE);
}

static void
zvni_print_macip_hash (struct hash_backet *backet, void *ctxt)
{
  struct macip *pmac;

  pmac = (struct macip *) backet->data;
  if (!pmac)
    return;

  zvni_print_macip (pmac, ctxt);
}

/*
 * Print an VNI entry.
 */
static void
zvni_print (zebra_vni_t *zvni, void *ctxt)
{
  struct vty *vty;
  zebra_vtep_t *zvtep;
  char buf[PREFIX_STRLEN];

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
  vty_out(vty, " MACs for this VNI:%s", VTY_NEWLINE);
  vty_out(vty, " MAC               IP      RemoteVTEP  Flag%s", VTY_NEWLINE);
  hash_iterate(zvni->macip_table, zvni_print_macip_hash, vty);
}

#if 0
/*
 * stringtomacaddr
 *
 * Function to convert string to mac address
 */
static void
stringtomacaddr (const char *mac_str, unsigned char *mac_addr)
{
    unsigned int mac[6];
    int ret;

    ret = sscanf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
                 &mac[0], &mac[1], &mac[2], &mac[3], &mac[4],
                 &mac[5]);
    if (!ret) {
        printf("Failed to copy mac_str into mac\n");
        return;
    }
    mac_addr[0] = mac[0]; mac_addr[1] = mac[1]; mac_addr[2] = mac[2];
    mac_addr[3] = mac[3]; mac_addr[4] = mac[4]; mac_addr[5] = mac[5];
    return;
}
#endif

/* Cleanup VNI/VTEP and update kernel */
static void
zvni_cleanup_all (struct hash_backet *backet, void *zvrf)
{
  zebra_vni_t *zvni;

  zvni = (zebra_vni_t *) backet->data;
  if (!zvni)
    return;

  /* Free up all remote VTEPs, if any. */
  zvni_vtep_del_all (zvni, 1);

  /* Delete the hash entry. */
  zvni_del (zvrf, zvni);
}

/*
 * Print a VNI hash entry.
 */
static void
zvni_print_hash (struct hash_backet *backet, void *ctxt)
{
  zebra_vni_t *zvni;

  zvni = (zebra_vni_t *) backet->data;
  if (!zvni)
    return;

  zvni_print (zvni, ctxt);
}



/* Public functions */

/*
 * Handle VxLAN interface up - update BGP if required.
 */
int
zebra_vxlan_if_up (struct interface *ifp)
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

  /* Inform BGP if required. */
  if (!zvrf->advertise_vni)
    return 0;

  zvni_send_add_to_client (zvrf, zvni);
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

  /* Inform BGP if required. */
  if (zvrf->advertise_vni)
    zvni_send_del_to_client (zvrf, zvni->vni);

  /* Free up all remote VTEPs, if any. */
  zvni_vtep_del_all (zvni, 1);

  return 0;
}

/*
 * Handle VxLAN interface add or update. Create/update VxLAN L2
 * interface info.  Store the VNI (in hash table) and update BGP,
 * if required.
 */
int
zebra_vxlan_if_add_update (struct interface *ifp,
                           struct zebra_l2if_vxlan *zl2if)
{
  struct zebra_if *zif;
  struct zebra_vrf *zvrf;
  struct zebra_l2if_vxlan *_zl2if;
  zebra_vni_t *zvni;
  vni_t vni;

  zif = ifp->info;
  assert(zif);

  vni = zl2if->vni;

  /* Locate VRF corresponding to interface. */
  zvrf = vrf_info_lookup(ifp->vrf_id);
  assert(zvrf);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Add/Update intf %s(%u) VNI %u local IP %s",
                ifp->vrf_id, ifp->name, ifp->ifindex, vni,
                inet_ntoa (zl2if->vtep_ip));

  /* Allocate/update L2 interface */
  if (!zif->l2if)
    {
      zif->l2if = XCALLOC (MTYPE_ZEBRA_L2IF,
                           sizeof (struct zebra_l2if_vxlan));
      if (!zif->l2if)
        {
          zlog_err ("Failed to alloc VxLAN L2IF VRF %d IF %s(%u)",
                    ifp->vrf_id, ifp->name, ifp->ifindex);
          return -1;
        }
    }
  _zl2if = (struct zebra_l2if_vxlan *)zif->l2if;
  *_zl2if = *zl2if;

  /* If hash entry exists and no change to VTEP IP, we're done. */
  zvni = zvni_lookup (zvrf, vni);
  if (zvni && IPV4_ADDR_SAME(&zvni->local_vtep_ip, &zl2if->vtep_ip))
    return 0;

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

  /* Done if interface is not up. */
  if (!if_is_operative (ifp))
    return 0;

  /* Inform BGP if required. */
  if (!zvrf->advertise_vni)
    return 0;

  zvni_send_add_to_client (zvrf, zvni);
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
        zlog_debug ("%u:Recv VTEP_ADD %s VNI %u",
                    zvrf->vrf_id, prefix2str (&vtep, pbuf, sizeof(pbuf)), vni);

      /* Locate VNI hash entry - expected to exist. */
      zvni = zvni_lookup (zvrf, vni);
      if (!zvni)
        {
          zlog_err ("Failed to locate VNI hash upon remote VTEP add, VRF %d VNI %u",
                    zvrf->vrf_id, vni);
          continue;
        }
      if (!zvni->vxlan_if)
        {
          zlog_err ("VNI %u hash %p doesn't have intf upon remote VTEP add",
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
        zlog_debug ("%u:Recv VTEP_DEL %s VNI %u",
                    zvrf->vrf_id, prefix2str (&vtep, pbuf, sizeof(pbuf)), vni);

      /* Locate VNI hash entry - expected to exist. */
      zvni = zvni_lookup (zvrf, vni);
      if (!zvni)
        {
          zlog_err ("Failed to locate VNI hash upon remote VTEP add, VRF %d VNI %u",
                    zvrf->vrf_id, vni);
          continue;
        }

      /* If the remote VTEP does not exist, there's nothing more to do.
       * Otherwise, uninstall the entry and remove it.
       */
      zvtep = zvni_vtep_find (zvni, &vtep);
      if (!zvtep)
        continue;

      zvni_vtep_uninstall (zvni, &vtep);
      zvni_vtep_del (zvni, zvtep);
    }

  return 0;
}

/*
 * Handle message from client to learn (or stop learning) about VNIs.
 * Note: This setting is similar to 'redistribute <proto>' and only
 * controls VNI propagation from zebra to client (bgpd). When enabled,
 * any existing VNIs need to be informed to the client; when disabled,
 * it is sufficient to note the state, the client is expected to do
 * its own internal cleanup.
 */
int zebra_vxlan_advertise_vni (struct zserv *client, int sock,
                               u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  int advertise;

  s = client->ibuf;
  advertise = stream_getc (s);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Recv ADVERTISE_VNI %s",
                zvrf->vrf_id, advertise ? "enable" : "disable");

  if (zvrf->advertise_vni != advertise)
    {
      zvrf->advertise_vni = advertise;
      if (zvrf->advertise_vni)
        zvni_propagate_vnis (zvrf);
    }

  return 0;
}

/*
 * Handle message from client to add a remote MAC/IP for a VNI.
 */
int 
zebra_vxlan_remote_macip_add (struct zserv *client, int sock,
                              u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  vni_t vni;
  struct in_addr ip, remote_vtep_ip;
  zebra_vni_t *zvni;
  struct ethaddr mac;
  struct macip *pmac;

  s = client->ibuf;

  /* Obtain each remote VTEP and process. */
  vni = (vni_t) stream_getl (s);
  stream_getc (s); // flags, currently unused
  ip.s_addr = stream_get_ipv4 (s);
  stream_get (&mac.octet, s, ETHER_ADDR_LEN);
  remote_vtep_ip.s_addr = stream_get_ipv4 (s);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Recv VTEP_ADD %s VNI %u " MAC_STR " %s\n",
                zvrf->vrf_id, inet_ntoa (ip), vni,
                macaddrtostring(mac.octet), inet_ntoa(remote_vtep_ip));

  /* Locate VNI hash entry - expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to locate VNI hash upon remote VTEP add, VRF %d VNI %u",
                zvrf->vrf_id, vni);
      return 0;
    }
  if (!zvni->vxlan_if)
    {
      zlog_err ("VNI %u hash %p doesn't have intf upon remote VTEP add",
                zvni->vni, zvni);
      return 0;
    }

  if (!if_is_operative (zvni->vxlan_if))
    return 0;

  /* If the remote MAC/IP already exists, or the local VxLAN interface is
   * not up (should be a transient event),  there's nothing more to do.
   * Otherwise, add and install the entry.
   */
  pmac = zebra_evpn_macip_lookup (zvni, mac);
  if (!pmac)
    zebra_evpn_new_macip (zvni, mac, ip, remote_vtep_ip, FALSE);

  return 0;
}

/*
 * Handle message from client to delete a remote MAC/IP for a VNI.
 */
int zebra_vxlan_remote_macip_del (struct zserv *client, int sock,
                                 u_short length, struct zebra_vrf *zvrf)
{
  struct stream *s;
  vni_t vni;
  struct in_addr ip;
  zebra_vni_t *zvni;
  struct ethaddr mac;
  struct macip *pmac;

  s = client->ibuf;

  /* Obtain each remote VTEP and process. */
  vni = (vni_t) stream_getl (s);
  stream_getc (s); // flags, currently unused
  ip.s_addr = stream_get_ipv4 (s);
  stream_get (&mac.octet, s, ETHER_ADDR_LEN);

  if (IS_ZEBRA_DEBUG_VXLAN)
    zlog_debug ("%u:Recv VTEP_DEL %s VNI %u " MAC_STR " ",
                zvrf->vrf_id, inet_ntoa (ip), vni,
                macaddrtostring(mac.octet));

  /* Locate VNI hash entry - expected to exist. */
  zvni = zvni_lookup (zvrf, vni);
  if (!zvni)
    {
      zlog_err ("Failed to locate VNI hash upon remote VTEP add, VRF %d VNI %u",
                zvrf->vrf_id, vni);
      return 0;
    }

  /* If the remote MAC/IP does not exist, there's nothing more to do.
   * Otherwise, uninstall the entry and remove it.
   */
  pmac = zebra_evpn_macip_lookup (zvni, mac);
  if (pmac)
    zebra_evpn_macip_free (zvni, pmac);

  return 0;
}

/*
 * Display VNI information (VTY command handler).
 */
void
zebra_vxlan_print_vni (struct vty *vty, struct zebra_vrf *zvrf, vni_t vni)
{
  zebra_vni_t *zvni;

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
