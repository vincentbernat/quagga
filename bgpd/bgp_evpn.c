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
#include "zclient.h"
#include "vxlan.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_zebra.h"
#include "linklist.h"
#include "jhash.h"

#define EVPN_TYPE_2_ROUTE_PREFIXLEN      192
#define EVPN_TYPE_3_ROUTE_PREFIXLEN      192



struct import_rt_node
{
  struct ecommunity_val import_rt;
  struct bgpevpn *vpn;
};

struct evpn_config_write
{
  int write;
  struct vty *vty;
};

struct macip
{
  struct ethaddr emac;
  struct in_addr nw_ip;
};

extern struct zclient *zclient;

DEFINE_QOBJ_TYPE(bgpevpn)

static int
bgp_evpn_uninstall_type3_route (struct bgp *bgp, afi_t afi, safi_t safi,
                              struct prefix_evpn *evp, struct bgp_info *ri);
static int
bgp_evpn_delete_type2_route (struct bgp *bgp, struct bgpevpn *vpn, struct ethaddr mac,
                             struct in_addr ip);

static int
bgp_evpn_uninstall_existing_type3_routes (struct bgp *bgp, struct bgpevpn *vpn,
                                          struct ecommunity_val val);
static int
bgp_evpn_uninstall_existing_type2_routes (struct bgp *bgp, struct bgpevpn *vpn,
                                          struct ecommunity_val val);

/*
 * Private functions.
 */

/*
 * Build EVPN type-2 prefix (for route node)
 */
static inline void
build_evpn_type2_prefix (struct prefix_evpn *p, struct ethaddr mac,
                         struct in_addr ip, vni_t vni)
{
  memset (p, 0, sizeof (struct prefix_evpn));
  p->family = AF_ETHERNET;
  p->prefixlen = EVPN_TYPE_2_ROUTE_PREFIXLEN;
  p->prefix.route_type = BGP_EVPN_MAC_IP_ROUTE;
  memcpy(&p->prefix.mac.octet, &mac.octet, ETHER_ADDR_LEN);
  SET_FLAG (p->prefix.flags, IP_ADDR_V4);
  p->prefix.ip.v4_addr = ip;
  p->prefix.vni = vni;
}

/*
 * Build EVPN type-3 prefix (for route node)
 */
static inline void
build_evpn_type3_prefix (struct prefix_evpn *p, struct in_addr originator_ip)
{
  memset (p, 0, sizeof (struct prefix_evpn));
  p->family = AF_ETHERNET;
  p->prefixlen = EVPN_TYPE_3_ROUTE_PREFIXLEN;
  p->prefix.route_type = BGP_EVPN_IMET_ROUTE;
  SET_FLAG (p->prefix.flags, IP_ADDR_V4);
  p->prefix.ip.v4_addr = originator_ip;
}

/*
 * vni_hash_key_make
 *
 * Make vni hash key.
 */
static unsigned int
vni_hash_key_make(void *p)
{
  struct bgpevpn *vpn = p;
  return (jhash_1word(vpn->vni, 0));
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
 * import_rt_hash_key_make
 *
 * Make import route target hash key.
 */
static unsigned int
import_rt_hash_key_make (void *p)
{
  struct import_rt_node *irt = p;
  char *pnt = irt->import_rt.val;
  unsigned int key = 0;
  int c=0;

  key += pnt[c];
  key += pnt[c + 1];
  key += pnt[c + 2];
  key += pnt[c + 3];
  key += pnt[c + 4];
  key += pnt[c + 5];
  key += pnt[c + 6];
  key += pnt[c + 7];

  return (key);
}

/*
 * import_rt_hash_cmp
 *
 * Comparison function for import rt hash
 */
static int
import_rt_hash_cmp (const void *p1, const void *p2)
{
  const struct import_rt_node *irt1 = p1;
  const struct import_rt_node *irt2 = p2;

  if (irt1 == NULL && irt2 == NULL)
    return 1;

  if (irt1 == NULL || irt2 == NULL)
    return 0;

  return(memcmp(irt1->import_rt.val, irt2->import_rt.val, ECOMMUNITY_SIZE) == 0);
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
 * bgp_evpn_get_auto_rt
 *
 * Set auto rt values.
 */
static void
bgp_evpn_get_auto_rt (struct bgp *bgp, struct bgpevpn *vpn,
                      struct ecommunity_val *import_rt)
{
  u_char rt_type;
  struct in_addr ip = { .s_addr = INADDR_ANY };

  if (bgp->as > BGP_AS_MAX)
    rt_type = ECOMMUNITY_ENCODE_AS4;
  else
    rt_type = ECOMMUNITY_ENCODE_AS;
  ecommunity_encode (rt_type, ECOMMUNITY_ROUTE_TARGET, 1, bgp->as,
                     ip, vpn->vni, import_rt);
  return;
}

/*
 * bgp_evpn_import_rt_new
 *
 * Create a new import_rt
 */
static struct import_rt_node *
bgp_evpn_import_rt_new (struct bgp *bgp, struct bgpevpn *vpn,
                        struct ecommunity_val import_rt)
{
  struct import_rt_node *irt;

  if (!bgp)
    return NULL;

  /*
   * Allocate new import rt node
   */
  irt = XCALLOC (MTYPE_BGP_EVPN_IMPORT_RT, sizeof (struct import_rt_node));

  if (!irt)
    return NULL;

  irt->vpn = vpn;
  irt->import_rt = import_rt;

  /* Add to hash */
  if (!hash_get(bgp->import_rt_hash, irt, hash_alloc_intern))
    {
      XFREE(MTYPE_BGP_EVPN_IMPORT_RT, irt);
      return NULL;
    }

  /* Add to VPN import rt list */
  listnode_add (vpn->import_rtl, irt);

  return(irt);
}

/*
 * bgp_evpn_import_rt_free
 *
 * Free the import rt node
 */
static void
bgp_evpn_import_rt_free (struct bgp *bgp, struct import_rt_node *irt)
{
  struct bgpevpn *vpn;

  if (irt)
    {
      vpn = irt->vpn;
      listnode_delete(vpn->import_rtl, irt);
      hash_release(bgp->import_rt_hash, irt);
      XFREE(MTYPE_BGP_EVPN_IMPORT_RT, irt);
    }
  return;
}

/*
 * bgp_evpn_lookup_import_rt
 *
 * Function to lookup vpn for the given vni
 */
static struct import_rt_node *
bgp_evpn_lookup_import_rt (struct bgp *bgp, u_char *import_rt)
{
  struct import_rt_node *irt;
  struct import_rt_node tmp;

  memset(&tmp, 0, sizeof(struct import_rt_node));
  memcpy(tmp.import_rt.val, import_rt, ECOMMUNITY_SIZE);
  irt = hash_lookup(bgp->import_rt_hash, &tmp);
  return(irt);
}

/*
 * bgp_evpn_set_auto_rt_import_flag
 *
 * Set RT_IMPORT_AUTO flag.
 */
static void
bgp_evpn_set_auto_rt_import_flag (struct bgpevpn *vpn)
{
  SET_FLAG (vpn->flags, RT_IMPORT_AUTO);
}

/*
 * bgp_evpn_set_auto_rt_export_flag
 *
 * Set RT_EXPORT_AUTO flag.
 */
static void
bgp_evpn_set_auto_rt_export_flag (struct bgpevpn *vpn)
{
  SET_FLAG (vpn->flags, RT_EXPORT_AUTO);
}

/*
 * bgp_evpn_set_auto_rt_import
 *
 * RT = AS:VNI
 */
static void
bgp_evpn_set_auto_rt_import (struct bgp *bgp, struct bgpevpn *vpn)
{
  struct ecommunity_val import_rt;

  bgp_evpn_get_auto_rt (bgp, vpn, &import_rt);
  bgp_evpn_set_auto_rt_import_flag(vpn);

  /* Add import rt to the bgp->import_rt_hash and vpn->import_rtl*/
  if (!bgp_evpn_import_rt_new (bgp, vpn, import_rt))
    zlog_err ("%s: Failed to create a new import_rt node\n", __FUNCTION__);
  return;
}

/*
 * bgp_evpn_set_auto_rt_export
 *
 * RT = AS:VNI
 */
static void
bgp_evpn_set_auto_rt_export (struct bgp *bgp, struct bgpevpn *vpn)
{
  bgp_evpn_get_auto_rt (bgp, vpn, &vpn->export_rt);
  bgp_evpn_set_auto_rt_export_flag(vpn);
}

/*
 * bgp_evpn_set_auto_rd_flag
 *
 * Set RD_AUTO flag.
 */
static void
bgp_evpn_set_auto_rd_flag (struct bgpevpn *vpn)
{
  SET_FLAG (vpn->flags, RD_AUTO);
}

/*
 * bgp_evpn_unset_auto_rd_flag
 *
 * UNSet RD_AUTO flag.
 */
static void
bgp_evpn_unset_auto_rd_flag (struct bgpevpn *vpn)
{
  UNSET_FLAG (vpn->flags, RD_AUTO);
}

/*
 * bgp_evpn_check_auto_rt_import_flag
 *
 * Check RT_IMPORT_AUTO flag.
 */
static int
bgp_evpn_check_auto_rt_import_flag (struct bgpevpn *vpn)
{
  return (CHECK_FLAG (vpn->flags, RT_IMPORT_AUTO));
}

/*
 * bgp_evpn_unset_auto_rt_import_flag
 *
 * UNSet RT_IMPORT_AUTO flag.
 */
static void
bgp_evpn_unset_auto_rt_import_flag (struct bgpevpn *vpn)
{
  UNSET_FLAG (vpn->flags, RT_IMPORT_AUTO);
}

/*
 * bgp_evpn_check_auto_rt_export_flag
 *
 * Check RT_EXPORT_AUTO flag.
 */
static int
bgp_evpn_check_auto_rt_export_flag (struct bgpevpn *vpn)
{
  return (CHECK_FLAG (vpn->flags, RT_EXPORT_AUTO));
}

/*
 * bgp_evpn_unset_auto_rt_export_flag
 *
 * UNSet RT_EXPORT_AUTO flag.
 */
static void
bgp_evpn_unset_auto_rt_export_flag (struct bgpevpn *vpn)
{
  UNSET_FLAG (vpn->flags, RT_EXPORT_AUTO);
}

/*
 * bgp_evpn_set_auto_rd
 *
 * RD = Router Id:VNI
 */
static void
bgp_evpn_set_auto_rd (struct bgp *bgp, struct bgpevpn *vpn)
{
  char buf[100];

  vpn->prd.family = AF_UNSPEC;
  vpn->prd.prefixlen = 64;
  sprintf (buf, "%s:%u", inet_ntoa (bgp->router_id), vpn->vni);
  str2prefix_rd (buf, &vpn->prd);
  bgp_evpn_set_auto_rd_flag(vpn);
}

/*
 * bgp_evpn_derive_rd_rt
 *
 * Function to derive RD and RT from the VNI.
 * RD = Router Id:VNI
 * RT = AS:VNI
 * TODO: Cannot handle VNI larger than UINT16_MAX
 */
static void
bgp_evpn_derive_rd_rt (struct bgp *bgp, struct bgpevpn *vpn)
{
  bgp_evpn_set_auto_rd(bgp, vpn);
  bgp_evpn_set_auto_rt_import(bgp, vpn);
  bgp_evpn_set_auto_rt_export(bgp, vpn);
}

/*
 * bgp_evpn_new
 *
 * Create a new vpn
 */
static struct bgpevpn *
bgp_evpn_new (struct bgp *bgp, vni_t vni, struct in_addr originator_ip)
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

  /* Set values - RD and RT set to defaults. */
  vpn->vni = vni;
  vpn->originator_ip = originator_ip;

  /* Create import rt list */
  vpn->import_rtl = list_new();

  bgp_evpn_derive_rd_rt (bgp, vpn);

  vpn->macip_table = hash_create(macip_keymake, macip_cmp);

  /* Add to hash */
  if (!hash_get(bgp->vnihash, vpn, hash_alloc_intern))
    {
      XFREE(MTYPE_BGP_EVPN, vpn);
      return NULL;
    }
  QOBJ_REG (vpn, bgpevpn);
  return(vpn);
}

static int
bgp_evpn_check_config_rt_with_route_rt (struct attr *attr, struct ecommunity_val val)
{
  struct attr_extra *attre = attr->extra;

  assert (attre);
  assert (attre->ecommunity);
  assert (attre->ecommunity->val);
  return(!memcmp(attre->ecommunity->val, &val, ECOMMUNITY_SIZE));
}

/*
 * bgp_evpn_uninstall_existing_type3_routes
 *
 * Uninstall any existing type-3 routes (remote VTEPs) that match the RT.
 */
static int
bgp_evpn_uninstall_existing_type3_routes (struct bgp *bgp, struct bgpevpn *vpn,
                                          struct ecommunity_val val)
{
  afi_t afi;
  safi_t safi;
  struct bgp_node *rd_rn, *rn;
  struct bgp_table *table;
  struct bgp_info *ri;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;

  /* TODO: We're walking entire table, this should be optimized later. */
  /* EVPN routes are a 2-level table. */
  for (rd_rn = bgp_table_top(bgp->rib[afi][safi]); rd_rn; rd_rn = bgp_route_next (rd_rn))
    {
      table = (struct bgp_table *)(rd_rn->info);
      if (table)
        {
          for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
            {
              struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

              if (evp->prefix.route_type != BGP_EVPN_IMET_ROUTE)
                continue;

              for (ri = rn->info; ri; ri = ri->next)
                if (bgp_evpn_check_config_rt_with_route_rt (ri->attr, val))
                  bgp_evpn_uninstall_type3_route (bgp, afi, safi, evp, ri);
            }
        }
    }

  return 0;
}

/*
 * bgp_evpn_new_macip
 *
 * Create a new mac ip entry.
 */
static int
bgp_evpn_new_macip (struct bgpevpn *vpn, struct ethaddr mac, struct in_addr ip)
{
  struct macip *new;

  /*
   * Allocate new import rt node
   */
  new = XCALLOC (MTYPE_BGP_EVPN_MACIP, sizeof (struct macip));

  if (!new)
    return 0;

  memcpy(&new->emac.octet, &mac.octet, ETHER_ADDR_LEN);
  new->nw_ip = ip;

  /* Add to hash */
  if (!hash_get(vpn->macip_table, new, hash_alloc_intern))
    {
      XFREE(MTYPE_BGP_EVPN_MACIP, new);
      return 0;
    }
  return 1;
}

static struct macip *
bgp_evpn_macip_lookup (struct bgpevpn *vpn, struct ethaddr mac)
{
  struct macip *pmac;
  struct macip tmp;

  memset(&tmp, 0, sizeof(struct macip));
  memcpy(&tmp.emac.octet, &mac.octet, ETHER_ADDR_LEN);
  pmac = hash_lookup(vpn->macip_table, &tmp);
  return(pmac);
}

static void
bgp_evpn_macip_update (struct bgp *bgp, struct bgpevpn *vpn, struct ethaddr mac,
                       struct in_addr ip)
{
  struct macip *pmac;

  pmac = bgp_evpn_macip_lookup (vpn, mac);
  if (!pmac) 
    {
      if (!bgp_evpn_new_macip (vpn, mac, ip))
        {
          zlog_err("Couldnt create macip entry\n");
          return;
        }
    }
  else
    {
      if (!IPV4_ADDR_SAME (&pmac->nw_ip, &ip))
        {
          /* If VNI was already local, withdraw route from peer */
          if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
            {
              /* Remove EVPN type-2 route and schedule for processing. */
              bgp_evpn_delete_type2_route (bgp, vpn, mac, ip);
            }
          pmac->nw_ip = ip;
        }
    }
  return;
}

static void
bgp_evpn_macip_free (struct bgpevpn *vpn, struct macip *pmac)
{
  if (pmac)
    {
      hash_release (vpn->macip_table, pmac);
      XFREE(MTYPE_BGP_EVPN_MACIP, pmac);
    }
  return;
}

static void
bgp_evpn_free_all_macip_iterator (struct hash_backet *backet, 
                                  struct bgpevpn *vpn)
{
  struct macip *pmac;

  pmac = (struct macip *) backet->data;
  bgp_evpn_macip_free(vpn, pmac);
  return;
}

static void
bgp_evpn_macip_cleanup (struct bgpevpn *vpn)
{
  hash_iterate (vpn->macip_table,
                (void (*) (struct hash_backet *, void *))
                bgp_evpn_free_all_macip_iterator,
                vpn);
  hash_free(vpn->macip_table);
  vpn->macip_table = NULL;
}

/*
 * bgp_evpn_uninstall_existing_evpn_routes
 *
 * Uninstall type2/type3 evpn routes from zebra.
 */
static void
bgp_evpn_uninstall_existing_evpn_routes (struct bgp *bgp, struct bgpevpn *vpn,
                                          struct ecommunity_val val)
{
  bgp_evpn_uninstall_existing_type3_routes (bgp, vpn, val);
  bgp_evpn_uninstall_existing_type2_routes (bgp, vpn, val);
}

/*
 * bgp_evpn_cleanup_config_rt_import
 *
 * Cleanup all the user/admin configured import RT.
 */
static void
bgp_evpn_cleanup_config_rt_import (struct bgp *bgp, struct bgpevpn *vpn)
{
  struct listnode *node, *nnode;
  struct import_rt_node *irt;

  for (ALL_LIST_ELEMENTS (vpn->import_rtl, node, nnode, irt))
    {
      /*
       * If there are existing routes that match this RT,
       * delete them from Zebra.
       */
      if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
        bgp_evpn_uninstall_existing_type3_routes (bgp, vpn, irt->import_rt);
      bgp_evpn_import_rt_free (bgp, irt);
    }
  return;
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
    bgp_evpn_macip_cleanup (vpn);
    vpn->macip_table = NULL;
    bgp_evpn_cleanup_config_rt_import (bgp, vpn);
    list_free(vpn->import_rtl);
    hash_release(bgp->vnihash, vpn);
    QOBJ_UNREG (vpn);
    XFREE(MTYPE_BGP_EVPN, vpn);
  }
}

/*
 * bgp_evpn_lookup_vpn
 *
 * Function to lookup vpn for the given vni
 */
static struct bgpevpn *
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

#if 0
static void
bgp_evpn_print_rt (u_char *import_rt)
{
  struct rd_as rd_as;
  struct rd_ip rd_ip;
  u_char *pnt;
  int encode = 0;

  pnt = (u_char *) import_rt;

  /* High-order octet of type. */
  encode = *pnt++;

  switch (encode)
    {
      case ECOMMUNITY_ENCODE_AS:
        decode_rd_as (import_rt+2, &rd_as);
        zlog_debug ("RT: %u:%d\n", rd_as.as, rd_as.val);
        break;
      case ECOMMUNITY_ENCODE_IP:
        decode_rd_ip (import_rt+2, &rd_ip);
        zlog_debug ("RT: %s:%d\n", inet_ntoa(rd_ip.ip), rd_ip.val);
        break;
      case ECOMMUNITY_ENCODE_AS4:
        decode_rd_as4 (import_rt+2, &rd_as);
        zlog_debug ("RT: %u:%d\n", rd_as.as, rd_as.val);
        break;
      default:
        break;
    }
}
#endif

static int
bgp_evpn_update_type2_route (struct bgp *bgp, struct bgpevpn *vpn,
                             struct ethaddr mac, struct in_addr ip)
{
  struct prefix_evpn p;
  struct bgp_node *rn;
  struct attr attr;
  struct bgp_info *ri;
  struct attr *attr_new;
  afi_t afi = AFI_L2VPN;
  safi_t safi = SAFI_EVPN;

  memset (&attr, 0, sizeof (struct attr));

  /* Build prefix and create route node. EVPN routes have a 2-level
   * tree (RD-level + Prefix-level) similar to L3VPN routes.
   */
  build_evpn_type2_prefix (&p, mac, ip, vpn->vni);
  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi,
                         (struct prefix *)&p, &vpn->prd);

  /* Build path-attribute for this route. */
  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);
  /* Set up RT extended community. */
  /* TODO: Only 1 RT supported now. */
  (bgp_attr_extra_get (&attr))->ecommunity =
    ecommunity_parse ((u_int8_t *)&vpn->export_rt.val, ECOMMUNITY_SIZE);
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);

  /* Add to hash. */
  attr_new = bgp_attr_intern (&attr);

  /* See if this is an update of an existing route, or a new add. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
        && ri->type == ZEBRA_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* If this is an existing route and when export_rt is changed,
     send an update message. Else create a new route */
  if (!ri)
    {
      /* Create new route. */
      ri = info_make (ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
                      bgp->peer_self, attr_new, rn);
      SET_FLAG (ri->flags, BGP_INFO_VALID);
      bgp_info_add (rn, ri);
    }
  bgp_unlock_node (rn);

  /* Schedule for processing. */
  bgp_process (bgp, rn, afi, safi);

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);

  return 0;
}

static int
bgp_evpn_update_type3_route (struct bgp *bgp, struct bgpevpn *vpn)
{
  struct prefix_evpn p;
  struct bgp_node *rn;
  struct attr attr;
  struct bgp_info *ri;
  struct attr *attr_new;
  afi_t afi = AFI_L2VPN;
  safi_t safi = SAFI_EVPN;

  memset (&attr, 0, sizeof (struct attr));

  /* Build prefix and create route node. EVPN routes have a 2-level
   * tree (RD-level + Prefix-level) similar to L3VPN routes.
   */
  build_evpn_type3_prefix (&p, vpn->originator_ip);
  rn = bgp_afi_node_get (bgp->rib[afi][safi], afi, safi,
                         (struct prefix *)&p, &vpn->prd);

  /* Build path-attribute for this route. */
  bgp_attr_default_set (&attr, BGP_ORIGIN_IGP);
  /* Set up RT extended community. */
  /* TODO: Only 1 RT supported now. */
  (bgp_attr_extra_get (&attr))->ecommunity =
    ecommunity_parse ((u_int8_t *)&vpn->export_rt.val, ECOMMUNITY_SIZE);
  attr.flag |= ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES);

  /* Add to hash. */
  attr_new = bgp_attr_intern (&attr);

  /* See if this is an update of an existing route, or a new add. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
        && ri->type == ZEBRA_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  /* If this is an existing route and when export_rt is changed,
     send an update message. Else create a new route */
  if (!ri)
    {
      /* Create new route. */
      ri = info_make (ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0,
                      bgp->peer_self, attr_new, rn);
      SET_FLAG (ri->flags, BGP_INFO_VALID);
      bgp_info_add (rn, ri);
    }
  else
    {
      struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

      if (evp->prefix.route_type == BGP_EVPN_IMET_ROUTE)
        {
          if (memcmp (&p, evp, sizeof(struct prefix_evpn)) == 0)
            for (ri = rn->info; ri; ri = ri->next)
              {
                ri->attr->extra->ecommunity =
                ecommunity_parse ((u_int8_t *)&vpn->export_rt.val, ECOMMUNITY_SIZE);
                ri->attr->extra->ecommunity->str = ecommunity_str(ri->attr->extra->ecommunity);

                /* The attribute is changed. */
                bgp_info_set_flag (rn, ri, BGP_INFO_ATTR_CHANGED);
              }
        }
    }
  bgp_unlock_node (rn);

  /* Schedule for processing. */
  bgp_process (bgp, rn, afi, safi);

  /* Unintern original. */
  aspath_unintern (&attr.aspath);
  bgp_attr_extra_free (&attr);

  return 0;
}

static int
bgp_evpn_delete_type3_route (struct bgp *bgp, struct bgpevpn *vpn)
{
  struct prefix_evpn p;
  struct bgp_node *rn;
  struct bgp_info *ri;
  afi_t afi = AFI_L2VPN;
  safi_t safi = SAFI_EVPN;

  /* Build prefix and locate route node. */
  build_evpn_type3_prefix (&p, vpn->originator_ip);
  rn = bgp_afi_node_lookup (bgp->rib[afi][safi], afi, safi,
                         (struct prefix *)&p, &vpn->prd);

  if (!rn)
    {
      /* TODO: Temporary, can ignore entry not found at delete. */
      zlog_err ("Could not find type-3 route for VNI %u at Del", vpn->vni);
      return -1;
    }

  /* Now, find matching route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
	&& ri->type == ZEBRA_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  if (!ri)
    {
      /* TODO: Temporary, can ignore entry not found at delete. */
      zlog_err ("Could not find type-3 route info for VNI %u at Del, RN %p",
                vpn->vni, rn);
      bgp_unlock_node (rn);
      return -1;
    }

  /* Mark route for delete and schedule for processing. */
  bgp_info_delete (rn, ri);
  bgp_process (bgp, rn, afi, safi);

  return 0;
}

static int
bgp_evpn_process_type2_route (struct peer *peer, afi_t afi, safi_t safi,
                              struct attr *attr, u_char *pfx, int psize,
                              u_int32_t addpath_id)
{
  struct prefix_rd prd;
  struct prefix_evpn p;
  u_char ipaddr_len;
  u_char macaddr_len;
  vni_t vni;
  int ret;

  /* Type-2 route should be either 33 or 52 bytes: 
   * RD (8), ESI (10), Eth Tag (4), MAC Addr Len (1),
   * MAC Addr (6), IP len (1), IP (0, 4 or 16),
   * MPLS Lbl1 (3), MPLS Lbl2 (0 or 3).
   */
  if (psize != 33 && psize != 37 && psize != 49 && psize != 52)
    {
      zlog_err ("%u:%s - Rx EVPN NLRI with invalid length %d",
                peer->bgp->vrf_id, peer->host, psize);
      return -1;
    }

  /* Make prefix_rd */
  prd.family = AF_UNSPEC;
  prd.prefixlen = 64;
  memcpy (&prd.val, pfx, 8);
  pfx += 8;

  /* Make EVPN prefix. */
  memset (&p, 0, sizeof (struct prefix_evpn));
  p.family = AF_ETHERNET;
  p.prefixlen = EVPN_TYPE_2_ROUTE_PREFIXLEN;
  p.prefix.route_type = BGP_EVPN_MAC_IP_ROUTE;

  /* Skip over Ethernet Seg Identifier for now. */
  pfx += 10;

  /* Skip over Ethernet Tag for now. */
  pfx += 4;

  /* Get the MAC Addr len */
  macaddr_len = *pfx++;

  /* Get the MAC Addr */
  memcpy (&p.prefix.mac.octet, pfx, macaddr_len);
  pfx += macaddr_len;

  /* Get the IP. */
  ipaddr_len = *pfx++;
  if (ipaddr_len == 4)
    p.prefix.flags = IP_ADDR_V4;
  else
    p.prefix.flags = IP_ADDR_V6;
  memcpy (&p.prefix.ip, pfx, ipaddr_len);
  pfx += ipaddr_len;

  /* Get the VNI */
  vni = *pfx;
  zlog_debug ("%s: Got %d\n", __FUNCTION__, vni);

  /* Process the route. */
  if (attr)
    ret = bgp_update (peer, (struct prefix *)&p, addpath_id, attr, afi, safi,
                      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0);
  else
    ret = bgp_withdraw (peer, (struct prefix *)&p, addpath_id, attr, afi, safi,
                        ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL);
  return ret;
}

static int
bgp_evpn_process_type3_route (struct peer *peer, afi_t afi, safi_t safi,
                              struct attr *attr, u_char *pfx, int psize,
                              u_int32_t addpath_id)
{
  struct prefix_rd prd;
  struct prefix_evpn p;
  u_char ipaddr_len;
  int ret;

  /* Type-3 route should be either 17 or 29 bytes: RD (8), Eth Tag (4),
   * IP len (1) and IP (4 or 16).
   */
  if (psize != 17 && psize != 29)
    {
      zlog_err ("%u:%s - Rx EVPN NLRI with invalid length %d",
                peer->bgp->vrf_id, peer->host, psize);
      return -1;
    }

  /* Make prefix_rd */
  prd.family = AF_UNSPEC;
  prd.prefixlen = 64;
  memcpy (&prd.val, pfx, 8);
  pfx += 8;

  /* Make EVPN prefix. */
  memset (&p, 0, sizeof (struct prefix_evpn));
  p.family = AF_ETHERNET;
  p.prefixlen = EVPN_TYPE_3_ROUTE_PREFIXLEN;
  p.prefix.route_type = BGP_EVPN_IMET_ROUTE;

  /* Skip over Ethernet Tag for now. */
  pfx += 4;

  /* Get the IP. */
  ipaddr_len = *pfx++;
  if (ipaddr_len == 4)
    p.prefix.flags = IP_ADDR_V4;
  else
    p.prefix.flags = IP_ADDR_V6;
  memcpy (&p.prefix.ip, pfx, ipaddr_len);

  /* Process the route. */
  if (attr)
    ret = bgp_update (peer, (struct prefix *)&p, addpath_id, attr, afi, safi,
                      ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0);
  else
    ret = bgp_withdraw (peer, (struct prefix *)&p, addpath_id, attr, afi, safi,
                        ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL);
  return ret;
}

static int
bgp_zebra_send_remote_mac (struct bgp *bgp, struct bgpevpn *vpn,
                           struct prefix_evpn *p, struct in_addr remote_vtep_ip,
                           int add)
{
  struct stream *s;

  /* Check socket. */
  if (!zclient || zclient->sock < 0)
    return 0;

  /* Don't try to register if Zebra doesn't know of this instance. */
  if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp))
    return 0;

  s = zclient->obuf;
  stream_reset (s);

  zclient_create_header (s, add ? ZEBRA_REMOTE_MACIP_ADD : ZEBRA_REMOTE_MACIP_DEL,
                         bgp->vrf_id);
  stream_putl(s, vpn->vni);
  stream_putc(s, 0); // flags - unused
  /*if (p->prefix.flags & IP_ADDR_V4)
    {
      stream_putw(s, AF_INET);
      stream_putc(s, IPV4_MAX_BITLEN);
      stream_put_in_addr(s, &p->prefix.ip.v4_addr);
    }
  else if (p->prefix.flags & IP_ADDR_V6)
    {
      stream_putw(s, AF_INET6);
      stream_putc(s, IPV6_MAX_BITLEN);
      stream_put(s, &p->prefix.ip.v6_addr, IPV6_MAX_BYTELEN);
    }*/
  stream_put_in_addr(s, &p->prefix.ip.v4_addr);
  stream_put (s, &p->prefix.mac.octet, ETHER_ADDR_LEN); /* Mac Addr */
  stream_put_in_addr(s, &remote_vtep_ip);

  stream_putw_at (s, 0, stream_get_endp (s));

  return zclient_send_message(zclient);
}

static int
bgp_evpn_extract_vni_from_rt (struct attr *attr, vni_t *vni)
{
  struct attr_extra *attre = attr->extra;
  u_char *pnt;
  u_char rt_type;
  vni_t route_vni = 0;

  assert (attre);
  assert (attre->ecommunity);
  assert (attre->ecommunity->val);
  pnt = attre->ecommunity->val;
  rt_type = *pnt;
  if (rt_type == ECOMMUNITY_ENCODE_AS)
    {
      u_char *c = pnt + 4;
      u_int32_t val;

      val = ((u_int32_t) *c++ << 24);
      val |= ((u_int32_t) *c++ << 16);
      val |= ((u_int32_t) *c++ << 8);
      val |= (u_int32_t) *c;
      if (val > UINT16_MAX)
        {
          zlog_err ("Received RT value %u too large", val);
          return -1;
        }
      route_vni = (vni_t) val;
    }
  else if (rt_type == ECOMMUNITY_ENCODE_IP
           || rt_type == ECOMMUNITY_ENCODE_AS4)
    {
      u_char *c = pnt + 6;
      u_int16_t val;

      val = ((u_int16_t) *c++ << 8);
      val |= (u_int16_t) *c;

      route_vni = (vni_t) val;
    }

  *vni = route_vni;
  return 0;
}

static int
bgp_zebra_send_remote_vtep (struct bgp *bgp, struct bgpevpn *vpn,
                            struct prefix_evpn *p, int add)
{
  struct stream *s;

  /* Check socket. */
  if (!zclient || zclient->sock < 0)
    return 0;

  /* Don't try to register if Zebra doesn't know of this instance. */
  if (!IS_BGP_INST_KNOWN_TO_ZEBRA(bgp))
    return 0;

  s = zclient->obuf;
  stream_reset (s);

  zclient_create_header (s, add ? ZEBRA_REMOTE_VTEP_ADD : ZEBRA_REMOTE_VTEP_DEL,
                         bgp->vrf_id);
  stream_putl(s, vpn->vni);
  stream_putc(s, 0); // flags - unused
  if (p->prefix.flags & IP_ADDR_V4)
    {
      stream_putw(s, AF_INET);
      stream_putc(s, IPV4_MAX_BITLEN);
      stream_put_in_addr(s, &p->prefix.ip.v4_addr);
    }
  else if (p->prefix.flags & IP_ADDR_V6)
    {
      stream_putw(s, AF_INET6);
      stream_putc(s, IPV6_MAX_BITLEN);
      stream_put(s, &p->prefix.ip.v6_addr, IPV6_MAX_BYTELEN);
    }

  stream_putw_at (s, 0, stream_get_endp (s));

  return zclient_send_message(zclient);
}

static struct in_addr
bgp_evpn_get_route_remote_vtep (struct bgp_node *rn)
{
  struct in_addr ip;
  
  ip.s_addr = 0;

  for (rn = bgp_table_top (rn->prn->info); rn; rn = bgp_route_next (rn))
    { 
      struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;
              
      if (evp->prefix.route_type != BGP_EVPN_IMET_ROUTE)
          continue;
      return(evp->prefix.ip.v4_addr);
    }
  return ip;
}

/*
 * Install type-2 route into zebra (as remote MAC). If VNI is non-zero,
 * install only routes matching this VNI.
 */
static int
bgp_evpn_install_type2_route (struct bgp *bgp, afi_t afi, safi_t safi,
                              struct prefix_evpn *evp, struct bgp_info *ri,
                              vni_t vni)
{
  struct attr *attr = ri->attr;
  vni_t route_vni;
  struct bgpevpn *vpn;
  struct in_addr remote_vtep_ip;

  assert (attr);

  /* If we don't have Route Target, nothing much to do. */
  if (!(attr->flag & ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES)))
    return 0;

  /*
   * Make sure this RT matches the import RT.
   */
  if ((bgp->as == ri->peer->as) && 
      !bgp_evpn_lookup_import_rt (bgp, attr->extra->ecommunity->val))
    {
      zlog_err ("%u: route RT doesnt match import RT", bgp->vrf_id);
      return -1;
    }

  /* Extract VNI from RT */
  if (bgp_evpn_extract_vni_from_rt (attr, &route_vni))
    {
      zlog_err ("%u: Failed to extract VNI from route in type-2 route",
                bgp->vrf_id);
      return -1;
    }

  /* If a VNI is specified to match on, it means it is already known locally
   * and we want to install only matching routes.
   */
  if (vni && vni == route_vni)
    {
      vpn = bgp_evpn_lookup_vpn (bgp, vni);
      assert (vpn);
      remote_vtep_ip = bgp_evpn_get_route_remote_vtep (ri->net);
      if (!remote_vtep_ip.s_addr) return -1;
      return bgp_zebra_send_remote_mac (bgp, vpn, evp, remote_vtep_ip, 1);
    }

  /* We are dealing with a received type-2 route. Inform zebra if this
   * is a "live" VNI - i.e., known locally.
   */
  vpn = bgp_evpn_lookup_vpn (bgp, route_vni);
  if (vpn && CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
    {
      remote_vtep_ip = bgp_evpn_get_route_remote_vtep (ri->net);
      if (!remote_vtep_ip.s_addr) return -1;
      return bgp_zebra_send_remote_mac (bgp, vpn, evp, remote_vtep_ip, 1);
    }

  return 0;
}

/*
 * Install type-3 route into zebra (as remote VTEP). If VNI is non-zero,
 * install only routes matching this VNI.
 */
static int
bgp_evpn_install_type3_route (struct bgp *bgp, afi_t afi, safi_t safi,
                              struct prefix_evpn *evp, struct bgp_info *ri,
                              vni_t vni)
{
  struct attr *attr = ri->attr;
  vni_t route_vni;
  struct bgpevpn *vpn;

  assert (attr);
  /* If we don't have Route Target, nothing much to do. */
  if (!(attr->flag & ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES)))
    return 0;

  /*
   * Make sure this RT matches the import RT.
   */
  if ((bgp->as == ri->peer->as) && !bgp_evpn_lookup_import_rt (bgp, attr->extra->ecommunity->val))
    {
      zlog_err ("%u: route RT doesnt match import RT", bgp->vrf_id);
      return -1;
    }

  /* Extract VNI from RT */
  if (bgp_evpn_extract_vni_from_rt (attr, &route_vni))
    {
      zlog_err ("%u: Failed to extract VNI from RT in type-3 route",
                bgp->vrf_id);
      return -1;
    }

  /* If a VNI is specified to match on, it means it is already known locally
   * and we want to install only matching routes.
   */
  if (vni && vni == route_vni)
    {
      vpn = bgp_evpn_lookup_vpn (bgp, vni);
      assert (vpn);
      return bgp_zebra_send_remote_vtep (bgp, vpn, evp, 1);
    }

  /* We are dealing with a received type-3 route. Inform zebra if this
   * is a "live" VNI - i.e., known locally.
   */
  vpn = bgp_evpn_lookup_vpn (bgp, route_vni);
  if (vpn && CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
    return bgp_zebra_send_remote_vtep (bgp, vpn, evp, 1);

  return 0;
}

/*
 * VNI is known locally, install any existing type-2 routes (remote MAC/IPs)
 * for this VNI.
 */
static int
bgp_evpn_install_existing_type2_routes (struct bgp *bgp, struct bgpevpn *vpn)
{
  vni_t vni;
  afi_t afi;
  safi_t safi;
  struct bgp_node *rd_rn, *rn;
  struct bgp_table *table;
  struct bgp_info *ri;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;
  vni = vpn->vni;

  /* TODO: We're walking entire table, this should be optimized later. */
  /* EVPN routes are a 2-level table. */
  for (rd_rn = bgp_table_top(bgp->rib[afi][safi]); rd_rn; rd_rn = bgp_route_next (rd_rn))
    {
      table = (struct bgp_table *)(rd_rn->info);
      if (table)
        {
          for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
            {
              struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

              if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
                continue;

              for (ri = rn->info; ri; ri = ri->next)
                {
                   if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
                       && ri->type == ZEBRA_ROUTE_BGP
                       && ri->sub_type == BGP_ROUTE_NORMAL)
                     bgp_evpn_install_type2_route (bgp, afi, safi,
                                                   evp, ri, vni);
                }
            }
        }
    }

  return 0;
}

/*
 * Uninstall type-2 route from zebra.
 */
static int
bgp_evpn_uninstall_type2_route (struct bgp *bgp, afi_t afi, safi_t safi,
                              struct prefix_evpn *evp, struct bgp_info *ri)
{
  struct attr *attr = ri->attr;
  vni_t route_vni;
  struct bgpevpn *vpn;
  struct in_addr remote_vtep_ip;

  assert (attr);
  /* If we don't have Route Target, nothing much to do. */
  if (!(attr->flag & ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES)))
    return 0;

  /* Extract VNI from RT */
  if (bgp_evpn_extract_vni_from_rt (attr, &route_vni))
    {
      zlog_err ("%u: Failed to extract VNI from RT in type-3 route",
                bgp->vrf_id);
      return -1;
    }

  /* If this is already a "live" VNI, remove remote VTEP from zebra. */
  vpn = bgp_evpn_lookup_vpn (bgp, route_vni);
  if (vpn && CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
    return bgp_zebra_send_remote_mac (bgp, vpn, evp, remote_vtep_ip, 0);

  return 0;
}

/*
 * Uninstall type-3 route from zebra.
 */
static int
bgp_evpn_uninstall_type3_route (struct bgp *bgp, afi_t afi, safi_t safi,
                              struct prefix_evpn *evp, struct bgp_info *ri)
{
  struct attr *attr = ri->attr;
  vni_t route_vni;
  struct bgpevpn *vpn;

  assert (attr);
  /* If we don't have Route Target, nothing much to do. */
  if (!(attr->flag & ATTR_FLAG_BIT (BGP_ATTR_EXT_COMMUNITIES)))
    return 0;

  /* Extract VNI from RT */
  if (bgp_evpn_extract_vni_from_rt (attr, &route_vni))
    {
      zlog_err ("%u: Failed to extract VNI from RT in type-3 route",
                bgp->vrf_id);
      return -1;
    }

  /* If this is already a "live" VNI, remove remote VTEP from zebra. */
  vpn = bgp_evpn_lookup_vpn (bgp, route_vni);
  if (vpn && CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
    return bgp_zebra_send_remote_vtep (bgp, vpn, evp, 0);

  return 0;
}

/*
 * VNI is known locally, install any existing type-3 routes (remote VTEPs)
 * for this VNI.
 */
static int
bgp_evpn_install_existing_type3_routes (struct bgp *bgp, struct bgpevpn *vpn)
{
  vni_t vni;
  afi_t afi;
  safi_t safi;
  struct bgp_node *rd_rn, *rn;
  struct bgp_table *table;
  struct bgp_info *ri;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;
  vni = vpn->vni;

  /* TODO: We're walking entire table, this should be optimized later. */
  /* EVPN routes are a 2-level table. */
  for (rd_rn = bgp_table_top(bgp->rib[afi][safi]); rd_rn; rd_rn = bgp_route_next (rd_rn))
    {
      table = (struct bgp_table *)(rd_rn->info);
      if (table)
        {
          for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
            {
              struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

              if (evp->prefix.route_type != BGP_EVPN_IMET_ROUTE)
                continue;

              for (ri = rn->info; ri; ri = ri->next)
                {
                   if (CHECK_FLAG (ri->flags, BGP_INFO_SELECTED)
                       && ri->type == ZEBRA_ROUTE_BGP
                       && ri->sub_type == BGP_ROUTE_NORMAL)
                     bgp_evpn_install_type3_route (bgp, afi, safi,
                                                   evp, ri, vni);
                }
            }
        }
    }

  return 0;
}

/*
 * bgp_evpn_uninstall_existing_type2_routes
 *
 * Uninstall any existing type-2 routes (remote MAC/IPs) that match the RT.
 */
static int
bgp_evpn_uninstall_existing_type2_routes (struct bgp *bgp, struct bgpevpn *vpn,
                                          struct ecommunity_val val)
{
  afi_t afi;
  safi_t safi;
  struct bgp_node *rd_rn, *rn;
  struct bgp_table *table;
  struct bgp_info *ri;

  afi = AFI_L2VPN;
  safi = SAFI_EVPN;

  /* TODO: We're walking entire table, this should be optimized later. */
  /* EVPN routes are a 2-level table. */
  for (rd_rn = bgp_table_top(bgp->rib[afi][safi]); rd_rn; rd_rn = bgp_route_next (rd_rn))
    {
      table = (struct bgp_table *)(rd_rn->info);
      if (table)
        {
          for (rn = bgp_table_top (table); rn; rn = bgp_route_next (rn))
            {
              struct prefix_evpn *evp = (struct prefix_evpn *)&rn->p;

              if (evp->prefix.route_type != BGP_EVPN_MAC_IP_ROUTE)
                continue;

              for (ri = rn->info; ri; ri = ri->next)
                if (bgp_evpn_check_config_rt_with_route_rt (ri->attr, val))
                  bgp_evpn_uninstall_type2_route (bgp, afi, safi, evp, ri);
            }
        }
    }

  return 0;
}

/*
 * bgp_evpn_update_vni_config_flag
 *
 * If VNI_FLAG_CONFIGURED was set (say admin just configured vni x)
 * and none of the import/export were configured and VNI_FLAG_LOCAL
 * is set (means learnt from zebra) then clear the VNI_FLAG_CONFIGURED.
 * If the (non-default) RD/RT is configured then set the VNI_FLAG_CONFIGURED
 * if not already set.
 */
static void
bgp_evpn_update_vni_config_flag (struct bgpevpn *vpn)
{
  if (!vpn)
    return;

  if (bgp_evpn_check_auto_rd_flag (vpn) &&
      bgp_evpn_check_auto_rt_import_flag (vpn) &&
      bgp_evpn_check_auto_rt_export_flag (vpn) &&
      CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
    UNSET_FLAG (vpn->flags, VNI_FLAG_CONFIGURED);
  else 
    SET_FLAG (vpn->flags, VNI_FLAG_CONFIGURED);
  return;
}

/*
 * bgp_evpn_update_import_rt
 *
 * Function to handle configured import route targets.
 */
static void
bgp_evpn_update_import_rt (struct bgp *bgp, struct bgpevpn *vpn,
                           struct ecommunity_val import_rt_conf,
                           int add, int auto_rt)
{
  struct import_rt_node *irt = NULL;
  struct ecommunity_val import_rt;

  if (!auto_rt)
    irt = bgp_evpn_lookup_import_rt(bgp, (u_char *)import_rt_conf.val);
  if (add)
    {
      if (!irt)
        {
          if (auto_rt)
            {
              if (!bgp_evpn_check_auto_rt_import_flag (vpn))
                {
                  bgp_evpn_cleanup_config_rt_import (bgp, vpn);
                  bgp_evpn_set_auto_rt_import (bgp, vpn);

                  if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
                    {
                      /*
                       * If there are existing routes that match this RT and
                       * were not pushed to Zebra, do it now.
                       */
                      bgp_evpn_install_existing_type3_routes (bgp, vpn);
                    }
                }
              return;
            }

          if (!bgp_evpn_import_rt_new (bgp, vpn, import_rt_conf))
            {
              zlog_err ("%s: Failed to create a new import_rt node\n", __FUNCTION__);
              return;
            }

          if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
            {
              /*
               * If there are existing routes that match this RT and 
               * were not pushed to Zebra, do it now. 
               */
              bgp_evpn_install_existing_type3_routes (bgp, vpn);
            }

          /*
           * If auto RT is set, remove it now.
           */
          if (bgp_evpn_check_auto_rt_import_flag (vpn))
            {
              bgp_evpn_get_auto_rt (bgp, vpn, &import_rt);

              if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
                {
                  /*
                   * If there are existing routes that match this RT,
                   * delete them from Zebra.
                   */
                  bgp_evpn_uninstall_existing_evpn_routes (bgp, vpn, import_rt);
                }
              irt = bgp_evpn_lookup_import_rt(bgp, (u_char *)import_rt.val);
              bgp_evpn_import_rt_free (bgp, irt);
            }
        }

      /*
       * If configured value is auto RT value then just clear the flag.
       */
      if (!auto_rt && bgp_evpn_check_auto_rt_import_flag(vpn))
        bgp_evpn_unset_auto_rt_import_flag(vpn);
    }
  else
    {
      if (irt)
        {
          if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
            {
              /*
               * If there are existing routes that match this RT,
               * delete them from Zebra.
               */
              bgp_evpn_uninstall_existing_evpn_routes (bgp, vpn, irt->import_rt);
            }
          bgp_evpn_import_rt_free (bgp, irt);

          /*
           * If there are no more import rt nodes, add the default auto rt.
           */
          if (!listnode_head(vpn->import_rtl))
            {
              bgp_evpn_set_auto_rt_import (bgp, vpn);

              if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
                {
                  /*
                   * If there are existing routes that match this RT and
                   * were not pushed to Zebra, do it now.
                   */
                  bgp_evpn_install_existing_type3_routes (bgp, vpn);
                }
            }
        }
    }
}

/*
 * bgp_evpn_update_export_rt
 *
 * Function to handle configured export rt updates.
 */
static void
bgp_evpn_update_export_rt (struct bgp *bgp, struct bgpevpn *vpn,
                           struct ecommunity_val rt_conf, int add, int auto_rt)
{
  int export_rt_changed = FALSE;

  /* Update local VNI cache */
  if (add)
    {
      if (auto_rt)
        {
          if (!bgp_evpn_check_auto_rt_export_flag(vpn))
            {
              bgp_evpn_set_auto_rt_export (bgp, vpn);

              if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
                {
                  /* Export RT changed, this needs to be informed to the peers */
                  bgp_evpn_update_type3_route (bgp, vpn);
                }
            }
          return;
        }
      memcpy (vpn->export_rt.val, rt_conf.val, ECOMMUNITY_SIZE);
      bgp_evpn_unset_auto_rt_export_flag (vpn);
      export_rt_changed = TRUE;
    }
  else
    {
      bgp_evpn_set_auto_rt_export (bgp, vpn);
      export_rt_changed = TRUE;
    }

 /* Update local route and inform peer */
  if (export_rt_changed && CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
    {
      /* Export RT changed, this needs to be informed to the peers */
      bgp_evpn_update_type3_route (bgp, vpn);
    }
}

/*
 * bgp_evpn_display_rt
 *
 * Display rt information.
 */
static void
bgp_evpn_display_rt (struct vty *vty, struct ecommunity_val rt,
                     vni_t vni, int rt_hash, int config_write,
                     int config_import_rt)
{
  struct rd_as rd_as;
  struct rd_ip rd_ip;
  u_char *pnt;
  int encode = 0;

  pnt = (u_char *)rt.val;

  /* High-order octet of type. */
  encode = *pnt++;

  switch (encode)
    {
      case ECOMMUNITY_ENCODE_AS:
        decode_rd_as ((u_char *)rt.val+2, &rd_as);
        if (rt_hash)
          {
            vty_out (vty, "%u:%d          %d%s", rd_as.as, rd_as.val, vni,
                                                 VTY_NEWLINE);
          }
        else if (config_write)
          {
            vty_out (vty, "   route-target %s %u:%d%s",
                          (config_import_rt)? "import":"export",
                          rd_as.as, rd_as.val, VTY_NEWLINE);
          }
        else
          {
            vty_out (vty, "     %u:%d%s", rd_as.as, rd_as.val, VTY_NEWLINE);
          }
        break;
      case ECOMMUNITY_ENCODE_IP:
        decode_rd_ip ((u_char *)rt.val+2, &rd_ip);
        if (rt_hash)
          {
            vty_out (vty, "%s:%d          %d%s", inet_ntoa(rd_ip.ip), rd_ip.val,
                                                 vni, VTY_NEWLINE);
          }
        else if (config_write)
          {
            vty_out (vty, "   route-target %s %s:%d%s",
                          (config_import_rt)? "import":"export",
                          inet_ntoa (rd_ip.ip), rd_ip.val, VTY_NEWLINE);
          }
        else
          {
            vty_out (vty, "     %s:%d%s", inet_ntoa(rd_ip.ip), rd_ip.val,
                                          VTY_NEWLINE);
          }
        break;
      case ECOMMUNITY_ENCODE_AS4:
        decode_rd_as4 ((u_char *)rt.val+2, &rd_as);
        if (rt_hash)
          {
            vty_out (vty, "%u:%d          %d%s", rd_as.as, rd_as.val, vni,
                                                 VTY_NEWLINE);
          }
        else if (config_write)
          {
            vty_out (vty, "   route-target %s %s:%d%s",
                          (config_import_rt)? "import":"export",
                          inet_ntoa(rd_ip.ip), rd_as.val, VTY_NEWLINE);
          }
        else
          {
            vty_out (vty, "     %u:%d%s", rd_as.as, rd_as.val, VTY_NEWLINE);
          }
        break;
      default:
        break;
    }
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

/*
 * bgp_evpn_config_write_vpn
 *
 * Write bgp evpn config in 'show running-config'
 */
static void
bgp_evpn_config_write_vpn (struct vty *vty, struct bgpevpn *vpn, int *write)
{
  char buf1[INET6_ADDRSTRLEN];
  struct listnode *node, *nnode;
  struct import_rt_node *irt;
  afi_t afi = AFI_L2VPN;
  safi_t safi = SAFI_EVPN;

  if (CHECK_FLAG (vpn->flags, VNI_FLAG_CONFIGURED) ||
      !bgp_evpn_check_auto_rd_flag (vpn) ||
      !bgp_evpn_check_auto_rt_import_flag (vpn) ||
      !bgp_evpn_check_auto_rt_export_flag (vpn))
    {
      bgp_config_write_family_header (vty, afi, safi, write);
      vty_out (vty, "  vni %d%s", vpn->vni, VTY_NEWLINE);
      if (!bgp_evpn_check_auto_rd_flag (vpn))
          vty_out (vty, "   rd %s%s",
                        prefix_rd2str (&vpn->prd, buf1, RD_ADDRSTRLEN),
                        VTY_NEWLINE);
      if (!bgp_evpn_check_auto_rt_import_flag (vpn))
        for (ALL_LIST_ELEMENTS (vpn->import_rtl, node, nnode, irt))
          bgp_evpn_display_rt (vty, irt->import_rt, vpn->vni, FALSE, TRUE, TRUE);
      if (!bgp_evpn_check_auto_rt_export_flag (vpn))
        bgp_evpn_display_rt (vty, vpn->export_rt, vpn->vni, FALSE, TRUE, FALSE);
      vty_out (vty, "  exit-vni%s", VTY_NEWLINE);
    }
}

static void
bgp_config_write_vxlan_info (struct hash_backet *backet, struct evpn_config_write *cfg)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  bgp_evpn_config_write_vpn (cfg->vty, vpn, &cfg->write);
}

/*
 * Public functions.
 */

/*
 * bgp_evpn_update_vni
 *
 * Create vpn for the given vni if not already created.
 */
struct bgpevpn *
bgp_evpn_update_vni (struct bgp *bgp, vni_t vni, int add)
{
  struct bgpevpn *vpn;

  if (!bgp->vnihash)
    return (NULL);

  vpn = bgp_evpn_lookup_vpn(bgp, vni);
  if (add)
    {
      if (!vpn)
        {
          vpn = bgp_evpn_new(bgp, vni, bgp->router_id);
          SET_FLAG (vpn->flags, VNI_FLAG_CONFIGURED);
        }
    }
  else
    {
      if (CHECK_FLAG (vpn->flags, VNI_FLAG_CONFIGURED))
        {
          bgp_evpn_free(bgp, vpn);
          return (NULL);
        }
      UNSET_FLAG (vpn->flags, VNI_FLAG_CONFIGURED);
    }
  return (vpn);
}

/*
 * Handle add of a local VNI.
 * TODO: Cannot handle VNI larger than UINT16_MAX
 */
int
bgp_evpn_local_vni_add (struct bgp *bgp, vni_t vni, struct in_addr originator_ip)
{
  struct bgpevpn *vpn;

  if (!bgp->vnihash)
    {
      zlog_err ("%u: VNI hash not created", bgp->vrf_id);
      return -1;
    }

  if (vni > UINT16_MAX)
    {
      zlog_err ("%u: VNI %u too large, cannot be handled by EVPN",
                bgp->vrf_id, vni);
      return -1;
    }

  /* Add VNI hash (or update, if already present (e.g., configured) */
  vpn = bgp_evpn_lookup_vpn (bgp, vni);
  if (!vpn)
    {
      vpn = bgp_evpn_new (bgp, vni, originator_ip);
      if (!vpn)
        {
          zlog_err ("%u: Failed to allocate VNI entry for VNI %u",
                    bgp->vrf_id, vni);
          return -1;
        }
    }
  else
    {
      if (!IPV4_ADDR_SAME (&vpn->originator_ip, &originator_ip))
        {
          /* If VNI was already local, withdraw route from peer */
          if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
            {
              /* Remove EVPN type-3 route and schedule for processing. */
              bgp_evpn_delete_type3_route (bgp, vpn);
            }
          vpn->originator_ip = originator_ip;
        }
    }

  /* Mark as locally "learnt" */
  SET_FLAG (vpn->flags, VNI_FLAG_LOCAL);

  bgp_evpn_update_vni_config_flag (vpn);

  /* Create EVPN type-3 route and schedule for processing. */
  if (bgp_evpn_update_type3_route (bgp, vpn))
    {
      zlog_err ("%u: Type3 route creation failure for VNI %u",
                bgp->vrf_id, vni);
      return -1;
    }

  /* If we have already learnt remote VTEPs for this VNI, install them. */
  bgp_evpn_install_existing_type3_routes (bgp, vpn);

  return 0;
}

/*
 * Handle add of a local MAC.
 */
int
bgp_evpn_local_macip_add (struct bgp *bgp, vni_t vni, struct in_addr ip,
                          struct ethaddr mac)
{
  struct bgpevpn *vpn;
  struct in_addr originator_ip;

  if (!bgp->vnihash)
    {
      zlog_err ("%u: VNI hash not created", bgp->vrf_id);
      return -1;
    }

  if (vni > UINT16_MAX)
    {
      zlog_err ("%u: VNI %u too large, cannot be handled by EVPN",
                bgp->vrf_id, vni);
      return -1;
    }

  /* Add VNI hash (or update, if already present (e.g., configured) */
  vpn = bgp_evpn_lookup_vpn (bgp, vni);
  if (!vpn)
    {
      vpn = bgp_evpn_new (bgp, vni, originator_ip);
      if (!vpn)
        {
          zlog_err ("%u: Failed to allocate VNI entry for VNI %u",
                    bgp->vrf_id, vni);
          return -1;
        }
    }
  bgp_evpn_macip_update (bgp, vpn, mac, ip);

  /* Mark as locally "learnt" */
  SET_FLAG (vpn->flags, MAC_FLAG_LOCAL);

  /* Create EVPN type-2 route and schedule for processing. */
  if (bgp_evpn_update_type2_route (bgp, vpn, mac, ip))
    {
      zlog_err ("%u: Type2 route creation failure for MAC" MAC_STR "\n",
                bgp->vrf_id, macaddrtostring(mac.octet));
      return -1;
    }

  /* If we have already learnt remote VTEPs for this VNI, install them. */
  bgp_evpn_install_existing_type2_routes (bgp, vpn);

  return 0;
}

static void
bgp_evpn_update_router_id_vni (struct hash_backet *backet, struct bgp *bgp)
{
  struct bgpevpn *vpn;

  vpn = (struct bgpevpn *) backet->data;

  if (!vpn)
    {
      zlog_warn ("%s: VNI hash entry for VNI %u not found",
                 __FUNCTION__, vpn->vni);
      return;
    }

  bgp_evpn_set_auto_rd (bgp, vpn);

  /* Create EVPN type-3 route and schedule for processing. */
  bgp_evpn_update_type3_route (bgp, vpn);
  return;
}

/*
 * bgp_evpn_withdraw_router_id_vni
 *
 * Withdraw the route from peer before updating the router id in evpn cache.
 */
static void
bgp_evpn_withdraw_router_id_vni (struct hash_backet *backet, struct bgp *bgp)
{
  struct bgpevpn *vpn;

  vpn = (struct bgpevpn *) backet->data;

  if (!vpn)
    {
      zlog_warn ("%s: VNI hash entry for VNI %u not found",
                 __FUNCTION__, vpn->vni);
      return;
    }

  /* Remove EVPN type-3 route and schedule for processing. */
  bgp_evpn_delete_type3_route (bgp, vpn);
  return;
}

/*
 * bgp_evpn_handle_router_id_update
 * - Update local VNI cache with new router id in RD
 * - Update evpn type 3 route by removing old RD
 *   and adding the new RD. This should send
 *   withdraw with old RD and update with new RD to peers.
 */
void
bgp_evpn_handle_router_id_update (struct bgp *bgp, int withdraw) 
{
  if (withdraw)
    hash_iterate (bgp->vnihash,
                  (void (*) (struct hash_backet *, void *))
                  bgp_evpn_withdraw_router_id_vni,
                  bgp);
  else
    hash_iterate (bgp->vnihash,
                  (void (*) (struct hash_backet *, void *))
                  bgp_evpn_update_router_id_vni,
                  bgp);
  return;
}

/*
 * Handle del of a local VNI.
 */
int
bgp_evpn_local_vni_del (struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;

  if (!bgp->vnihash)
    {
      zlog_err ("%u: VNI hash not created", bgp->vrf_id);
      return -1;
    }

  /* Locate VNI hash */
  vpn = bgp_evpn_lookup_vpn (bgp, vni);
  if (!vpn)
    {
      zlog_warn ("%u: VNI hash entry for VNI %u not found at DEL",
                 bgp->vrf_id, vni);
      return 0;
    }

  /* Remove EVPN type-3 route and schedule for processing. */
  bgp_evpn_delete_type3_route (bgp, vpn);

  /* Clear locally "learnt" flag and see if hash needs to be freed. */
  UNSET_FLAG (vpn->flags, VNI_FLAG_LOCAL);
  if (!CHECK_FLAG (vpn->flags, VNI_FLAG_CONFIGURED))
    bgp_evpn_free(bgp, vpn);

  return 0;
}

static int
bgp_evpn_delete_type2_route (struct bgp *bgp, struct bgpevpn *vpn, struct ethaddr mac,
                             struct in_addr ip)
{
  struct prefix_evpn p;
  struct bgp_node *rn;
  struct bgp_info *ri;
  afi_t afi = AFI_L2VPN;
  safi_t safi = SAFI_EVPN;

  /* Build prefix and locate route node. */
  build_evpn_type2_prefix (&p, mac, ip, vpn->vni);
  rn = bgp_afi_node_lookup (bgp->rib[afi][safi], afi, safi,
                         (struct prefix *)&p, &vpn->prd);

  if (!rn)
    {
      /* TODO: Temporary, can ignore entry not found at delete. */
      zlog_err ("Could not find type-2 route for VNI %u at Del", vpn->vni);
      return -1;
    }

  /* Now, find matching route. */
  for (ri = rn->info; ri; ri = ri->next)
    if (ri->peer == bgp->peer_self
	&& ri->type == ZEBRA_ROUTE_BGP
        && ri->sub_type == BGP_ROUTE_STATIC)
      break;

  if (!ri)
    {
      /* TODO: Temporary, can ignore entry not found at delete. */
      zlog_err ("Could not find type-2 route info for VNI %u at Del, RN %p",
                vpn->vni, rn);
      bgp_unlock_node (rn);
      return -1;
    }

  /* Mark route for delete and schedule for processing. */
  bgp_info_delete (rn, ri);
  bgp_process (bgp, rn, afi, safi);

  return 0;
}

/*
 * Handle del of a local MAC.
 */
int
bgp_evpn_local_macip_del (struct bgp *bgp, vni_t vni, struct in_addr ip,
                          struct ethaddr mac)
{
  struct bgpevpn *vpn;

  if (!bgp->vnihash)
    {
      zlog_err ("%u: VNI hash not created", bgp->vrf_id);
      return -1;
    }

  if (vni > UINT16_MAX)
    {
      zlog_err ("%u: VNI %u too large, cannot be handled by EVPN",
                bgp->vrf_id, vni);
      return -1;
    }

  /* Add VNI hash (or update, if already present (e.g., configured) */
  vpn = bgp_evpn_lookup_vpn (bgp, vni);
  if (!vpn)
    {
      zlog_warn ("%u: VNI hash entry for VNI %u not found at DEL",
                 bgp->vrf_id, vni);
      return 0;
    }

  /* Remove EVPN type-2 route and schedule for processing. */
  bgp_evpn_delete_type2_route (bgp, vpn, mac, ip);

  /* Clear locally "learnt" flag and see if hash needs to be freed. */
  UNSET_FLAG (vpn->flags, MAC_FLAG_LOCAL);

  return 0;
}

static void
bgp_evpn_print_macip (struct macip *pmac, void *ctxt)
{
  struct vty *vty;

  vty = (struct vty *) ctxt;

  vty_out(vty, "  " MAC_STR " %s%s", macaddrtostring(pmac->emac.octet), 
                                    inet_ntoa(pmac->nw_ip), VTY_NEWLINE);
}

static void
bgp_evpn_print_macip_hash (struct hash_backet *backet, void *ctxt)
{
  struct macip *pmac;

  pmac = (struct macip *) backet->data;
  if (!pmac)
    return;

  bgp_evpn_print_macip (pmac, ctxt);
}

/*
 * bgp_evpn_display_vni
 *
 * Function to display vpn cache.
 */
static void
bgp_evpn_display_vni (struct vty *vty, struct bgpevpn *vpn)
{
  char buf1[INET6_ADDRSTRLEN];
  struct listnode *node, *nnode;
  struct import_rt_node *irt;

  vty_out (vty, "VNI: %d%s", vpn->vni, VTY_NEWLINE);
  vty_out (vty, "  RD: %s%s", prefix_rd2str (&vpn->prd, buf1, RD_ADDRSTRLEN), 
                VTY_NEWLINE);
  vty_out (vty, "  Originator IP: %s%s", inet_ntoa(vpn->originator_ip),
                VTY_NEWLINE);
  vty_out (vty, "  Import Route Target:%s", VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS (vpn->import_rtl, node, nnode, irt))
    bgp_evpn_display_rt(vty, irt->import_rt, irt->vpn->vni, FALSE, FALSE, FALSE);
  vty_out (vty, "  Export Route Target:%s", VTY_NEWLINE);
  bgp_evpn_display_rt(vty, vpn->export_rt, 0, FALSE, FALSE, FALSE);
  if (CHECK_FLAG (vpn->flags, VNI_FLAG_CONFIGURED))
    vty_out (vty, "  VNI information is CLI configured%s", VTY_NEWLINE);
  vty_out(vty, "  MACs for this VNI:%s", VTY_NEWLINE);
  hash_iterate(vpn->macip_table, bgp_evpn_print_macip_hash, vty);
}

/*
 * bgp_evpn_show_one_vni
 *
 * Function to show details of the given vni.
 */
void
bgp_evpn_show_one_vni (struct vty *vty, struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;

  vpn = bgp_evpn_lookup_vpn (bgp, vni);
  if (!vpn)
    {
      vty_out (vty, "VNI not found%s", VTY_NEWLINE);
      return;
    }
  bgp_evpn_display_vni (vty, vpn);
}

/*
 * bgp_evpn_show_vni
 *
 * Display a VNI (upon user query).
 */
void
bgp_evpn_show_vni (struct hash_backet *backet, struct vty *vty)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  bgp_evpn_display_vni (vty, vpn);
}

/*
 * Encode EVPN prefix in Update (MP_REACH)
 */
void
bgp_evpn_encode_prefix (struct stream *s, struct prefix *p,
                        struct prefix_rd *prd, int addpath_encode,
                        u_int32_t addpath_tx_id)
{
  struct prefix_evpn *evp = (struct prefix_evpn *)p;

  if (addpath_encode)
    stream_putl (s, addpath_tx_id);

  /* Route type */
  stream_putc (s, evp->prefix.route_type);

  switch (evp->prefix.route_type)
    {
      case BGP_EVPN_IMET_ROUTE:
        stream_putc (s, 17); // TODO: Hardcoded for now
        stream_put (s, prd->val, 8); /* RD */
        stream_putl (s, 0); /* Ethernet Tag ID */
        stream_putc (s, 4); /* IP address Length */
        /* Originating Router's IP Addr */
        stream_put_in_addr (s, &evp->prefix.ip.v4_addr);
        break;

      case BGP_EVPN_MAC_IP_ROUTE:
        stream_putc (s, 37); // TODO: Hardcoded for now
        stream_put (s, prd->val, 8); /* RD */
        stream_put (s, 0, 10); /* ESI */
        stream_putl (s, 0); /* Ethernet Tag ID */
        stream_putc (s, ETHER_ADDR_LEN); /* Mac Addr Len */
        stream_put (s, evp->prefix.mac.octet, 6); /* Mac Addr */
        stream_putc (s, 4); /* IP address Length */
        stream_put_in_addr (s, &evp->prefix.ip.v4_addr);
        stream_put (s, &evp->prefix.vni, 3); /* VNI */
        break;

      default:
        break;
    }
}

/*
 * Perform sanity check on EVPN NLRI.
 * TODO: Not yet implemented.
 */
int
bgp_evpn_nlri_sanity_check (struct peer *peer, int afi, safi_t safi,
                            u_char *pnt, bgp_size_t length, int *numpfx)
{
  return 0;
}

/*
 * Process EVPN NLRI, create/update/delete route and schedule for processing.
 */
int
bgp_evpn_nlri_parse (struct peer *peer, struct attr *attr, struct bgp_nlri *packet)
{
  u_char *pnt;
  u_char *lim;
  afi_t afi;
  safi_t safi;
  u_int32_t addpath_id;
  int addpath_encoded;
  int psize = 0;
  u_char rtype;
  u_char rlen;
  struct prefix p;

  /* Check peer status. */
  if (peer->status != Established)
    {
      zlog_err ("%u:%s - EVPN update received in state %d",
                peer->bgp->vrf_id, peer->host, peer->status);
      return -1;
    }

  /* Start processing the NLRI - there may be multiple in the MP_REACH */
  pnt = packet->nlri;
  lim = pnt + packet->length;
  afi = packet->afi;
  safi = packet->safi;
  addpath_id = 0;

  addpath_encoded = (CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV) &&
                     CHECK_FLAG (peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_TX_RCV));

#define VPN_PREFIXLEN_MIN_BYTES (3 + 8) /* label + RD */
  for (; pnt < lim; pnt += psize)
    {
      /* Clear prefix structure. */
      memset (&p, 0, sizeof (struct prefix));

      /* Deal with path-id if AddPath is supported. */
      if (addpath_encoded)
        {
          /* When packet overflow occurs return immediately. */
          if (pnt + BGP_ADDPATH_ID_LEN > lim)
            return -1;

          addpath_id = ntohl(*((uint32_t*) pnt));
          pnt += BGP_ADDPATH_ID_LEN;
        }

      /* All EVPN NLRI types start with type and length. */
      if (pnt + 2 > lim)
        return -1;

      rtype = *pnt++;
      psize = rlen = *pnt++;

      /* When packet overflow occur return immediately. */
      if (pnt + psize > lim)
        return -1;

      switch (rtype)
        {
          case BGP_EVPN_IMET_ROUTE:
            if (bgp_evpn_process_type3_route (peer, afi, safi, attr,
                                              pnt, psize, addpath_id))
              {
                zlog_err ("%u:%s - Error in processing EVPN type-3 NLRI size %d",
                          peer->bgp->vrf_id, peer->host, psize);
                return -1;
              }

          case BGP_EVPN_MAC_IP_ROUTE:
            if (bgp_evpn_process_type2_route (peer, afi, safi, attr,
                                              pnt, psize, addpath_id))
              {
                zlog_err ("%u:%s - Error in processing EVPN type-2 NLRI size %d",
                          peer->bgp->vrf_id, peer->host, psize);
                return -1;
              }
            break;

          default:
            break;
        }

    }

  /* Packet length consistency check. */
  if (pnt != lim)
    return -1;

  return 0;
}

/*
 * Install EVPN route into zebra, if appropriate.
 * TODO: There are some assumptions here such as auto-RD and auto-RT.
 */
int
bgp_evpn_install_route (struct bgp *bgp, afi_t afi, safi_t safi,
                        struct prefix *p, struct bgp_info *ri)
{
  struct prefix_evpn *evp = (struct prefix_evpn *)p;
  int ret = 0;

  switch (evp->prefix.route_type)
    {
      case BGP_EVPN_IMET_ROUTE:
        ret = bgp_evpn_install_type3_route (bgp, afi, safi, evp, ri, 0);
        break;

      case BGP_EVPN_MAC_IP_ROUTE:
        ret = bgp_evpn_install_type2_route (bgp, afi, safi, evp, ri, 0);
        break;

      default:
        break;
    }

  return ret;
}

/*
 * Uninstall EVPN route from zebra, if appropriate.
 */
int
bgp_evpn_uninstall_route (struct bgp *bgp, afi_t afi, safi_t safi,
                          struct prefix *p, struct bgp_info *ri)
{
  struct prefix_evpn *evp = (struct prefix_evpn *)p;
  int ret = 0;

  switch (evp->prefix.route_type)
    {
      case BGP_EVPN_IMET_ROUTE:
        ret = bgp_evpn_uninstall_type3_route (bgp, afi, safi, evp, ri);
        break;

      case BGP_EVPN_MAC_IP_ROUTE:
        ret = bgp_evpn_uninstall_type2_route (bgp, afi, safi, evp, ri);
        break;

      default:
        break;
    }

  return ret;
}

/*
 * bgp_evpn_init
 *
 * Initialize vnihash.
 */
void
bgp_evpn_init (struct bgp *bgp)
{
  bgp->vnihash = hash_create(vni_hash_key_make, vni_hash_cmp);
  bgp->import_rt_hash = hash_create(import_rt_hash_key_make, import_rt_hash_cmp);
}

/*
 * bgp_evpn_cleanup
 *
 * Cleanup all BGP EVPN cache.
 */
void
bgp_evpn_cleanup (struct bgp *bgp)
{
  hash_iterate (bgp->vnihash,
                (void (*) (struct hash_backet *, void *))
                bgp_evpn_free_all_vni_iterator,
                bgp);
  hash_free(bgp->import_rt_hash);
  bgp->import_rt_hash = NULL;
  hash_free(bgp->vnihash);
  bgp->vnihash = NULL;
}

/*
 * bgp_evpn_cleanup_local_vni_and_withdraw_route_iterator
 *
 * Function to clean up all VNI cache and withdraw routes.
 */
static void
bgp_evpn_cleanup_local_vni_and_withdraw_route_iterator (struct hash_backet *backet, 
                                                        struct bgp *bgp)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  
  /* Remove EVPN type-3 route and schedule for processing. */
  bgp_evpn_delete_type3_route (bgp, vpn);

  /* Clear locally "learnt" flag and see if hash needs to be freed. */
  UNSET_FLAG (vpn->flags, VNI_FLAG_LOCAL);
  if (!CHECK_FLAG (vpn->flags, VNI_FLAG_CONFIGURED))
    bgp_evpn_free(bgp, vpn);
}

/*
 * bgp_evpn_update_advertise_vni
 *
 * Function to register/deregister advertise_vni with zebra
 */
void
bgp_evpn_update_advertise_vni (struct bgp *bgp)
{
  zlog_debug("%s:Update advertise vni flag:%d in zebra\n", __FUNCTION__,
                                                        bgp->advertise_vni);
  bgp_zebra_advertise_vni (bgp, bgp->advertise_vni);

  /* Cleanup for 'no advertise-vni' */
  if (!bgp->advertise_vni)
    {
      hash_iterate (bgp->vnihash,
                (void (*) (struct hash_backet *, void *))
                bgp_evpn_cleanup_local_vni_and_withdraw_route_iterator,
                bgp);
    } 
}

/*
 * bgp_evpn_route2str
 *
 * Function to convert evpn route to string.
 */
char *
bgp_evpn_route2str (struct prefix_evpn *p, char *buf)
{
  if (p->prefix.route_type == BGP_EVPN_IMET_ROUTE)
    {
      snprintf (buf, EVPN_ROUTE_LEN, "[%d]:[0]:[%d]:[%s]",p->prefix.route_type,
                    (p->prefix.flags == IP_ADDR_V4)? 
                    IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN,
                    inet_ntoa(p->prefix.ip.v4_addr));
    }
  if (p->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
    {
      snprintf (buf, EVPN_ROUTE_LEN, "[%d]:[0]:[0]:[%d]:["MAC_STR"]:[%d]:[%s]",
                    p->prefix.route_type,
                    ETHER_ADDR_LEN,
                    macaddrtostring(p->prefix.mac.octet),
                    (p->prefix.flags == IP_ADDR_V4)? 
                    IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN,
                    inet_ntoa(p->prefix.ip.v4_addr));
    }
  return(buf);
}

/*
 * bgp_evpn_print_prefix
 *
 * Function to print evpn prefix.
 */
int
bgp_evpn_print_prefix (struct vty *vty, struct prefix_evpn *p)
{
  int len = 0;
  char buf[EVPN_ROUTE_LEN];

  len = vty_out (vty, "%s", bgp_evpn_route2str(p, buf));
  return len;
}

/*
 * bgp_evpn_check_auto_rd_flag
 *
 * Check RD_AUTO flag.
 */
int
bgp_evpn_check_auto_rd_flag (struct bgpevpn *vpn)
{
  return (CHECK_FLAG (vpn->flags, RD_AUTO));
}

/*
 * bgp_evpn_check_configured_rd
 *
 * Check configured prd with VPN prd.
 */
int
bgp_evpn_check_configured_rd (struct bgpevpn *vpn, struct prefix_rd *prd)
{
  return(memcmp (&vpn->prd.val, prd->val, ECOMMUNITY_SIZE));
}

/*
 * bgp_evpn_update_rd
 *
 * Update CLI configured RD into VPN
 */
void
bgp_evpn_update_rd (struct bgp *bgp, struct bgpevpn *vpn, struct prefix_rd *rd,
                    int auto_rd)
{
  if (!bgp || !vpn)
    return;

  if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
    /* Remove EVPN type-3 route and schedule for processing. */
    bgp_evpn_delete_type3_route (bgp, vpn);

  if (auto_rd)
    {
      bgp_evpn_set_auto_rd (bgp, vpn);
    }
  else
    {
      memcpy(&vpn->prd, rd, sizeof (struct prefix_rd));
      bgp_evpn_unset_auto_rd_flag(vpn);
    }

  if (CHECK_FLAG (vpn->flags, VNI_FLAG_LOCAL))
    {
      /* Create EVPN type-3 route and schedule for processing. */
      if (bgp_evpn_update_type3_route (bgp, vpn))
        zlog_err ("%u: Type3 route creation failure for VNI %u",
                  bgp->vrf_id, vpn->vni);
    }
  bgp_evpn_update_vni_config_flag (vpn);
}

/*
 * bgp_evpn_process_rt_config
 *
 * Process CLI configured route target.
 */
int
bgp_evpn_process_rt_config (struct vty *vty, struct bgp *bgp, struct bgpevpn *vpn,
                            struct prefix_rd *prd, const char *rttype, int add, int auto_rt)
{
  int processed=0;
  int rttype_ip=0;
  u_int16_t rdtype = 0xffff;
  struct rd_ip rd_ip;
  struct rd_as rd_as;
  struct in_addr ip = { .s_addr = INADDR_ANY };
  struct ecommunity_val rt_conf;
  u_char rt_type;

  if (!auto_rt)
    {
      ip.s_addr = 0;
      rdtype = (prd->val[0] << 8) | prd->val[1];

      /* Decode and set values of rt node. */
      if (rdtype == RD_TYPE_IP)
        {
          decode_rd_ip (prd->val + 2, &rd_ip);
          rt_type = ECOMMUNITY_ENCODE_IP;
          rttype_ip = 1;
        }
      else if (rdtype == RD_TYPE_AS4)
        {
          decode_rd_as4(prd->val + 2, &rd_as);
          rt_type = ECOMMUNITY_ENCODE_AS4;
        }
      else
        {
          decode_rd_as(prd->val + 2, &rd_as);
          rt_type = ECOMMUNITY_ENCODE_AS;
        }
      ecommunity_encode (rt_type, ECOMMUNITY_ROUTE_TARGET, 1, rd_as.as,
                         (rttype_ip)? rd_ip.ip : ip,
                         (rttype_ip)? rd_ip.val : rd_as.val,
                         &rt_conf);
    }

  if (!strcmp(rttype, "import") || !strcmp(rttype, "both"))
    {
      bgp_evpn_update_import_rt (bgp, vpn, rt_conf, add, auto_rt);
      processed=1;
    }
  if (!strcmp(rttype, "export") || !strcmp(rttype, "both"))
    {
      if (add && !memcmp(vpn->export_rt.val, rt_conf.val, ECOMMUNITY_SIZE))
        {
          vty_out (vty, "Entered route target matches cached"
                        " route target, nothing to be done%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      if (!add && memcmp(vpn->export_rt.val, rt_conf.val, ECOMMUNITY_SIZE) != 0)
        {
          vty_out (vty, "Route target mismatch, please enter"
                        " configured route target%s", VTY_NEWLINE);
          return CMD_WARNING;
        }
      bgp_evpn_update_export_rt (bgp, vpn, rt_conf, add, auto_rt);
      processed=1;
    }
  if (!processed)
    {
      vty_out (vty, "Enter valid option (import/export/both)");
      return CMD_WARNING;
    }

  /*
   * Update VNI_FLAG_CONFIGURED based on RD/RT configs.
   */
  bgp_evpn_update_vni_config_flag (vpn);

  return CMD_SUCCESS;
}

/*
 * bgp_evpn_show_import_rt
 *
 * Show import rt from bgp->import_rt_hash
 */
void
bgp_evpn_show_import_rt (struct hash_backet *backet, struct vty *vty)
{
  struct import_rt_node *irt = (struct import_rt_node *) backet->data;
  bgp_evpn_display_rt (vty, irt->import_rt, irt->vpn->vni, TRUE, FALSE, FALSE);
}

/*
 * bgp_evpn_check_uninstall_evpn_route
 *
 * Check if the given route has RT in import-rt. If not,
 * remove the route from rib.
 */
void
bgp_evpn_check_uninstall_evpn_route (struct bgp *bgp, afi_t afi, safi_t safi,
                                     struct prefix_evpn *evp,
                                     struct bgp_info *ri)
{
  if (!bgp_evpn_lookup_import_rt (bgp,
                                  (u_char *)ri->attr->extra->ecommunity->val))
    {
       if (evp->prefix.route_type == BGP_EVPN_IMET_ROUTE)
         bgp_evpn_uninstall_type3_route (bgp, afi, safi, evp, ri);
       if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
         bgp_evpn_uninstall_type2_route (bgp, afi, safi, evp, ri);
    }
  return;
}

void
bgp_config_write_advertise_vni (struct vty *vty, struct bgp *bgp, afi_t afi,
                                safi_t safi, int *write)
{
  struct evpn_config_write cfg;

  if (bgp->advertise_vni)
    {
      bgp_config_write_family_header (vty, afi, safi, write);
      vty_out (vty, "  advertise-vni%s", VTY_NEWLINE);
    }
  cfg.write = *write;
  cfg.vty = vty;
  if (bgp->vnihash)
    {
      hash_iterate (bgp->vnihash,
                    (void (*) (struct hash_backet *, void *))
                    bgp_config_write_vxlan_info,
                    &cfg);
    }
  *write = cfg.write;
}
