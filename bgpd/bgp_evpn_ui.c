/* BGP EVPN UI
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

/*
 * Definitions and external declarations.
 */


struct evpn_config_write
{
  int write;
  struct vty *vty;
};

extern struct zclient *zclient;


/*
 * Private functions.
 */

static void
write_vni_config (struct vty *vty, struct bgpevpn *vpn, int *write)
{
  char buf1[INET6_ADDRSTRLEN];
  afi_t afi = AFI_L2VPN;
  safi_t safi = SAFI_EVPN;
  char *ecom_str;

  if (is_vni_configured (vpn))
    {
      bgp_config_write_family_header (vty, afi, safi, write);
      vty_out (vty, "  vni %d%s", vpn->vni, VTY_NEWLINE);
      if (is_rd_configured (vpn))
          vty_out (vty, "   rd %s%s",
                        prefix_rd2str (&vpn->prd, buf1, RD_ADDRSTRLEN),
                        VTY_NEWLINE);
      if (is_import_rt_configured (vpn))
        {
          ecom_str = ecommunity_ecom2str (vpn->import_rtl,
                                          ECOMMUNITY_FORMAT_ROUTE_MAP);
          vty_out (vty, "   route-target import %s%s", ecom_str, VTY_NEWLINE);
          XFREE (MTYPE_ECOMMUNITY_STR, ecom_str);
        }
      if (is_export_rt_configured (vpn))
        {
          ecom_str = ecommunity_ecom2str (vpn->export_rtl,
                                          ECOMMUNITY_FORMAT_ROUTE_MAP);
          vty_out (vty, "   route-target export %s%s", ecom_str, VTY_NEWLINE);
          XFREE (MTYPE_ECOMMUNITY_STR, ecom_str);
        }

      vty_out (vty, "  exit-vni%s", VTY_NEWLINE);
    }
}

static void
write_vni_config_for_entry (struct hash_backet *backet,
                            struct evpn_config_write *cfg)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  write_vni_config (cfg->vty, vpn, &cfg->write);
}

static void
display_import_rt (struct vty *vty, struct irt_node *irt)
{
  u_char *pnt;
  u_char type, sub_type;
  struct ecommunity_as
  {
    as_t as;
    u_int32_t val;
  } eas;
  struct ecommunity_ip
  {
    struct in_addr ip;
    u_int16_t val;
  } eip;
  struct listnode *node, *nnode;
  struct bgpevpn *tmp_vpn;


  /* TODO: This needs to go into a function */

  pnt = (u_char *)&irt->rt.val;
  type = *pnt++;
  sub_type = *pnt++;
  if (sub_type != ECOMMUNITY_ROUTE_TARGET)
    return;

  switch (type)
    {
      case ECOMMUNITY_ENCODE_AS:
        eas.as = (*pnt++ << 8);
        eas.as |= (*pnt++);

        eas.val = (*pnt++ << 24);
        eas.val |= (*pnt++ << 16);
        eas.val |= (*pnt++ << 8);
        eas.val |= (*pnt++);

        vty_out (vty, "Route-target: %u:%u", eas.as, eas.val);
        break;

      case ECOMMUNITY_ENCODE_IP:
        memcpy (&eip.ip, pnt, 4);
        pnt += 4;
        eip.val = (*pnt++ << 8);
        eip.val |= (*pnt++);

        vty_out (vty, "Route-target: %s:%u",
                 inet_ntoa (eip.ip), eip.val);
        break;

      case ECOMMUNITY_ENCODE_AS4:
        eas.as = (*pnt++ << 24);
        eas.as |= (*pnt++ << 16);
        eas.as |= (*pnt++ << 8);
        eas.as |= (*pnt++);

        eas.val = (*pnt++ << 8);
        eas.val |= (*pnt++);

        vty_out (vty, "Route-target: %u:%u", eas.as, eas.val);
        break;

      default:
        return;
    }

  vty_out (vty, "%s", VTY_NEWLINE);
  vty_out (vty, "List of VNIs importing routes with this route-target:%s",
           VTY_NEWLINE);

  for (ALL_LIST_ELEMENTS (irt->vnis, node, nnode, tmp_vpn))
    vty_out (vty, "  %u%s", tmp_vpn->vni, VTY_NEWLINE);
}

static void
display_vni (struct vty *vty, struct bgpevpn *vpn)
{
  char buf1[INET6_ADDRSTRLEN];
  char *ecom_str;

  vty_out (vty, "VNI: %d", vpn->vni);
  if (is_vni_configured (vpn))
    vty_out (vty, " (configured)");
  if (is_vni_live (vpn))
    vty_out (vty, " (defined in the kernel)");
  vty_out (vty, "%s", VTY_NEWLINE);

  vty_out (vty, "  RD: %s%s",
           prefix_rd2str (&vpn->prd, buf1, RD_ADDRSTRLEN),
           is_rd_configured (vpn) ? " (configured)" : "");
  vty_out (vty, "%s", VTY_NEWLINE);

  vty_out (vty, "  Originator IP: %s%s",
           inet_ntoa(vpn->originator_ip), VTY_NEWLINE);

  vty_out (vty, "  Import Route Target:%s%s",
           is_import_rt_configured (vpn) ? " (configured)" : "",
           VTY_NEWLINE);
  ecom_str = ecommunity_ecom2str (vpn->import_rtl,
                                  ECOMMUNITY_FORMAT_ROUTE_MAP);
  vty_out (vty, "    %s%s", ecom_str, VTY_NEWLINE);
  XFREE (MTYPE_ECOMMUNITY_STR, ecom_str);

  vty_out (vty, "  Export Route Target:%s%s",
           is_export_rt_configured (vpn) ? " (configured)" : "",
           VTY_NEWLINE);
  ecom_str = ecommunity_ecom2str (vpn->export_rtl,
                                  ECOMMUNITY_FORMAT_ROUTE_MAP);
  vty_out (vty, "    %s%s", ecom_str, VTY_NEWLINE);
  XFREE (MTYPE_ECOMMUNITY_STR, ecom_str);
}

static void
show_import_rt_entry (struct hash_backet *backet, struct vty *vty)
{
  struct irt_node *irt = (struct irt_node *) backet->data;
  display_import_rt (vty, irt);
}

static void
show_vni_entry (struct hash_backet *backet, struct vty *vty)
{
  struct bgpevpn *vpn = (struct bgpevpn *) backet->data;
  display_vni (vty, vpn);
}


/*
 * Public functions.
 */


/*
 * Configure the Import RTs for a VNI (vty handler). Caller expected to
 * check that this is a change. Note that import RTs are implemented as
 * a "replace" (similar to other configuration).
 */
void
bgp_evpn_configure_import_rt (struct bgp *bgp, struct bgpevpn *vpn,
                              struct ecommunity *ecomadd)
{
  /* If the VNI is "live", we need to uninstall routes using the current
   * import RT(s) first before we update the import RT, and subsequently
   * install routes.
   */
  if (is_vni_live (vpn))
    bgp_evpn_uninstall_routes (bgp, vpn);

  /* Cleanup the RT to VNI mapping and get rid of existing import RT. */
  bgp_evpn_unmap_vni_from_its_rts (bgp, vpn);
  ecommunity_free (&vpn->import_rtl);

  /* Set to new value and rebuild the RT to VNI mapping */
  vpn->import_rtl = ecomadd;
  SET_FLAG (vpn->flags, VNI_FLAG_IMPRT_CFGD);
  bgp_evpn_map_vni_to_its_rts (bgp, vpn);

  /* Install routes that match new import RT */
  if (is_vni_live (vpn))
    bgp_evpn_install_routes (bgp, vpn);
}

/*
 * Unconfigure Import RT(s) for a VNI (vty handler).
 */
void
bgp_evpn_unconfigure_import_rt (struct bgp *bgp, struct bgpevpn *vpn,
                                struct ecommunity *ecomadd)
{
  /* Along the lines of "configure" except we have to reset to the
   * automatic value.
   */
  if (is_vni_live (vpn))
    bgp_evpn_uninstall_routes (bgp, vpn);

  /* Cleanup the RT to VNI mapping and get rid of existing import RT. */
  bgp_evpn_unmap_vni_from_its_rts (bgp, vpn);
  ecommunity_free (&vpn->import_rtl);

  /* Reset to auto RT - this also rebuilds the RT to VNI mapping */
  bgp_evpn_derive_auto_rt_import (bgp, vpn);

  /* Install routes that match new import RT */
  if (is_vni_live (vpn))
    bgp_evpn_install_routes (bgp, vpn);
}

/*
 * Configure the Export RT for a VNI (vty handler). Caller expected to
 * check that this is a change. Note that only a single export RT is
 * allowed for a VNI and any change to configuration is implemented as
 * a "replace" (similar to other configuration).
 */
void
bgp_evpn_configure_export_rt (struct bgp *bgp, struct bgpevpn *vpn,
                              struct ecommunity *ecomadd)
{
  /* Replace existing with new config and process all routes. */
  ecommunity_free (&vpn->export_rtl);
  vpn->export_rtl = ecomadd;
  SET_FLAG (vpn->flags, VNI_FLAG_EXPRT_CFGD);
  if (is_vni_live (vpn))
    bgp_evpn_handle_export_rt_change (bgp, vpn);
}

/*
 * Unconfigure the Export RT for a VNI (vty handler)
 */
void
bgp_evpn_unconfigure_export_rt (struct bgp *bgp, struct bgpevpn *vpn,
                                struct ecommunity *ecomadd)
{
  /* Reset to default and process all routes. */
  ecommunity_free (&vpn->export_rtl);
  bgp_evpn_derive_auto_rt_export (bgp, vpn);
  if (is_vni_live (vpn))
    bgp_evpn_handle_export_rt_change (bgp, vpn);
}

/*
 * Configure RD for a VNI (vty handler)
 */
void
bgp_evpn_configure_rd (struct bgp *bgp, struct bgpevpn *vpn,
                       struct prefix_rd *rd)
{
  /* update RD */
  memcpy(&vpn->prd, rd, sizeof (struct prefix_rd));
  SET_FLAG (vpn->flags, VNI_FLAG_RD_CFGD);
}

/*
 * Unconfigure RD for a VNI (vty handler)
 */
void
bgp_evpn_unconfigure_rd (struct bgp *bgp, struct bgpevpn *vpn)
{
  /* reset RD to default */
  bgp_evpn_derive_auto_rd (bgp, vpn);
}

/*
 * Create VNI, if not already present (VTY handler). Mark as configured.
 */
struct bgpevpn *
bgp_evpn_create_update_vni (struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;

  if (!bgp->vnihash)
    return NULL;

  vpn = bgp_evpn_lookup_vni (bgp, vni);
  if (!vpn)
    {
      vpn = bgp_evpn_new (bgp, vni, bgp->router_id);
      if (!vpn)
        {
          zlog_err ("%u: Failed to allocate VNI entry for VNI %u - at Config",
                    bgp->vrf_id, vni);
          return NULL;
        }
    }

  /* Mark as configured. */
  SET_FLAG (vpn->flags, VNI_FLAG_CFGD);
  return vpn;
}

/*
 * Delete VNI; either free it or mark as unconfigured.
 */
int
bgp_evpn_delete_vni (struct bgp *bgp, struct bgpevpn *vpn)
{
  assert (bgp->vnihash);

  UNSET_FLAG (vpn->flags, VNI_FLAG_CFGD);
  if (!is_vni_live (vpn))
    bgp_evpn_free (bgp, vpn);
  return 0;
}

/*
 * Output EVPN configuration information.
 */
void
bgp_config_write_evpn_info (struct vty *vty, struct bgp *bgp, afi_t afi,
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
                    write_vni_config_for_entry, &cfg);
    }
  *write = cfg.write;
}

/*
 * Display import RT mapping to VNIs (vty handler)
 */
void
bgp_evpn_show_import_rts (struct vty *vty, struct bgp *bgp)
{
  hash_iterate (bgp->import_rt_hash,
                (void (*) (struct hash_backet *, void *))
                show_import_rt_entry, vty);
}

/*
 * Display specified VNI (vty handler)
 */
void
bgp_evpn_show_vni (struct vty *vty, struct bgp *bgp, vni_t vni)
{
  struct bgpevpn *vpn;

  vpn = bgp_evpn_lookup_vni (bgp, vni);
  if (!vpn)
    {
      vty_out (vty, "VNI not found%s", VTY_NEWLINE);
      return;
    }

  display_vni (vty, vpn);
}

/*
 * Display a VNI (upon user query).
 */
void
bgp_evpn_show_all_vnis (struct vty *vty, struct bgp *bgp)
{
  hash_iterate (bgp->vnihash,
                (void (*) (struct hash_backet *, void *))
                show_vni_entry, vty);
}

/*
 * EVPN (VNI advertisement) enabled. Register with zebra.
 */
void
bgp_evpn_set_advertise_vni (struct bgp *bgp)
{
  bgp->advertise_vni = 1;
  bgp_zebra_advertise_vni (bgp, bgp->advertise_vni);
}

/*
 * EVPN (VNI advertisement) disabled. De-register with zebra. Cleanup VNI
 * cache, EVPN routes (delete and withdraw from peers).
 */
void
bgp_evpn_unset_advertise_vni (struct bgp *bgp)
{
  bgp->advertise_vni = 0;
  bgp_zebra_advertise_vni (bgp, bgp->advertise_vni);
  bgp_evpn_cleanup_on_disable (bgp);
}
