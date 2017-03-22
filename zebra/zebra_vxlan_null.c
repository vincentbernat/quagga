#include <zebra.h>

#include "if.h"
#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/rib.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_l2.h"
#include "zebra/zebra_vxlan.h"

int
zebra_vxlan_if_up (struct interface *ifp)
{
  return 0;
}

int
zebra_vxlan_if_down (struct interface *ifp)
{
  return 0;
}

int
zebra_vxlan_if_add_update (struct interface *ifp,
                           struct zebra_l2if_vxlan *zl2if)
{
  return 0;
}

int
zebra_vxlan_if_del (struct interface *ifp)
{
  return 0;
}

int zebra_vxlan_update_access_vlan (struct interface *ifp,
                                    vlanid_t access_vlan)
{
  return 0;
}

int zebra_vxlan_remote_vtep_add (struct zserv *client, int sock,
                                 u_short length, struct zebra_vrf *zvrf)
{
  return 0;
}

int zebra_vxlan_remote_vtep_del (struct zserv *client, int sock,
                                 u_short length, struct zebra_vrf *zvrf)
{
  return 0;
}

int zebra_vxlan_remote_macip_add (struct zserv *client, int sock,
                                  u_short length, struct zebra_vrf *zvrf)
{
  return 0;
}

int zebra_vxlan_remote_macip_del (struct zserv *client, int sock,
                                  u_short length, struct zebra_vrf *zvrf)
{
  return 0;
}

int
zebra_vxlan_local_mac_add_update (struct interface *ifp, struct interface *br_if,
                                  struct ethaddr *mac, vlanid_t vid)
{
  return 0;
}

int
zebra_vxlan_local_mac_del (struct interface *ifp, struct interface *br_if,
                           struct ethaddr *mac, vlanid_t vid)
{
  return 0;
}

int
zebra_vxlan_check_readd_remote_mac (struct interface *ifp,
                                    struct interface *br_if,
                                    struct ethaddr *mac, vlanid_t vid)
{
  return 0;
}

int
zebra_vxlan_check_del_local_mac (struct interface *ifp,
                                 struct interface *br_if,
                                 struct ethaddr *mac, vlanid_t vid)
{
  return 0;
}

int zebra_vxlan_advertise_all_vni (struct zserv *client, int sock,
                                   u_short length, struct zebra_vrf *zvrf)
{
  return 0;
}

void
zebra_vxlan_print_macs_vni (struct vty *vty, struct zebra_vrf *zvrf, vni_t vni)
{
}

void zebra_vxlan_print_macs_all_vni (struct vty *vty, struct zebra_vrf *zvrf)
{
}

void
zebra_vxlan_print_specific_mac_vni (struct vty *vty, struct zebra_vrf *zvrf,
                                    vni_t vni, struct ethaddr *mac)
{
}

void
zebra_vxlan_print_macs_vni_vtep (struct vty *vty, struct zebra_vrf *zvrf,
                                 vni_t vni, struct in_addr vtep_ip)
{
}

void
zebra_vxlan_print_vni (struct vty *vty, struct zebra_vrf *zvrf, vni_t vni)
{
}

void
zebra_vxlan_print_vnis (struct vty *vty, struct zebra_vrf *zvrf)
{
}

void
zebra_vxlan_init_tables (struct zebra_vrf *zvrf)
{
}

void
zebra_vxlan_close_tables (struct zebra_vrf *zvrf)
{
}
