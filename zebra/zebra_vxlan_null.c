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

int zebra_vxlan_advertise_vni (struct zserv *client, int sock,
                               u_short length, struct zebra_vrf *zvrf)
{
  return 0;
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
