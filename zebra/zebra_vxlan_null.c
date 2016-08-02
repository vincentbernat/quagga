#include <zebra.h>

#if defined(HAVE_EVPN)

#include "if.h"
#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/rib.h"
#include "zebra/zebra_vrf.h"
#include "zebra/zebra_vxlan.h"

int
zebra_vxlan_if_add (struct interface *ifp, vni_t vni)
{
  return 0;
}

int
zebra_vxlan_if_del (struct interface *ifp)
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

int zebra_vxlan_advertise_vni (struct zserv *client, int sock,
                               u_short length, struct zebra_vrf *zvrf)
{
  return 0;
}

void
zebra_vxlan_init_tables (struct zebra_vrf *zvrf)
{
}
#endif /* HAVE_EVPN */
