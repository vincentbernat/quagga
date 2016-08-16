/* BGP RD definitions for BGP-based VPNs (IP/EVPN)
 * -- brought over from bgpd/bgp_mplsvpn.c
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#include <zebra.h>
#include "command.h"
#include "log.h"
#include "prefix.h"
#include "memory.h"
#include "stream.h"
#include "filter.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_rd.h"

u_int16_t
decode_rd_type (u_char *pnt)
{
  u_int16_t v;
  
  v = ((u_int16_t) *pnt++ << 8);
  v |= (u_int16_t) *pnt;
  return v;
}

/* type == RD_TYPE_AS */
void
decode_rd_as (u_char *pnt, struct rd_as *rd_as)
{
  rd_as->as = (u_int16_t) *pnt++ << 8;
  rd_as->as |= (u_int16_t) *pnt++;
  
  rd_as->val = ((u_int32_t) *pnt++ << 24);
  rd_as->val |= ((u_int32_t) *pnt++ << 16);
  rd_as->val |= ((u_int32_t) *pnt++ << 8);
  rd_as->val |= (u_int32_t) *pnt;
}

/* type == RD_TYPE_AS4 */
void
decode_rd_as4 (u_char *pnt, struct rd_as *rd_as)
{
  rd_as->as  = (u_int32_t) *pnt++ << 24;
  rd_as->as |= (u_int32_t) *pnt++ << 16;
  rd_as->as |= (u_int32_t) *pnt++ << 8;
  rd_as->as |= (u_int32_t) *pnt++;

  rd_as->val  = ((u_int16_t) *pnt++ << 8);
  rd_as->val |= (u_int16_t) *pnt;
}

/* type == RD_TYPE_IP */
void
decode_rd_ip (u_char *pnt, struct rd_ip *rd_ip)
{
  memcpy (&rd_ip->ip, pnt, 4);
  pnt += 4;
  
  rd_ip->val = ((u_int16_t) *pnt++ << 8);
  rd_ip->val |= (u_int16_t) *pnt;
}

int
str2prefix_rd (const char *str, struct prefix_rd *prd)
{
  int ret;
  char *p;
  char *p2;
  struct stream *s;
  char *half;
  struct in_addr addr;

  s = stream_new (8);

  prd->family = AF_UNSPEC;
  prd->prefixlen = 64;

  p = strchr (str, ':');
  if (! p)
    return 0;

  if (! all_digit (p + 1))
    return 0;

  half = XMALLOC (MTYPE_TMP, (p - str) + 1);
  memcpy (half, str, (p - str));
  half[p - str] = '\0';

  p2 = strchr (str, '.');

  if (! p2)
    {
      if (! all_digit (half))
	{
	  XFREE (MTYPE_TMP, half);
	  return 0;
	}
      stream_putw (s, RD_TYPE_AS);
      stream_putw (s, atoi (half));
      stream_putl (s, atol (p + 1));
    }
  else
    {
      ret = inet_aton (half, &addr);
      if (! ret)
	{
	  XFREE (MTYPE_TMP, half);
	  return 0;
	}
      stream_putw (s, RD_TYPE_IP);
      stream_put_in_addr (s, &addr);
      stream_putw (s, atol (p + 1));
    }
  memcpy (prd->val, s->data, 8);

  XFREE(MTYPE_TMP, half);
  return 1;
}

char *
prefix_rd2str (struct prefix_rd *prd, char *buf, size_t size)
{
  u_char *pnt;
  u_int16_t type;
  struct rd_as rd_as;
  struct rd_ip rd_ip;

  if (size < RD_ADDRSTRLEN)
    return NULL;

  pnt = prd->val;

  type = decode_rd_type (pnt);

  if (type == RD_TYPE_AS)
    {
      decode_rd_as (pnt + 2, &rd_as);
      snprintf (buf, size, "%u:%d", rd_as.as, rd_as.val);
      return buf;
    }
  else if (type == RD_TYPE_AS4)
    {
      decode_rd_as4 (pnt + 2, &rd_as);
      snprintf (buf, size, "%u:%d", rd_as.as, rd_as.val);
      return buf;
    }
  else if (type == RD_TYPE_IP)
    {
      decode_rd_ip (pnt + 2, &rd_ip);
      snprintf (buf, size, "%s:%d", inet_ntoa (rd_ip.ip), rd_ip.val);
      return buf;
    }
  return NULL;
}
