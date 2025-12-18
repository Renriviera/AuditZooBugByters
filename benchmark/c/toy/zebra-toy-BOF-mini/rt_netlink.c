/* Kernel routing table updates using netlink over GNU/Linux system.
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>


static int parse_encap_seg6(struct rtattr *tb, struct in6_addr *segs)
{
	struct rtattr *tb_encap[256] = {};
	struct seg6_iptunnel_encap *ipt = NULL;
	struct in6_addr *segments = NULL;

	netlink_parse_rtattr_nested(tb_encap, 256, tb);

	/*
	 * TODO: It's not support multiple SID list.
	 */
	if (tb_encap[SEG6_IPTUNNEL_SRH]) {
		ipt = (struct seg6_iptunnel_encap *)
			RTA_DATA(tb_encap[SEG6_IPTUNNEL_SRH]);
		segments = ipt->srh[0].segments;
		*segs = segments[0];
		return 1;
	}

	return 0;
}
