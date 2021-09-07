/* Copyright (C) 2020-2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file manage_sql_port_lists.c
 * @brief GVM management layer: Port list SQL
 *
 * The Port List SQL for the GVM management layer.
 */

#include "manage_sql_port_lists.h"
#include "manage_acl.h"
#include "manage_port_lists.h"
#include "sql.h"

#include <errno.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "md manage"


/* Static headers for internal non-SQL functions. */

int
sync_port_lists_with_feed (gboolean);


/* Port list functions. */

/**
 * @brief Insert a port range.
 */
#define RANGE(type, start, end)                                      \
  sql ("INSERT INTO port_ranges"                                     \
       " (uuid, port_list, type, start, \"end\", comment, exclude)"  \
       " VALUES"                                                     \
       " (make_uuid (), %llu, %i,"                                   \
       "  '" G_STRINGIFY (start) "',"                                \
       "  '" G_STRINGIFY (end) "',"                                  \
       "  '', 0)",                                                   \
       list,                                                         \
       type)

/**
 * @brief Make port ranges.
 *
 * Caller must lock the db.
 *
 * @param[in]  list  Port list.
 */
static void
make_port_ranges_openvas_default (port_list_t list)
{
  RANGE (PORT_PROTOCOL_TCP, 1, 5);
  RANGE (PORT_PROTOCOL_TCP, 7, 7);
  RANGE (PORT_PROTOCOL_TCP, 9, 9);
  RANGE (PORT_PROTOCOL_TCP, 11, 11);
  RANGE (PORT_PROTOCOL_TCP, 13, 13);
  RANGE (PORT_PROTOCOL_TCP, 15, 15);
  RANGE (PORT_PROTOCOL_TCP, 17, 25);
  RANGE (PORT_PROTOCOL_TCP, 27, 27);
  RANGE (PORT_PROTOCOL_TCP, 29, 29);
  RANGE (PORT_PROTOCOL_TCP, 31, 31);
  RANGE (PORT_PROTOCOL_TCP, 33, 33);
  RANGE (PORT_PROTOCOL_TCP, 35, 35);
  RANGE (PORT_PROTOCOL_TCP, 37, 39);
  RANGE (PORT_PROTOCOL_TCP, 41, 59);
  RANGE (PORT_PROTOCOL_TCP, 61, 224);
  RANGE (PORT_PROTOCOL_TCP, 242, 248);
  RANGE (PORT_PROTOCOL_TCP, 256, 268);
  RANGE (PORT_PROTOCOL_TCP, 280, 287);
  RANGE (PORT_PROTOCOL_TCP, 308, 322);
  RANGE (PORT_PROTOCOL_TCP, 333, 333);
  RANGE (PORT_PROTOCOL_TCP, 344, 700);
  RANGE (PORT_PROTOCOL_TCP, 702, 702);
  RANGE (PORT_PROTOCOL_TCP, 704, 707);
  RANGE (PORT_PROTOCOL_TCP, 709, 711);
  RANGE (PORT_PROTOCOL_TCP, 721, 721);
  RANGE (PORT_PROTOCOL_TCP, 723, 723);
  RANGE (PORT_PROTOCOL_TCP, 729, 731);
  RANGE (PORT_PROTOCOL_TCP, 740, 742);
  RANGE (PORT_PROTOCOL_TCP, 744, 744);
  RANGE (PORT_PROTOCOL_TCP, 747, 754);
  RANGE (PORT_PROTOCOL_TCP, 758, 765);
  RANGE (PORT_PROTOCOL_TCP, 767, 767);
  RANGE (PORT_PROTOCOL_TCP, 769, 777);
  RANGE (PORT_PROTOCOL_TCP, 780, 783);
  RANGE (PORT_PROTOCOL_TCP, 786, 787);
  RANGE (PORT_PROTOCOL_TCP, 799, 801);
  RANGE (PORT_PROTOCOL_TCP, 808, 808);
  RANGE (PORT_PROTOCOL_TCP, 810, 810);
  RANGE (PORT_PROTOCOL_TCP, 828, 829);
  RANGE (PORT_PROTOCOL_TCP, 847, 848);
  RANGE (PORT_PROTOCOL_TCP, 860, 860);
  RANGE (PORT_PROTOCOL_TCP, 871, 871);
  RANGE (PORT_PROTOCOL_TCP, 873, 873);
  RANGE (PORT_PROTOCOL_TCP, 886, 888);
  RANGE (PORT_PROTOCOL_TCP, 898, 898);
  RANGE (PORT_PROTOCOL_TCP, 900, 904);
  RANGE (PORT_PROTOCOL_TCP, 911, 913);
  RANGE (PORT_PROTOCOL_TCP, 927, 927);
  RANGE (PORT_PROTOCOL_TCP, 950, 950);
  RANGE (PORT_PROTOCOL_TCP, 953, 953);
  RANGE (PORT_PROTOCOL_TCP, 975, 975);
  RANGE (PORT_PROTOCOL_TCP, 989, 1002);
  RANGE (PORT_PROTOCOL_TCP, 1005, 1005);
  RANGE (PORT_PROTOCOL_TCP, 1008, 1008);
  RANGE (PORT_PROTOCOL_TCP, 1010, 1010);
  RANGE (PORT_PROTOCOL_TCP, 1023, 1027);
  RANGE (PORT_PROTOCOL_TCP, 1029, 1036);
  RANGE (PORT_PROTOCOL_TCP, 1040, 1040);
  RANGE (PORT_PROTOCOL_TCP, 1042, 1042);
  RANGE (PORT_PROTOCOL_TCP, 1045, 1045);
  RANGE (PORT_PROTOCOL_TCP, 1047, 1112);
  RANGE (PORT_PROTOCOL_TCP, 1114, 1117);
  RANGE (PORT_PROTOCOL_TCP, 1119, 1120);
  RANGE (PORT_PROTOCOL_TCP, 1122, 1127);
  RANGE (PORT_PROTOCOL_TCP, 1139, 1139);
  RANGE (PORT_PROTOCOL_TCP, 1154, 1155);
  RANGE (PORT_PROTOCOL_TCP, 1161, 1162);
  RANGE (PORT_PROTOCOL_TCP, 1168, 1170);
  RANGE (PORT_PROTOCOL_TCP, 1178, 1178);
  RANGE (PORT_PROTOCOL_TCP, 1180, 1181);
  RANGE (PORT_PROTOCOL_TCP, 1183, 1188);
  RANGE (PORT_PROTOCOL_TCP, 1194, 1194);
  RANGE (PORT_PROTOCOL_TCP, 1199, 1231);
  RANGE (PORT_PROTOCOL_TCP, 1233, 1286);
  RANGE (PORT_PROTOCOL_TCP, 1288, 1774);
  RANGE (PORT_PROTOCOL_TCP, 1776, 2028);
  RANGE (PORT_PROTOCOL_TCP, 2030, 2030);
  RANGE (PORT_PROTOCOL_TCP, 2032, 2035);
  RANGE (PORT_PROTOCOL_TCP, 2037, 2038);
  RANGE (PORT_PROTOCOL_TCP, 2040, 2065);
  RANGE (PORT_PROTOCOL_TCP, 2067, 2083);
  RANGE (PORT_PROTOCOL_TCP, 2086, 2087);
  RANGE (PORT_PROTOCOL_TCP, 2089, 2152);
  RANGE (PORT_PROTOCOL_TCP, 2155, 2155);
  RANGE (PORT_PROTOCOL_TCP, 2159, 2167);
  RANGE (PORT_PROTOCOL_TCP, 2170, 2177);
  RANGE (PORT_PROTOCOL_TCP, 2180, 2181);
  RANGE (PORT_PROTOCOL_TCP, 2190, 2191);
  RANGE (PORT_PROTOCOL_TCP, 2199, 2202);
  RANGE (PORT_PROTOCOL_TCP, 2213, 2213);
  RANGE (PORT_PROTOCOL_TCP, 2220, 2223);
  RANGE (PORT_PROTOCOL_TCP, 2232, 2246);
  RANGE (PORT_PROTOCOL_TCP, 2248, 2255);
  RANGE (PORT_PROTOCOL_TCP, 2260, 2260);
  RANGE (PORT_PROTOCOL_TCP, 2273, 2273);
  RANGE (PORT_PROTOCOL_TCP, 2279, 2289);
  RANGE (PORT_PROTOCOL_TCP, 2294, 2311);
  RANGE (PORT_PROTOCOL_TCP, 2313, 2371);
  RANGE (PORT_PROTOCOL_TCP, 2381, 2425);
  RANGE (PORT_PROTOCOL_TCP, 2427, 2681);
  RANGE (PORT_PROTOCOL_TCP, 2683, 2824);
  RANGE (PORT_PROTOCOL_TCP, 2826, 2854);
  RANGE (PORT_PROTOCOL_TCP, 2856, 2924);
  RANGE (PORT_PROTOCOL_TCP, 2926, 3096);
  RANGE (PORT_PROTOCOL_TCP, 3098, 3299);
  RANGE (PORT_PROTOCOL_TCP, 3302, 3321);
  RANGE (PORT_PROTOCOL_TCP, 3326, 3366);
  RANGE (PORT_PROTOCOL_TCP, 3372, 3403);
  RANGE (PORT_PROTOCOL_TCP, 3405, 3545);
  RANGE (PORT_PROTOCOL_TCP, 3547, 3707);
  RANGE (PORT_PROTOCOL_TCP, 3709, 3765);
  RANGE (PORT_PROTOCOL_TCP, 3767, 3770);
  RANGE (PORT_PROTOCOL_TCP, 3772, 3800);
  RANGE (PORT_PROTOCOL_TCP, 3802, 3802);
  RANGE (PORT_PROTOCOL_TCP, 3845, 3871);
  RANGE (PORT_PROTOCOL_TCP, 3875, 3876);
  RANGE (PORT_PROTOCOL_TCP, 3885, 3885);
  RANGE (PORT_PROTOCOL_TCP, 3900, 3900);
  RANGE (PORT_PROTOCOL_TCP, 3928, 3929);
  RANGE (PORT_PROTOCOL_TCP, 3939, 3939);
  RANGE (PORT_PROTOCOL_TCP, 3959, 3959);
  RANGE (PORT_PROTOCOL_TCP, 3970, 3971);
  RANGE (PORT_PROTOCOL_TCP, 3984, 3987);
  RANGE (PORT_PROTOCOL_TCP, 3999, 4036);
  RANGE (PORT_PROTOCOL_TCP, 4040, 4042);
  RANGE (PORT_PROTOCOL_TCP, 4045, 4045);
  RANGE (PORT_PROTOCOL_TCP, 4080, 4080);
  RANGE (PORT_PROTOCOL_TCP, 4096, 4100);
  RANGE (PORT_PROTOCOL_TCP, 4111, 4111);
  RANGE (PORT_PROTOCOL_TCP, 4114, 4114);
  RANGE (PORT_PROTOCOL_TCP, 4132, 4134);
  RANGE (PORT_PROTOCOL_TCP, 4138, 4138);
  RANGE (PORT_PROTOCOL_TCP, 4141, 4145);
  RANGE (PORT_PROTOCOL_TCP, 4154, 4154);
  RANGE (PORT_PROTOCOL_TCP, 4160, 4160);
  RANGE (PORT_PROTOCOL_TCP, 4199, 4200);
  RANGE (PORT_PROTOCOL_TCP, 4242, 4242);
  RANGE (PORT_PROTOCOL_TCP, 4300, 4300);
  RANGE (PORT_PROTOCOL_TCP, 4321, 4321);
  RANGE (PORT_PROTOCOL_TCP, 4333, 4333);
  RANGE (PORT_PROTOCOL_TCP, 4343, 4351);
  RANGE (PORT_PROTOCOL_TCP, 4353, 4358);
  RANGE (PORT_PROTOCOL_TCP, 4369, 4369);
  RANGE (PORT_PROTOCOL_TCP, 4400, 4400);
  RANGE (PORT_PROTOCOL_TCP, 4442, 4457);
  RANGE (PORT_PROTOCOL_TCP, 4480, 4480);
  RANGE (PORT_PROTOCOL_TCP, 4500, 4500);
  RANGE (PORT_PROTOCOL_TCP, 4545, 4547);
  RANGE (PORT_PROTOCOL_TCP, 4555, 4555);
  RANGE (PORT_PROTOCOL_TCP, 4557, 4557);
  RANGE (PORT_PROTOCOL_TCP, 4559, 4559);
  RANGE (PORT_PROTOCOL_TCP, 4567, 4568);
  RANGE (PORT_PROTOCOL_TCP, 4600, 4601);
  RANGE (PORT_PROTOCOL_TCP, 4658, 4662);
  RANGE (PORT_PROTOCOL_TCP, 4672, 4672);
  RANGE (PORT_PROTOCOL_TCP, 4752, 4752);
  RANGE (PORT_PROTOCOL_TCP, 4800, 4802);
  RANGE (PORT_PROTOCOL_TCP, 4827, 4827);
  RANGE (PORT_PROTOCOL_TCP, 4837, 4839);
  RANGE (PORT_PROTOCOL_TCP, 4848, 4849);
  RANGE (PORT_PROTOCOL_TCP, 4868, 4869);
  RANGE (PORT_PROTOCOL_TCP, 4885, 4885);
  RANGE (PORT_PROTOCOL_TCP, 4894, 4894);
  RANGE (PORT_PROTOCOL_TCP, 4899, 4899);
  RANGE (PORT_PROTOCOL_TCP, 4950, 4950);
  RANGE (PORT_PROTOCOL_TCP, 4983, 4983);
  RANGE (PORT_PROTOCOL_TCP, 4987, 4989);
  RANGE (PORT_PROTOCOL_TCP, 4998, 4998);
  RANGE (PORT_PROTOCOL_TCP, 5000, 5011);
  RANGE (PORT_PROTOCOL_TCP, 5020, 5025);
  RANGE (PORT_PROTOCOL_TCP, 5031, 5031);
  RANGE (PORT_PROTOCOL_TCP, 5042, 5042);
  RANGE (PORT_PROTOCOL_TCP, 5050, 5057);
  RANGE (PORT_PROTOCOL_TCP, 5060, 5061);
  RANGE (PORT_PROTOCOL_TCP, 5064, 5066);
  RANGE (PORT_PROTOCOL_TCP, 5069, 5069);
  RANGE (PORT_PROTOCOL_TCP, 5071, 5071);
  RANGE (PORT_PROTOCOL_TCP, 5081, 5081);
  RANGE (PORT_PROTOCOL_TCP, 5093, 5093);
  RANGE (PORT_PROTOCOL_TCP, 5099, 5102);
  RANGE (PORT_PROTOCOL_TCP, 5137, 5137);
  RANGE (PORT_PROTOCOL_TCP, 5145, 5145);
  RANGE (PORT_PROTOCOL_TCP, 5150, 5152);
  RANGE (PORT_PROTOCOL_TCP, 5154, 5154);
  RANGE (PORT_PROTOCOL_TCP, 5165, 5165);
  RANGE (PORT_PROTOCOL_TCP, 5190, 5193);
  RANGE (PORT_PROTOCOL_TCP, 5200, 5203);
  RANGE (PORT_PROTOCOL_TCP, 5222, 5222);
  RANGE (PORT_PROTOCOL_TCP, 5225, 5226);
  RANGE (PORT_PROTOCOL_TCP, 5232, 5232);
  RANGE (PORT_PROTOCOL_TCP, 5236, 5236);
  RANGE (PORT_PROTOCOL_TCP, 5250, 5251);
  RANGE (PORT_PROTOCOL_TCP, 5264, 5265);
  RANGE (PORT_PROTOCOL_TCP, 5269, 5269);
  RANGE (PORT_PROTOCOL_TCP, 5272, 5272);
  RANGE (PORT_PROTOCOL_TCP, 5282, 5282);
  RANGE (PORT_PROTOCOL_TCP, 5300, 5311);
  RANGE (PORT_PROTOCOL_TCP, 5314, 5315);
  RANGE (PORT_PROTOCOL_TCP, 5351, 5355);
  RANGE (PORT_PROTOCOL_TCP, 5400, 5432);
  RANGE (PORT_PROTOCOL_TCP, 5435, 5435);
  RANGE (PORT_PROTOCOL_TCP, 5454, 5456);
  RANGE (PORT_PROTOCOL_TCP, 5461, 5463);
  RANGE (PORT_PROTOCOL_TCP, 5465, 5465);
  RANGE (PORT_PROTOCOL_TCP, 5500, 5504);
  RANGE (PORT_PROTOCOL_TCP, 5510, 5510);
  RANGE (PORT_PROTOCOL_TCP, 5520, 5521);
  RANGE (PORT_PROTOCOL_TCP, 5530, 5530);
  RANGE (PORT_PROTOCOL_TCP, 5540, 5540);
  RANGE (PORT_PROTOCOL_TCP, 5550, 5550);
  RANGE (PORT_PROTOCOL_TCP, 5553, 5556);
  RANGE (PORT_PROTOCOL_TCP, 5566, 5566);
  RANGE (PORT_PROTOCOL_TCP, 5569, 5569);
  RANGE (PORT_PROTOCOL_TCP, 5595, 5605);
  RANGE (PORT_PROTOCOL_TCP, 5631, 5632);
  RANGE (PORT_PROTOCOL_TCP, 5666, 5666);
  RANGE (PORT_PROTOCOL_TCP, 5673, 5680);
  RANGE (PORT_PROTOCOL_TCP, 5688, 5688);
  RANGE (PORT_PROTOCOL_TCP, 5690, 5690);
  RANGE (PORT_PROTOCOL_TCP, 5713, 5717);
  RANGE (PORT_PROTOCOL_TCP, 5720, 5720);
  RANGE (PORT_PROTOCOL_TCP, 5729, 5730);
  RANGE (PORT_PROTOCOL_TCP, 5741, 5742);
  RANGE (PORT_PROTOCOL_TCP, 5745, 5746);
  RANGE (PORT_PROTOCOL_TCP, 5755, 5755);
  RANGE (PORT_PROTOCOL_TCP, 5757, 5757);
  RANGE (PORT_PROTOCOL_TCP, 5766, 5768);
  RANGE (PORT_PROTOCOL_TCP, 5771, 5771);
  RANGE (PORT_PROTOCOL_TCP, 5800, 5803);
  RANGE (PORT_PROTOCOL_TCP, 5813, 5813);
  RANGE (PORT_PROTOCOL_TCP, 5858, 5859);
  RANGE (PORT_PROTOCOL_TCP, 5882, 5882);
  RANGE (PORT_PROTOCOL_TCP, 5888, 5889);
  RANGE (PORT_PROTOCOL_TCP, 5900, 5903);
  RANGE (PORT_PROTOCOL_TCP, 5968, 5969);
  RANGE (PORT_PROTOCOL_TCP, 5977, 5979);
  RANGE (PORT_PROTOCOL_TCP, 5987, 5991);
  RANGE (PORT_PROTOCOL_TCP, 5997, 6010);
  RANGE (PORT_PROTOCOL_TCP, 6050, 6051);
  RANGE (PORT_PROTOCOL_TCP, 6064, 6073);
  RANGE (PORT_PROTOCOL_TCP, 6085, 6085);
  RANGE (PORT_PROTOCOL_TCP, 6100, 6112);
  RANGE (PORT_PROTOCOL_TCP, 6123, 6123);
  RANGE (PORT_PROTOCOL_TCP, 6141, 6150);
  RANGE (PORT_PROTOCOL_TCP, 6175, 6177);
  RANGE (PORT_PROTOCOL_TCP, 6200, 6200);
  RANGE (PORT_PROTOCOL_TCP, 6253, 6253);
  RANGE (PORT_PROTOCOL_TCP, 6255, 6255);
  RANGE (PORT_PROTOCOL_TCP, 6270, 6270);
  RANGE (PORT_PROTOCOL_TCP, 6300, 6300);
  RANGE (PORT_PROTOCOL_TCP, 6321, 6322);
  RANGE (PORT_PROTOCOL_TCP, 6343, 6343);
  RANGE (PORT_PROTOCOL_TCP, 6346, 6347);
  RANGE (PORT_PROTOCOL_TCP, 6373, 6373);
  RANGE (PORT_PROTOCOL_TCP, 6382, 6382);
  RANGE (PORT_PROTOCOL_TCP, 6389, 6389);
  RANGE (PORT_PROTOCOL_TCP, 6400, 6400);
  RANGE (PORT_PROTOCOL_TCP, 6455, 6456);
  RANGE (PORT_PROTOCOL_TCP, 6471, 6471);
  RANGE (PORT_PROTOCOL_TCP, 6500, 6503);
  RANGE (PORT_PROTOCOL_TCP, 6505, 6510);
  RANGE (PORT_PROTOCOL_TCP, 6543, 6543);
  RANGE (PORT_PROTOCOL_TCP, 6547, 6550);
  RANGE (PORT_PROTOCOL_TCP, 6558, 6558);
  RANGE (PORT_PROTOCOL_TCP, 6566, 6566);
  RANGE (PORT_PROTOCOL_TCP, 6580, 6582);
  RANGE (PORT_PROTOCOL_TCP, 6588, 6588);
  RANGE (PORT_PROTOCOL_TCP, 6620, 6621);
  RANGE (PORT_PROTOCOL_TCP, 6623, 6623);
  RANGE (PORT_PROTOCOL_TCP, 6628, 6628);
  RANGE (PORT_PROTOCOL_TCP, 6631, 6631);
  RANGE (PORT_PROTOCOL_TCP, 6665, 6670);
  RANGE (PORT_PROTOCOL_TCP, 6672, 6673);
  RANGE (PORT_PROTOCOL_TCP, 6699, 6701);
  RANGE (PORT_PROTOCOL_TCP, 6714, 6714);
  RANGE (PORT_PROTOCOL_TCP, 6767, 6768);
  RANGE (PORT_PROTOCOL_TCP, 6776, 6776);
  RANGE (PORT_PROTOCOL_TCP, 6788, 6790);
  RANGE (PORT_PROTOCOL_TCP, 6831, 6831);
  RANGE (PORT_PROTOCOL_TCP, 6841, 6842);
  RANGE (PORT_PROTOCOL_TCP, 6850, 6850);
  RANGE (PORT_PROTOCOL_TCP, 6881, 6889);
  RANGE (PORT_PROTOCOL_TCP, 6891, 6891);
  RANGE (PORT_PROTOCOL_TCP, 6901, 6901);
  RANGE (PORT_PROTOCOL_TCP, 6939, 6939);
  RANGE (PORT_PROTOCOL_TCP, 6961, 6966);
  RANGE (PORT_PROTOCOL_TCP, 6969, 6970);
  RANGE (PORT_PROTOCOL_TCP, 6998, 7015);
  RANGE (PORT_PROTOCOL_TCP, 7020, 7021);
  RANGE (PORT_PROTOCOL_TCP, 7030, 7030);
  RANGE (PORT_PROTOCOL_TCP, 7070, 7070);
  RANGE (PORT_PROTOCOL_TCP, 7099, 7100);
  RANGE (PORT_PROTOCOL_TCP, 7121, 7121);
  RANGE (PORT_PROTOCOL_TCP, 7161, 7161);
  RANGE (PORT_PROTOCOL_TCP, 7170, 7170);
  RANGE (PORT_PROTOCOL_TCP, 7174, 7174);
  RANGE (PORT_PROTOCOL_TCP, 7200, 7201);
  RANGE (PORT_PROTOCOL_TCP, 7210, 7210);
  RANGE (PORT_PROTOCOL_TCP, 7269, 7269);
  RANGE (PORT_PROTOCOL_TCP, 7273, 7273);
  RANGE (PORT_PROTOCOL_TCP, 7280, 7281);
  RANGE (PORT_PROTOCOL_TCP, 7283, 7283);
  RANGE (PORT_PROTOCOL_TCP, 7300, 7300);
  RANGE (PORT_PROTOCOL_TCP, 7320, 7320);
  RANGE (PORT_PROTOCOL_TCP, 7326, 7326);
  RANGE (PORT_PROTOCOL_TCP, 7391, 7392);
  RANGE (PORT_PROTOCOL_TCP, 7395, 7395);
  RANGE (PORT_PROTOCOL_TCP, 7426, 7431);
  RANGE (PORT_PROTOCOL_TCP, 7437, 7437);
  RANGE (PORT_PROTOCOL_TCP, 7464, 7464);
  RANGE (PORT_PROTOCOL_TCP, 7491, 7491);
  RANGE (PORT_PROTOCOL_TCP, 7501, 7501);
  RANGE (PORT_PROTOCOL_TCP, 7510, 7511);
  RANGE (PORT_PROTOCOL_TCP, 7544, 7545);
  RANGE (PORT_PROTOCOL_TCP, 7560, 7560);
  RANGE (PORT_PROTOCOL_TCP, 7566, 7566);
  RANGE (PORT_PROTOCOL_TCP, 7570, 7570);
  RANGE (PORT_PROTOCOL_TCP, 7575, 7575);
  RANGE (PORT_PROTOCOL_TCP, 7588, 7588);
  RANGE (PORT_PROTOCOL_TCP, 7597, 7597);
  RANGE (PORT_PROTOCOL_TCP, 7624, 7624);
  RANGE (PORT_PROTOCOL_TCP, 7626, 7627);
  RANGE (PORT_PROTOCOL_TCP, 7633, 7634);
  RANGE (PORT_PROTOCOL_TCP, 7648, 7649);
  RANGE (PORT_PROTOCOL_TCP, 7666, 7666);
  RANGE (PORT_PROTOCOL_TCP, 7674, 7676);
  RANGE (PORT_PROTOCOL_TCP, 7743, 7743);
  RANGE (PORT_PROTOCOL_TCP, 7775, 7779);
  RANGE (PORT_PROTOCOL_TCP, 7781, 7781);
  RANGE (PORT_PROTOCOL_TCP, 7786, 7786);
  RANGE (PORT_PROTOCOL_TCP, 7797, 7798);
  RANGE (PORT_PROTOCOL_TCP, 7800, 7801);
  RANGE (PORT_PROTOCOL_TCP, 7845, 7846);
  RANGE (PORT_PROTOCOL_TCP, 7875, 7875);
  RANGE (PORT_PROTOCOL_TCP, 7902, 7902);
  RANGE (PORT_PROTOCOL_TCP, 7913, 7913);
  RANGE (PORT_PROTOCOL_TCP, 7932, 7933);
  RANGE (PORT_PROTOCOL_TCP, 7967, 7967);
  RANGE (PORT_PROTOCOL_TCP, 7979, 7980);
  RANGE (PORT_PROTOCOL_TCP, 7999, 8005);
  RANGE (PORT_PROTOCOL_TCP, 8007, 8010);
  RANGE (PORT_PROTOCOL_TCP, 8022, 8022);
  RANGE (PORT_PROTOCOL_TCP, 8032, 8033);
  RANGE (PORT_PROTOCOL_TCP, 8044, 8044);
  RANGE (PORT_PROTOCOL_TCP, 8074, 8074);
  RANGE (PORT_PROTOCOL_TCP, 8080, 8082);
  RANGE (PORT_PROTOCOL_TCP, 8088, 8089);
  RANGE (PORT_PROTOCOL_TCP, 8098, 8098);
  RANGE (PORT_PROTOCOL_TCP, 8100, 8100);
  RANGE (PORT_PROTOCOL_TCP, 8115, 8116);
  RANGE (PORT_PROTOCOL_TCP, 8118, 8118);
  RANGE (PORT_PROTOCOL_TCP, 8121, 8122);
  RANGE (PORT_PROTOCOL_TCP, 8130, 8132);
  RANGE (PORT_PROTOCOL_TCP, 8160, 8161);
  RANGE (PORT_PROTOCOL_TCP, 8181, 8194);
  RANGE (PORT_PROTOCOL_TCP, 8199, 8201);
  RANGE (PORT_PROTOCOL_TCP, 8204, 8208);
  RANGE (PORT_PROTOCOL_TCP, 8224, 8225);
  RANGE (PORT_PROTOCOL_TCP, 8245, 8245);
  RANGE (PORT_PROTOCOL_TCP, 8311, 8311);
  RANGE (PORT_PROTOCOL_TCP, 8351, 8351);
  RANGE (PORT_PROTOCOL_TCP, 8376, 8380);
  RANGE (PORT_PROTOCOL_TCP, 8400, 8403);
  RANGE (PORT_PROTOCOL_TCP, 8416, 8417);
  RANGE (PORT_PROTOCOL_TCP, 8431, 8431);
  RANGE (PORT_PROTOCOL_TCP, 8443, 8444);
  RANGE (PORT_PROTOCOL_TCP, 8450, 8450);
  RANGE (PORT_PROTOCOL_TCP, 8473, 8473);
  RANGE (PORT_PROTOCOL_TCP, 8554, 8555);
  RANGE (PORT_PROTOCOL_TCP, 8649, 8649);
  RANGE (PORT_PROTOCOL_TCP, 8733, 8733);
  RANGE (PORT_PROTOCOL_TCP, 8763, 8765);
  RANGE (PORT_PROTOCOL_TCP, 8786, 8787);
  RANGE (PORT_PROTOCOL_TCP, 8804, 8804);
  RANGE (PORT_PROTOCOL_TCP, 8863, 8864);
  RANGE (PORT_PROTOCOL_TCP, 8875, 8875);
  RANGE (PORT_PROTOCOL_TCP, 8880, 8880);
  RANGE (PORT_PROTOCOL_TCP, 8888, 8894);
  RANGE (PORT_PROTOCOL_TCP, 8900, 8901);
  RANGE (PORT_PROTOCOL_TCP, 8910, 8911);
  RANGE (PORT_PROTOCOL_TCP, 8954, 8954);
  RANGE (PORT_PROTOCOL_TCP, 8989, 8989);
  RANGE (PORT_PROTOCOL_TCP, 8999, 9002);
  RANGE (PORT_PROTOCOL_TCP, 9006, 9006);
  RANGE (PORT_PROTOCOL_TCP, 9009, 9009);
  RANGE (PORT_PROTOCOL_TCP, 9020, 9026);
  RANGE (PORT_PROTOCOL_TCP, 9080, 9080);
  RANGE (PORT_PROTOCOL_TCP, 9090, 9091);
  RANGE (PORT_PROTOCOL_TCP, 9100, 9103);
  RANGE (PORT_PROTOCOL_TCP, 9110, 9111);
  RANGE (PORT_PROTOCOL_TCP, 9131, 9131);
  RANGE (PORT_PROTOCOL_TCP, 9152, 9152);
  RANGE (PORT_PROTOCOL_TCP, 9160, 9164);
  RANGE (PORT_PROTOCOL_TCP, 9200, 9207);
  RANGE (PORT_PROTOCOL_TCP, 9210, 9211);
  RANGE (PORT_PROTOCOL_TCP, 9217, 9217);
  RANGE (PORT_PROTOCOL_TCP, 9281, 9285);
  RANGE (PORT_PROTOCOL_TCP, 9287, 9287);
  RANGE (PORT_PROTOCOL_TCP, 9292, 9292);
  RANGE (PORT_PROTOCOL_TCP, 9321, 9321);
  RANGE (PORT_PROTOCOL_TCP, 9343, 9344);
  RANGE (PORT_PROTOCOL_TCP, 9346, 9346);
  RANGE (PORT_PROTOCOL_TCP, 9374, 9374);
  RANGE (PORT_PROTOCOL_TCP, 9390, 9390);
  RANGE (PORT_PROTOCOL_TCP, 9396, 9397);
  RANGE (PORT_PROTOCOL_TCP, 9400, 9400);
  RANGE (PORT_PROTOCOL_TCP, 9418, 9418);
  RANGE (PORT_PROTOCOL_TCP, 9495, 9495);
  RANGE (PORT_PROTOCOL_TCP, 9500, 9500);
  RANGE (PORT_PROTOCOL_TCP, 9535, 9537);
  RANGE (PORT_PROTOCOL_TCP, 9593, 9595);
  RANGE (PORT_PROTOCOL_TCP, 9600, 9600);
  RANGE (PORT_PROTOCOL_TCP, 9612, 9612);
  RANGE (PORT_PROTOCOL_TCP, 9704, 9704);
  RANGE (PORT_PROTOCOL_TCP, 9747, 9747);
  RANGE (PORT_PROTOCOL_TCP, 9753, 9753);
  RANGE (PORT_PROTOCOL_TCP, 9797, 9797);
  RANGE (PORT_PROTOCOL_TCP, 9800, 9802);
  RANGE (PORT_PROTOCOL_TCP, 9872, 9872);
  RANGE (PORT_PROTOCOL_TCP, 9875, 9876);
  RANGE (PORT_PROTOCOL_TCP, 9888, 9889);
  RANGE (PORT_PROTOCOL_TCP, 9898, 9901);
  RANGE (PORT_PROTOCOL_TCP, 9909, 9909);
  RANGE (PORT_PROTOCOL_TCP, 9911, 9911);
  RANGE (PORT_PROTOCOL_TCP, 9950, 9952);
  RANGE (PORT_PROTOCOL_TCP, 9990, 10005);
  RANGE (PORT_PROTOCOL_TCP, 10007, 10008);
  RANGE (PORT_PROTOCOL_TCP, 10012, 10012);
  RANGE (PORT_PROTOCOL_TCP, 10080, 10083);
  RANGE (PORT_PROTOCOL_TCP, 10101, 10103);
  RANGE (PORT_PROTOCOL_TCP, 10113, 10116);
  RANGE (PORT_PROTOCOL_TCP, 10128, 10128);
  RANGE (PORT_PROTOCOL_TCP, 10252, 10252);
  RANGE (PORT_PROTOCOL_TCP, 10260, 10260);
  RANGE (PORT_PROTOCOL_TCP, 10288, 10288);
  RANGE (PORT_PROTOCOL_TCP, 10607, 10607);
  RANGE (PORT_PROTOCOL_TCP, 10666, 10666);
  RANGE (PORT_PROTOCOL_TCP, 10752, 10752);
  RANGE (PORT_PROTOCOL_TCP, 10990, 10990);
  RANGE (PORT_PROTOCOL_TCP, 11000, 11001);
  RANGE (PORT_PROTOCOL_TCP, 11111, 11111);
  RANGE (PORT_PROTOCOL_TCP, 11201, 11201);
  RANGE (PORT_PROTOCOL_TCP, 11223, 11223);
  RANGE (PORT_PROTOCOL_TCP, 11319, 11321);
  RANGE (PORT_PROTOCOL_TCP, 11367, 11367);
  RANGE (PORT_PROTOCOL_TCP, 11371, 11371);
  RANGE (PORT_PROTOCOL_TCP, 11600, 11600);
  RANGE (PORT_PROTOCOL_TCP, 11720, 11720);
  RANGE (PORT_PROTOCOL_TCP, 11751, 11751);
  RANGE (PORT_PROTOCOL_TCP, 11965, 11965);
  RANGE (PORT_PROTOCOL_TCP, 11967, 11967);
  RANGE (PORT_PROTOCOL_TCP, 11999, 12006);
  RANGE (PORT_PROTOCOL_TCP, 12076, 12076);
  RANGE (PORT_PROTOCOL_TCP, 12109, 12109);
  RANGE (PORT_PROTOCOL_TCP, 12168, 12168);
  RANGE (PORT_PROTOCOL_TCP, 12172, 12172);
  RANGE (PORT_PROTOCOL_TCP, 12223, 12223);
  RANGE (PORT_PROTOCOL_TCP, 12321, 12321);
  RANGE (PORT_PROTOCOL_TCP, 12345, 12346);
  RANGE (PORT_PROTOCOL_TCP, 12361, 12362);
  RANGE (PORT_PROTOCOL_TCP, 12468, 12468);
  RANGE (PORT_PROTOCOL_TCP, 12701, 12701);
  RANGE (PORT_PROTOCOL_TCP, 12753, 12753);
  RANGE (PORT_PROTOCOL_TCP, 13160, 13160);
  RANGE (PORT_PROTOCOL_TCP, 13223, 13224);
  RANGE (PORT_PROTOCOL_TCP, 13701, 13702);
  RANGE (PORT_PROTOCOL_TCP, 13705, 13706);
  RANGE (PORT_PROTOCOL_TCP, 13708, 13718);
  RANGE (PORT_PROTOCOL_TCP, 13720, 13722);
  RANGE (PORT_PROTOCOL_TCP, 13724, 13724);
  RANGE (PORT_PROTOCOL_TCP, 13782, 13783);
  RANGE (PORT_PROTOCOL_TCP, 13818, 13822);
  RANGE (PORT_PROTOCOL_TCP, 14001, 14001);
  RANGE (PORT_PROTOCOL_TCP, 14033, 14034);
  RANGE (PORT_PROTOCOL_TCP, 14141, 14141);
  RANGE (PORT_PROTOCOL_TCP, 14145, 14145);
  RANGE (PORT_PROTOCOL_TCP, 14149, 14149);
  RANGE (PORT_PROTOCOL_TCP, 14194, 14194);
  RANGE (PORT_PROTOCOL_TCP, 14237, 14237);
  RANGE (PORT_PROTOCOL_TCP, 14936, 14937);
  RANGE (PORT_PROTOCOL_TCP, 15000, 15000);
  RANGE (PORT_PROTOCOL_TCP, 15126, 15126);
  RANGE (PORT_PROTOCOL_TCP, 15345, 15345);
  RANGE (PORT_PROTOCOL_TCP, 15363, 15363);
  RANGE (PORT_PROTOCOL_TCP, 16360, 16361);
  RANGE (PORT_PROTOCOL_TCP, 16367, 16368);
  RANGE (PORT_PROTOCOL_TCP, 16384, 16384);
  RANGE (PORT_PROTOCOL_TCP, 16660, 16661);
  RANGE (PORT_PROTOCOL_TCP, 16959, 16959);
  RANGE (PORT_PROTOCOL_TCP, 16969, 16969);
  RANGE (PORT_PROTOCOL_TCP, 16991, 16991);
  RANGE (PORT_PROTOCOL_TCP, 17007, 17007);
  RANGE (PORT_PROTOCOL_TCP, 17185, 17185);
  RANGE (PORT_PROTOCOL_TCP, 17219, 17219);
  RANGE (PORT_PROTOCOL_TCP, 17300, 17300);
  RANGE (PORT_PROTOCOL_TCP, 17770, 17772);
  RANGE (PORT_PROTOCOL_TCP, 18000, 18000);
  RANGE (PORT_PROTOCOL_TCP, 18181, 18187);
  RANGE (PORT_PROTOCOL_TCP, 18190, 18190);
  RANGE (PORT_PROTOCOL_TCP, 18241, 18241);
  RANGE (PORT_PROTOCOL_TCP, 18463, 18463);
  RANGE (PORT_PROTOCOL_TCP, 18769, 18769);
  RANGE (PORT_PROTOCOL_TCP, 18888, 18888);
  RANGE (PORT_PROTOCOL_TCP, 19191, 19191);
  RANGE (PORT_PROTOCOL_TCP, 19194, 19194);
  RANGE (PORT_PROTOCOL_TCP, 19283, 19283);
  RANGE (PORT_PROTOCOL_TCP, 19315, 19315);
  RANGE (PORT_PROTOCOL_TCP, 19398, 19398);
  RANGE (PORT_PROTOCOL_TCP, 19410, 19412);
  RANGE (PORT_PROTOCOL_TCP, 19540, 19541);
  RANGE (PORT_PROTOCOL_TCP, 19638, 19638);
  RANGE (PORT_PROTOCOL_TCP, 19726, 19726);
  RANGE (PORT_PROTOCOL_TCP, 20000, 20001);
  RANGE (PORT_PROTOCOL_TCP, 20005, 20005);
  RANGE (PORT_PROTOCOL_TCP, 20011, 20012);
  RANGE (PORT_PROTOCOL_TCP, 20034, 20034);
  RANGE (PORT_PROTOCOL_TCP, 20200, 20200);
  RANGE (PORT_PROTOCOL_TCP, 20202, 20203);
  RANGE (PORT_PROTOCOL_TCP, 20222, 20222);
  RANGE (PORT_PROTOCOL_TCP, 20670, 20670);
  RANGE (PORT_PROTOCOL_TCP, 20999, 21000);
  RANGE (PORT_PROTOCOL_TCP, 21490, 21490);
  RANGE (PORT_PROTOCOL_TCP, 21544, 21544);
  RANGE (PORT_PROTOCOL_TCP, 21590, 21590);
  RANGE (PORT_PROTOCOL_TCP, 21800, 21800);
  RANGE (PORT_PROTOCOL_TCP, 21845, 21849);
  RANGE (PORT_PROTOCOL_TCP, 22000, 22001);
  RANGE (PORT_PROTOCOL_TCP, 22222, 22222);
  RANGE (PORT_PROTOCOL_TCP, 22273, 22273);
  RANGE (PORT_PROTOCOL_TCP, 22289, 22289);
  RANGE (PORT_PROTOCOL_TCP, 22305, 22305);
  RANGE (PORT_PROTOCOL_TCP, 22321, 22321);
  RANGE (PORT_PROTOCOL_TCP, 22370, 22370);
  RANGE (PORT_PROTOCOL_TCP, 22555, 22555);
  RANGE (PORT_PROTOCOL_TCP, 22800, 22800);
  RANGE (PORT_PROTOCOL_TCP, 22951, 22951);
  RANGE (PORT_PROTOCOL_TCP, 23456, 23456);
  RANGE (PORT_PROTOCOL_TCP, 24000, 24006);
  RANGE (PORT_PROTOCOL_TCP, 24242, 24242);
  RANGE (PORT_PROTOCOL_TCP, 24249, 24249);
  RANGE (PORT_PROTOCOL_TCP, 24345, 24347);
  RANGE (PORT_PROTOCOL_TCP, 24386, 24386);
  RANGE (PORT_PROTOCOL_TCP, 24554, 24554);
  RANGE (PORT_PROTOCOL_TCP, 24677, 24678);
  RANGE (PORT_PROTOCOL_TCP, 24922, 24922);
  RANGE (PORT_PROTOCOL_TCP, 25000, 25009);
  RANGE (PORT_PROTOCOL_TCP, 25378, 25378);
  RANGE (PORT_PROTOCOL_TCP, 25544, 25544);
  RANGE (PORT_PROTOCOL_TCP, 25793, 25793);
  RANGE (PORT_PROTOCOL_TCP, 25867, 25867);
  RANGE (PORT_PROTOCOL_TCP, 25901, 25901);
  RANGE (PORT_PROTOCOL_TCP, 25903, 25903);
  RANGE (PORT_PROTOCOL_TCP, 26000, 26000);
  RANGE (PORT_PROTOCOL_TCP, 26208, 26208);
  RANGE (PORT_PROTOCOL_TCP, 26260, 26264);
  RANGE (PORT_PROTOCOL_TCP, 27000, 27010);
  RANGE (PORT_PROTOCOL_TCP, 27345, 27345);
  RANGE (PORT_PROTOCOL_TCP, 27374, 27374);
  RANGE (PORT_PROTOCOL_TCP, 27504, 27504);
  RANGE (PORT_PROTOCOL_TCP, 27665, 27665);
  RANGE (PORT_PROTOCOL_TCP, 27999, 27999);
  RANGE (PORT_PROTOCOL_TCP, 28001, 28001);
  RANGE (PORT_PROTOCOL_TCP, 29559, 29559);
  RANGE (PORT_PROTOCOL_TCP, 29891, 29891);
  RANGE (PORT_PROTOCOL_TCP, 30001, 30002);
  RANGE (PORT_PROTOCOL_TCP, 30100, 30102);
  RANGE (PORT_PROTOCOL_TCP, 30303, 30303);
  RANGE (PORT_PROTOCOL_TCP, 30999, 30999);
  RANGE (PORT_PROTOCOL_TCP, 31337, 31337);
  RANGE (PORT_PROTOCOL_TCP, 31339, 31339);
  RANGE (PORT_PROTOCOL_TCP, 31416, 31416);
  RANGE (PORT_PROTOCOL_TCP, 31457, 31457);
  RANGE (PORT_PROTOCOL_TCP, 31554, 31554);
  RANGE (PORT_PROTOCOL_TCP, 31556, 31556);
  RANGE (PORT_PROTOCOL_TCP, 31620, 31620);
  RANGE (PORT_PROTOCOL_TCP, 31765, 31765);
  RANGE (PORT_PROTOCOL_TCP, 31785, 31787);
  RANGE (PORT_PROTOCOL_TCP, 32261, 32261);
  RANGE (PORT_PROTOCOL_TCP, 32666, 32666);
  RANGE (PORT_PROTOCOL_TCP, 32768, 32780);
  RANGE (PORT_PROTOCOL_TCP, 32786, 32787);
  RANGE (PORT_PROTOCOL_TCP, 32896, 32896);
  RANGE (PORT_PROTOCOL_TCP, 33270, 33270);
  RANGE (PORT_PROTOCOL_TCP, 33331, 33331);
  RANGE (PORT_PROTOCOL_TCP, 33434, 33434);
  RANGE (PORT_PROTOCOL_TCP, 33911, 33911);
  RANGE (PORT_PROTOCOL_TCP, 34249, 34249);
  RANGE (PORT_PROTOCOL_TCP, 34324, 34324);
  RANGE (PORT_PROTOCOL_TCP, 34952, 34952);
  RANGE (PORT_PROTOCOL_TCP, 36865, 36865);
  RANGE (PORT_PROTOCOL_TCP, 37475, 37475);
  RANGE (PORT_PROTOCOL_TCP, 37651, 37651);
  RANGE (PORT_PROTOCOL_TCP, 38037, 38037);
  RANGE (PORT_PROTOCOL_TCP, 38201, 38201);
  RANGE (PORT_PROTOCOL_TCP, 38292, 38293);
  RANGE (PORT_PROTOCOL_TCP, 39681, 39681);
  RANGE (PORT_PROTOCOL_TCP, 40412, 40412);
  RANGE (PORT_PROTOCOL_TCP, 40841, 40843);
  RANGE (PORT_PROTOCOL_TCP, 41111, 41111);
  RANGE (PORT_PROTOCOL_TCP, 41508, 41508);
  RANGE (PORT_PROTOCOL_TCP, 41794, 41795);
  RANGE (PORT_PROTOCOL_TCP, 42508, 42510);
  RANGE (PORT_PROTOCOL_TCP, 43118, 43118);
  RANGE (PORT_PROTOCOL_TCP, 43188, 43190);
  RANGE (PORT_PROTOCOL_TCP, 44321, 44322);
  RANGE (PORT_PROTOCOL_TCP, 44333, 44334);
  RANGE (PORT_PROTOCOL_TCP, 44442, 44443);
  RANGE (PORT_PROTOCOL_TCP, 44818, 44818);
  RANGE (PORT_PROTOCOL_TCP, 45000, 45000);
  RANGE (PORT_PROTOCOL_TCP, 45054, 45054);
  RANGE (PORT_PROTOCOL_TCP, 45678, 45678);
  RANGE (PORT_PROTOCOL_TCP, 45966, 45966);
  RANGE (PORT_PROTOCOL_TCP, 47000, 47000);
  RANGE (PORT_PROTOCOL_TCP, 47557, 47557);
  RANGE (PORT_PROTOCOL_TCP, 47624, 47624);
  RANGE (PORT_PROTOCOL_TCP, 47806, 47806);
  RANGE (PORT_PROTOCOL_TCP, 47808, 47808);
  RANGE (PORT_PROTOCOL_TCP, 47891, 47891);
  RANGE (PORT_PROTOCOL_TCP, 48000, 48003);
  RANGE (PORT_PROTOCOL_TCP, 48556, 48556);
  RANGE (PORT_PROTOCOL_TCP, 49400, 49400);
  RANGE (PORT_PROTOCOL_TCP, 50000, 50004);
  RANGE (PORT_PROTOCOL_TCP, 50505, 50505);
  RANGE (PORT_PROTOCOL_TCP, 50776, 50776);
  RANGE (PORT_PROTOCOL_TCP, 51210, 51210);
  RANGE (PORT_PROTOCOL_TCP, 53001, 53001);
  RANGE (PORT_PROTOCOL_TCP, 54320, 54321);
  RANGE (PORT_PROTOCOL_TCP, 57341, 57341);
  RANGE (PORT_PROTOCOL_TCP, 59595, 59595);
  RANGE (PORT_PROTOCOL_TCP, 60177, 60177);
  RANGE (PORT_PROTOCOL_TCP, 60179, 60179);
  RANGE (PORT_PROTOCOL_TCP, 61439, 61441);
  RANGE (PORT_PROTOCOL_TCP, 61446, 61446);
  RANGE (PORT_PROTOCOL_TCP, 65000, 65000);
  RANGE (PORT_PROTOCOL_TCP, 65301, 65301);
}

/**
 * @brief Find a port list given a UUID.
 *
 * @param[in]   uuid       UUID of port_list.
 * @param[out]  port_list  Port_List return, 0 if successfully failed to find
 *                         port_list.
 *
 * @return FALSE on success (including if failed to find port_list), TRUE on error.
 */
gboolean
find_port_list (const char* uuid, port_list_t* port_list)
{
  gchar *quoted_uuid = sql_quote (uuid);
  if (acl_user_owns_uuid ("port_list", quoted_uuid, 0) == 0)
    {
      g_free (quoted_uuid);
      *port_list = 0;
      return FALSE;
    }
  switch (sql_int64 (port_list,
                     "SELECT id FROM port_lists WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *port_list = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Find a port list given a UUID.
 *
 * This does not do any permission checks.
 *
 * @param[in]   uuid       UUID of resource.
 * @param[out]  port_list  Port list return, 0 if no such port list.
 *
 * @return FALSE on success (including if no such port list), TRUE on error.
 */
gboolean
find_port_list_no_acl (const char *uuid, port_list_t *port_list)
{
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  switch (sql_int64 (port_list,
                     "SELECT id FROM port_lists WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *port_list = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Find a port list for a specific permission, given a UUID.
 *
 * @param[in]   uuid        UUID of port list.
 * @param[out]  port_list   Port list return, 0 if successfully failed to find
 *                          port list.
 * @param[in]   permission  Permission.
 *
 * @return FALSE on success (including if failed to find port_list), TRUE on
 *         error.
 */
gboolean
find_port_list_with_permission (const char* uuid, port_list_t* port_list,
                                const char *permission)
{
  return find_resource_with_permission ("port_list", uuid, port_list,
                                        permission, 0);
}

/**
 * @brief Find a trash port list given a UUID.
 *
 * This does not do any permission checks.
 *
 * @param[in]   uuid        UUID of resource.
 * @param[out]  port_list   Port list return, 0 if no such port list.
 *
 * @return FALSE on success (including if no such port list), TRUE on error.
 */
gboolean
find_trash_port_list_no_acl (const char *uuid, port_list_t *port_list)
{
  gchar *quoted_uuid;

  quoted_uuid = sql_quote (uuid);
  switch (sql_int64 (port_list,
                     "SELECT id FROM port_lists_trash WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *port_list = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Return whether a port list is predefined.
 *
 * @param[in]  port_list  Port list.
 *
 * @return 1 if predefined, else 0.
 */
int
port_list_predefined (port_list_t port_list)
{
  return sql_int ("SELECT predefined FROM port_lists"
                  " WHERE id = %llu;",
                  port_list);
}

/**
 * @brief Return whether a trash port list is predefined.
 *
 * @param[in]  port_list  Port list.
 *
 * @return 1 if predefined, else 0.
 */
int
trash_port_list_predefined (port_list_t port_list)
{
  return sql_int ("SELECT predefined FROM port_lists_trash"
                  " WHERE id = %llu;",
                  port_list);
}

/**
 * @brief Return the UUID of the port list of a port_range.
 *
 * @param[in]  port_range  Port Range UUID.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
static char*
port_range_port_list_uuid (const char *port_range)
{
  gchar *quoted_port_range;
  char *ret;

  quoted_port_range = sql_quote (port_range);
  if (sql_int ("SELECT count (*) FROM port_ranges WHERE uuid = '%s';",
               quoted_port_range))
    ret = sql_string ("SELECT uuid FROM port_lists"
                      " WHERE id = (SELECT port_list FROM port_ranges"
                      "             WHERE uuid = '%s');",
                      quoted_port_range);
  else
    ret = NULL;
  g_free (quoted_port_range);
  return ret;
}

/**
 * @brief Find a port range given a UUID.
 *
 * @param[in]   uuid        UUID of port_range.
 * @param[out]  port_range  Port range return, 0 if successfully failed to find
 *                          port range.
 * @param[in]   permission  UUID of port_range.
 *
 * @return FALSE on success (including if failed to find port range), TRUE on
 *         error.
 */
static gboolean
find_port_range_with_permission (const char *uuid, port_range_t *port_range,
                                 const char *permission)
{
  char *port_list_uuid;
  gchar *quoted_uuid;
  port_list_t port_list;

  assert (current_credentials.uuid);

  *port_range = 0;

  if (uuid == NULL)
    return TRUE;

  port_list_uuid = port_range_port_list_uuid (uuid);
  if (port_list_uuid == NULL)
    return TRUE;

  if (find_port_list_with_permission (port_list_uuid, &port_list, permission)
      || port_list == 0)
    {
      g_free (port_list_uuid);
      return TRUE;
    }
  g_free (port_list_uuid);

  quoted_uuid = sql_quote (uuid);
  switch (sql_int64 (port_range,
                     "SELECT id FROM port_ranges WHERE uuid = '%s';",
                     quoted_uuid))
    {
      case 0:
        break;
      case 1:        /* Too few rows in result of query. */
        *port_range = 0;
        break;
      default:       /* Programming error. */
        assert (0);
      case -1:
        g_free (quoted_uuid);
        return TRUE;
        break;
    }

  g_free (quoted_uuid);
  return FALSE;
}

/**
 * @brief Compare two ranges by type then start.
 *
 * @param[in]  one  First range.
 * @param[in]  two  Second range.
 *
 * @return 0 equal, 1 one greater, -1 two greater.
 */
static int
range_compare (gconstpointer one, gconstpointer two)
{
  range_t *range_one, *range_two;

  range_one = *((range_t**) one);
  range_two = *((range_t**) two);

  if (range_one->type > range_two->type)
    return 1;

  if (range_one->type < range_two->type)
    return -1;

  if (range_one->start > range_two->start)
    return 1;

  if (range_one->start < range_two->start)
    return -1;

  return 0;
}

/**
 * @brief Sort and merge ranges.
 *
 * @param[in]  ranges  Array of port ranges of type range_t.
 */
static void
ranges_sort_merge (array_t *ranges)
{
  if (ranges->len > 1)
    {
      int index;
      range_t *last_range;

      /* Sort by type then start. */

      g_ptr_array_sort (ranges, range_compare);

      /* Merge overlaps. */

      last_range = (range_t*) g_ptr_array_index (ranges, 0);
      for (index = 1; index < ranges->len; )
        {
          range_t *range;

          range = (range_t*) g_ptr_array_index (ranges, index);
          if (range == NULL)
            break;

          if (range->type == last_range->type
              && range->start <= last_range->end)
            {
              if (range->end > last_range->end)
                last_range->end = range->end;
              /* This moves everything else up into the space. */
              g_ptr_array_remove_index (ranges, index);
            }
          else
            {
              index++;
              last_range = range;
            }
        }
    }
}

/**
 * @brief Create a port list, with database locked.
 *
 * Caller must lock the database.
 *
 * @param[in]   quoted_id       SQL quoted UUID, or NULL.
 * @param[in]   quoted_name     SQL quoted name of port list.
 * @param[in]   comment         Comment on port list.
 * @param[in]   ranges          Port ranges of port list.
 * @param[in]   predefined      Whether port list is predefined.
 * @param[out]  port_list       Created port list.
 *
 * @return 0 success.
 */
static int
create_port_list_lock (const char *quoted_id, const char *quoted_name,
                       const char *comment, array_t *ranges, int predefined,
                       port_list_t* port_list)
{
  gchar *quoted_comment;
  range_t *range;
  int index;

  assert (comment);

  quoted_comment = sql_quote (comment);
  if (quoted_id)
    sql ("INSERT INTO port_lists"
         " (uuid, owner, name, comment, predefined, creation_time,"
         "  modification_time)"
         " VALUES"
         " ('%s', (SELECT id FROM users WHERE uuid = '%s'), '%s',"
         "  '%s', %i, m_now (), m_now ());",
         quoted_id,
         current_credentials.uuid,
         quoted_name,
         quoted_comment,
         predefined);
  else
    sql ("INSERT INTO port_lists"
         " (uuid, owner, name, comment, predefined, creation_time,"
         "  modification_time)"
         " VALUES"
         " (make_uuid (), (SELECT id FROM users WHERE uuid = '%s'), '%s',"
         "  '%s', %i, m_now (), m_now ());",
         current_credentials.uuid,
         quoted_name,
         quoted_comment,
         predefined);
  g_free (quoted_comment);

  *port_list = sql_last_insert_id ();

  ranges_sort_merge (ranges);
  array_terminate (ranges);
  index = 0;
  while ((range = (range_t*) g_ptr_array_index (ranges, index++)))
    sql ("INSERT INTO port_ranges"
         " (uuid, port_list, type, start, \"end\", comment, exclude)"
         " VALUES"
         " (make_uuid (), %llu, %i, %i, %i, '', %i);",
         *port_list,
         range->type,
         range->start,
         range->end,
         range->exclude);
  return 0;
}

/**
 * @brief Create a port list having a unique name.
 *
 * Caller must provide transaction.
 *
 * @param[in]   name            Name of port list.
 * @param[in]   comment         Comment on port list.
 * @param[in]   port_range      GMP style port range list.
 * @param[out]  port_list       Created port list.
 *
 * @return 0 success, 4 error in port range.
 */
int
create_port_list_unique (const char *name, const char *comment,
                         const char* port_range, port_list_t* port_list)
{
  gchar *quoted_name;
  array_t *ranges;
  int suffix, ret;

  assert (current_credentials.uuid);

  if (validate_port_range (port_range))
    return 4;

  ranges = port_range_ranges (port_range);

  /* Check whether a port list with the same name exists already. */
  suffix = 1;
  quoted_name = sql_quote (name);
  while (resource_with_name_exists (quoted_name, "port_list", 0))
    {
      gchar *new_name;
      new_name = g_strdup_printf ("%s %i", name, suffix);
      g_free (quoted_name);
      quoted_name = sql_quote (new_name);
      g_free (new_name);
      suffix++;
    }

  ret = create_port_list_lock (NULL, quoted_name, comment, ranges, 0,
                               port_list);

  array_free (ranges);

  return ret;
}

/**
 * @brief Create a port list.
 *
 * @param[in]   check_access      Whether to check for create_config permission.
 * @param[in]   id                ID of port list.  Only used with \p ranges.
 * @param[in]   name              Name of port list.
 * @param[in]   comment           Comment on port list.
 * @param[in]   port_ranges       GMP port range string.
 * @param[in]   ranges            Array of port ranges of type range_t.
 *                                Overrides port_ranges.
 * @param[in]   predefined        Whether port list is predefined.
 * @param[out]  port_list_return  Created port list.
 *
 * @return 0 success, 1 port list exists already, 4 error in port_ranges,
 *         99 permission denied, -1 error.
 */
static int
create_port_list_internal (int check_access, const char *id, const char *name,
                           const char *comment, const char *port_ranges,
                           array_t *ranges, int predefined,
                           port_list_t *port_list_return)
{
  port_list_t port_list;
  int ret;

  assert (current_credentials.uuid);

  if (ranges)
    {
      int suffix;
      gchar *quoted_name, *quoted_id;

      if (id == NULL)
        return -1;

      sql_begin_immediate ();

      if (check_access && acl_user_may ("create_port_list") == 0)
        {
          sql_rollback ();
          return 99;
        }

      /* Check whether this port list exists already. */

      quoted_id = sql_quote (id);
      if (sql_int ("SELECT COUNT(*) FROM port_lists"
                   " WHERE uuid = '%s';",
                   quoted_id))
        {
          g_free (quoted_id);
          sql_rollback ();
          return 1;
        }

      if (sql_int ("SELECT COUNT(*) FROM port_lists_trash"
                   " WHERE uuid = '%s';",
                   quoted_id))
        {
          g_free (quoted_id);
          sql_rollback ();
          return 2;
        }

      /* Ensure the name is unique. */
      quoted_name = sql_quote (name);
      suffix = 1;
      while (resource_with_name_exists (quoted_name, "port_list", 0))
        {
          gchar *new_name;
          g_free (quoted_name);
          new_name = g_strdup_printf ("%s %i", name, suffix++);
          quoted_name = sql_quote (new_name);
          g_free (new_name);
        }

      ret = create_port_list_lock (quoted_id, quoted_name,
                                   comment ? comment : "", ranges, predefined,
                                   &port_list);
      g_free (quoted_name);
      if (ret)
        {
          sql_rollback ();
          return ret;
        }

      if (port_list_return)
        *port_list_return = port_list;

      sql_commit ();
      return 0;
    }

  if (port_ranges == NULL)
    port_ranges = "default";

  if (validate_port_range (port_ranges))
    return 4;

  sql_begin_immediate ();

  if (check_access && acl_user_may ("create_port_list") == 0)
    {
      sql_rollback ();
      return 99;
    }


  /* Check whether a port_list with the same name exists already. */
  if (resource_with_name_exists (name, "port_list", 0))
    {
      sql_rollback ();
      return 1;
    }

  if (port_ranges == NULL || (strcmp (port_ranges, "default") == 0))
    {
      gchar *quoted_comment, *quoted_name;

      quoted_name = sql_quote (name);
      quoted_comment = sql_quote (comment ? comment : "");
      sql ("INSERT INTO port_lists"
           " (uuid, owner, name, comment, predefined, creation_time,"
           "  modification_time)"
           " VALUES"
           " (make_uuid (), (SELECT id FROM users WHERE uuid = '%s'), '%s',"
           "  '%s', %i, m_now (), m_now ());",
           current_credentials.uuid,
           quoted_name,
           quoted_comment,
           predefined);
      g_free (quoted_comment);
      g_free (quoted_name);

      port_list = sql_last_insert_id ();
      make_port_ranges_openvas_default (port_list);
    }
  else
    {
      gchar *quoted_name;

      quoted_name = sql_quote (name);

      ranges = port_range_ranges (port_ranges);
      ret = create_port_list_lock (NULL, quoted_name, comment ? comment : "",
                                   ranges, predefined, &port_list);

      g_free (quoted_name);
      array_free (ranges);
      if (ret)
        {
          sql_rollback ();
          return ret;
        }
    }

  if (port_list_return)
    *port_list_return = port_list;

  sql_commit ();

  return 0;
}

/**
 * @brief Create a port list.
 *
 * @param[in]   id                ID of port list.  Only used with \p ranges.
 * @param[in]   name              Name of port list.
 * @param[in]   comment           Comment on port list.
 * @param[in]   port_ranges       GMP port range string.
 * @param[in]   ranges            Array of port ranges of type range_t.
 *                                Overrides port_ranges.
 * @param[out]  port_list_return  Created port list.
 *
 * @return 0 success, 1 port list exists already, 4 error in port_ranges,
 *         99 permission denied, -1 error.
 */
int
create_port_list (const char *id, const char *name, const char *comment,
                  const char *port_ranges, array_t *ranges,
                  port_list_t *port_list_return)
{
  return create_port_list_internal (1, id, name, comment, port_ranges, ranges,
                                    0, /* Predefined. */
                                    port_list_return);
}

/**
 * @brief Create a port list.
 *
 * @param[in]   id                ID of port list.  Only used with \p ranges.
 * @param[in]   name              Name of port list.
 * @param[in]   comment           Comment on port list.
 * @param[in]   port_ranges       GMP port range string.
 * @param[in]   ranges            Array of port ranges of type range_t.
 *                                Overrides port_ranges.
 * @param[out]  port_list_return  Created port list.
 *
 * @return 0 success, 1 port list exists already, 4 error in port_ranges,
 *         99 permission denied, -1 error.
 */
int
create_port_list_no_acl (const char *id, const char *name, const char *comment,
                         const char *port_ranges, array_t *ranges,
                         port_list_t *port_list_return)
{
  return create_port_list_internal (0, id, name, comment, port_ranges, ranges,
                                    1, /* Predefined. */
                                    port_list_return);
}

/**
 * @brief Create Port List from an existing Port List.
 *
 * @param[in]  name             Name of new Port List. NULL to copy from
 *                              existing.
 * @param[in]  comment          Comment on new Port List. NULL to copy from
 *                              existing.
 * @param[in]  port_list_id     UUID of existing Port List.
 * @param[out] new_port_list    New Port List.
 *
 * @return 0 success, 1 Port List exists already, 2 failed to find existing
 *         Port List, 99 permission denied, -1 error.
 */
int
copy_port_list (const char* name, const char* comment,
                const char* port_list_id, port_list_t* new_port_list)
{
  int ret;
  port_list_t new, old;

  sql_begin_immediate ();

  ret = copy_resource_lock ("port_list", name, comment, port_list_id, NULL, 1,
                            &new, &old);
  if (ret)
    {
      sql_rollback ();
      return ret;
    }

  sql ("UPDATE port_lists SET predefined = 0 WHERE id = %llu;", new);

  /* Copy port ranges. */

  sql ("INSERT INTO port_ranges "
       " (uuid, port_list, type, start, \"end\", comment, exclude)"
       " SELECT make_uuid(), %llu, type, start, \"end\", comment, exclude"
       "  FROM port_ranges WHERE port_list = %llu;",
       new,
       old);

  sql_commit ();
  if (new_port_list) *new_port_list = new;
  return 0;
}

/**
 * @brief Return whether a port list is predefined.
 *
 * @param[in]  port_list_id  UUID of port list.
 *
 * @return 1 if predefined, else 0.
 */
static int
port_list_predefined_uuid (const gchar *port_list_id)
{
  port_list_t port_list;

  if (find_port_list_no_acl (port_list_id, &port_list)
      || port_list == 0)
    return 0;

  return port_list_predefined (port_list);
}

/**
 * @brief Modify a Port List.
 *
 * @param[in]   port_list_id    UUID of Port List.
 * @param[in]   name            Name of Port List.
 * @param[in]   comment         Comment on Port List.
 *
 * @return 0 success, 1 failed to find port list, 2 port list with new name,
 *         exists, 3 port_list_id required, 99 permission denied, -1 internal
 *         error.
 */
int
modify_port_list (const char *port_list_id, const char *name,
                  const char *comment)
{
  gchar *quoted_name, *quoted_comment;
  port_list_t port_list;

  if (port_list_id == NULL)
    return 3;

  sql_begin_immediate ();

  assert (current_credentials.uuid);

  if (acl_user_may ("modify_port_list") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (port_list_predefined_uuid (port_list_id))
    {
      sql_rollback ();
      return 99;
    }

  port_list = 0;
  if (find_port_list_with_permission (port_list_id, &port_list,
                                      "modify_port_list"))
    {
      sql_rollback ();
      return -1;
    }

  if (port_list == 0)
    {
      sql_rollback ();
      return 1;
    }

  /* Check whether a Port List with the same name exists already. */
  if (name)
    {
      if (resource_with_name_exists (name, "port_list", port_list))
        {
          sql_rollback ();
          return 2;
        }
    }

  quoted_name = sql_quote (name ?: "");
  quoted_comment = sql_quote (comment ?: "");

  sql ("UPDATE port_lists SET"
       " name = '%s',"
       " comment = '%s',"
       " modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_name,
       quoted_comment,
       port_list);

  g_free (quoted_comment);
  g_free (quoted_name);

  sql_commit ();

  return 0;
}

/**
 * @brief Create a port range in a port list.
 *
 * @param[in]   port_list_id      Port list UUID.
 * @param[in]   type              Type.
 * @param[in]   start             Start port.
 * @param[in]   end               End port.
 * @param[in]   comment           Comment.
 * @param[out]  port_range_return  Created port range.
 *
 * @return 0 success, 1 syntax error in start, 2 syntax error in end, 3 failed
 *         to find port list, 4 syntax error in type, 5 port list in use,
 *         6 new range overlaps an existing range, 99 permission denied,
 *         -1 error.
 */
int
create_port_range (const char *port_list_id, const char *type,
                   const char *start, const char *end, const char *comment,
                   port_range_t *port_range_return)
{
  int first, last;
  port_list_t port_list;
  port_protocol_t port_type;
  gchar *quoted_comment;

  first = atoi (start);
  if (first < 1 || first > 65535)
    return 1;

  last = atoi (end);
  if (last < 1 || last > 65535)
    return 2;

  if (strcasecmp (type, "TCP") == 0)
    port_type = PORT_PROTOCOL_TCP;
  else if (strcasecmp (type, "UDP") == 0)
    port_type = PORT_PROTOCOL_UDP;
  else
    return 4;

  if (last < first)
    {
      int tem;
      tem = first;
      first = last;
      last = tem;
    }

  sql_begin_immediate ();

  if (acl_user_may ("create_port_range") == 0)
    {
      sql_rollback ();
      return 99;
    }

  port_list = 0;

  if (find_port_list (port_list_id, &port_list))
    {
      sql_rollback ();
      return -1;
    }

  if (port_list == 0)
    {
      sql_rollback ();
      return 3;
    }

  if (port_list_in_use (port_list))
    {
      sql_rollback ();
      return 5;
    }

  if (sql_int ("SELECT count (*) FROM port_ranges"
               " WHERE port_list = %llu"
               " AND type = %i"
               " AND ((start <= %i AND \"end\" >= %i)"
               "      OR (start <= %i AND \"end\" >= %i)"
               "      OR (start >= %i AND start <= %i)"
               "      OR (\"end\" >= %i AND \"end\" <= %i))",
               port_list,
               port_type,
               first,
               first,
               last,
               last,
               first,
               last,
               first,
               last))
    {
      sql_rollback ();
      return 6;
    }

  quoted_comment = comment ? sql_quote (comment) : g_strdup ("");
  sql ("INSERT INTO port_ranges"
       " (uuid, port_list, type, start, \"end\", comment, exclude)"
       " VALUES"
       " (make_uuid (), %llu, %i, %i, %i, '', 0);",
       port_list, port_type, first, last, quoted_comment);
  g_free (quoted_comment);

  if (port_range_return)
    *port_range_return = sql_last_insert_id ();

  sql_commit ();

  return 0;
}

/**
 * @brief Delete a port list.
 *
 * @param[in]  port_list_id  UUID of port_list.
 * @param[in]  ultimate      Whether to remove entirely, or to trashcan.
 *
 * @return 0 success, 1 fail because a target refers to the port list, 2 failed
 *         to find port list, 99 permission denied, -1 error.
 */
int
delete_port_list (const char *port_list_id, int ultimate)
{
  port_list_t port_list = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_port_list") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_port_list_with_permission (port_list_id, &port_list,
                                      "delete_port_list"))
    {
      sql_rollback ();
      return -1;
    }

  if (port_list == 0)
    {
      if (find_trash ("port_list", port_list_id, &port_list))
        {
          sql_rollback ();
          return -1;
        }
      if (port_list == 0)
        {
          sql_rollback ();
          return 2;
        }
      if (ultimate == 0)
        {
          /* It's already in the trashcan. */
          sql_commit ();
          return 0;
        }

      /* Check if it's in use by a target in the trashcan. */
      if (sql_int ("SELECT count(*) FROM targets_trash"
                   " WHERE port_list = %llu"
                   " AND port_list_location"
                   " = " G_STRINGIFY (LOCATION_TRASH) ";",
                   port_list))
        {
          sql_rollback ();
          return 1;
        }

      permissions_set_orphans ("port_list", port_list, LOCATION_TRASH);
      tags_remove_resource ("port_list", port_list, LOCATION_TRASH);

      sql ("DELETE FROM port_ranges_trash WHERE port_list = %llu;", port_list);
      sql ("DELETE FROM port_lists_trash WHERE id = %llu;", port_list);
      sql_commit ();
      return 0;
    }

  if (sql_int ("SELECT count(*) FROM targets"
               " WHERE port_list = %llu;",
               port_list))
    {
      sql_rollback ();
      return 1;
    }

  if (ultimate == 0)
    {
      port_list_t trash_port_list;

      sql ("INSERT INTO port_lists_trash"
           " (uuid, owner, name, comment, predefined, creation_time,"
           "  modification_time)"
           " SELECT uuid, owner, name, comment, predefined, creation_time,"
           "        modification_time"
           " FROM port_lists WHERE id = %llu;",
           port_list);

      trash_port_list = sql_last_insert_id ();

      sql ("INSERT INTO port_ranges_trash"
           " (uuid, port_list, type, start, \"end\", comment, exclude)"
           " SELECT uuid, %llu, type, start, \"end\", comment, exclude"
           " FROM port_ranges WHERE port_list = %llu;",
           trash_port_list,
           port_list);

      /* Update the location of the port_list in any trashcan targets. */
      sql ("UPDATE targets_trash"
           " SET port_list = %llu,"
           "     port_list_location = " G_STRINGIFY (LOCATION_TRASH)
           " WHERE port_list = %llu"
           " AND port_list_location = " G_STRINGIFY (LOCATION_TABLE) ";",
           trash_port_list,
           port_list);

      permissions_set_locations ("port_list", port_list, trash_port_list,
                                 LOCATION_TRASH);
      tags_set_locations ("port_list", port_list, trash_port_list,
                          LOCATION_TRASH);
    }
  else
    {
      permissions_set_orphans ("port_list", port_list, LOCATION_TABLE);
      tags_remove_resource ("port_list", port_list, LOCATION_TABLE);
    }

  sql ("DELETE FROM port_ranges WHERE port_list = %llu;", port_list);
  sql ("DELETE FROM port_lists WHERE id = %llu;", port_list);

  sql_commit ();
  return 0;
}

/**
 * @brief Create a port range.
 *
 * @param[in]  port_list   Port list to insert into.
 * @param[in]  type        Protocol: PORT_PROTOCOL_UDP or PORT_PROTOCOL_TCP.
 * @param[in]  start       Start of range.
 * @param[in]  end         End of range.
 */
void
insert_port_range (port_list_t port_list, port_protocol_t type, int start,
                   int end)
{
  sql ("INSERT INTO port_ranges"
       " (uuid, port_list, type, start, \"end\", comment, exclude)"
       " VALUES"
       " (make_uuid (), %llu, %i, '%i', '%i', '', 0);",
       port_list,
       type,
       start,
       end);
}

/**
 * @brief Delete a port range.
 *
 * @param[in]  port_range_id  UUID of port_range.
 * @param[in]  dummy          Dummy arg to match other delete functions.
 *
 * @return 0 success, 2 failed to find port range, 99 permission denied,
 *         -1 error.
 */
int
delete_port_range (const char *port_range_id, int dummy)
{
  port_range_t port_range = 0;

  sql_begin_immediate ();

  if (acl_user_may ("delete_port_range") == 0)
    {
      sql_rollback ();
      return 99;
    }

  if (find_port_range_with_permission (port_range_id, &port_range,
                                       "delete_port_range"))
    {
      sql_rollback ();
      return -1;
    }

  if (port_range == 0)
    {
      sql_rollback ();
      return 2;
    }

  sql ("DELETE FROM port_ranges WHERE id = %llu;", port_range);

  sql_commit ();
  return 0;
}

/**
 * @brief Filter columns for Port List iterator.
 */
#define PORT_LIST_ITERATOR_FILTER_COLUMNS                                    \
 { GET_ITERATOR_FILTER_COLUMNS,  "total", "tcp", "udp", "predefined", NULL }

/**
 * @brief Port List iterator columns.
 */
#define PORT_LIST_ITERATOR_COLUMNS                                 \
 {                                                                 \
   GET_ITERATOR_COLUMNS (port_lists),                              \
   {                                                               \
     /* COUNT ALL ports */                                         \
     "(SELECT"                                                     \
     " sum ((CASE"                                                 \
     "       WHEN \"end\" IS NULL THEN start ELSE \"end\""         \
     "       END)"                                                 \
     "      - start"                                               \
     "      + 1)"                                                  \
     " FROM port_ranges WHERE port_list = port_lists.id)",         \
     "total",                                                      \
     KEYWORD_TYPE_INTEGER                                          \
   },                                                              \
   {                                                               \
     /* COUNT TCP ports */                                         \
     "(SELECT"                                                     \
     " sum ((CASE"                                                 \
     "       WHEN \"end\" IS NULL THEN start ELSE \"end\""         \
     "       END)"                                                 \
     "      - start"                                               \
     "      + 1)"                                                  \
     " FROM port_ranges WHERE port_list = port_lists.id"           \
     "                  AND   type = 0)",                          \
     "tcp",                                                        \
     KEYWORD_TYPE_INTEGER                                          \
   },                                                              \
   {                                                               \
     /* COUNT UDP ports */                                         \
     "(SELECT"                                                     \
     " sum ((CASE"                                                 \
     "       WHEN \"end\" IS NULL THEN start ELSE \"end\""         \
     "       END)"                                                 \
     "      - start"                                               \
     "      + 1)"                                                  \
     " FROM port_ranges WHERE port_list = port_lists.id"           \
     "                  AND   type = 1)",                          \
     "udp",                                                        \
     KEYWORD_TYPE_INTEGER                                          \
   },                                                              \
   { "predefined", NULL, KEYWORD_TYPE_INTEGER },                   \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                            \
 }

/**
 * @brief Port List iterator columns for trash case.
 */
#define PORT_LIST_ITERATOR_TRASH_COLUMNS                           \
 {                                                                 \
   GET_ITERATOR_COLUMNS (port_lists_trash),                        \
   {                                                               \
     /* COUNT ALL ports */                                         \
     "(SELECT"                                                     \
     " sum ((CASE"                                                 \
     "       WHEN \"end\" IS NULL THEN start ELSE \"end\""         \
     "       END)"                                                 \
     "      - start"                                               \
     "      + 1)"                                                  \
     " FROM port_ranges_trash"                                     \
     " WHERE port_list = port_lists_trash.id)",                    \
     "total",                                                      \
     KEYWORD_TYPE_INTEGER                                          \
   },                                                              \
   {                                                               \
     /* COUNT TCP ports */                                         \
     "(SELECT"                                                     \
     " sum ((CASE"                                                 \
     "       WHEN \"end\" IS NULL THEN start ELSE \"end\""         \
     "       END)"                                                 \
     "      - start"                                               \
     "      + 1)"                                                  \
     " FROM port_ranges_trash"                                     \
     " WHERE port_list = port_lists_trash.id AND type = 0)",       \
     "tcp",                                                        \
     KEYWORD_TYPE_INTEGER                                          \
   },                                                              \
   {                                                               \
     /* COUNT UDP ports */                                         \
     "(SELECT"                                                     \
     " sum ((CASE"                                                 \
     "       WHEN \"end\" IS NULL THEN start ELSE \"end\""         \
     "       END)"                                                 \
     "      - start"                                               \
     "      + 1)"                                                  \
     " FROM port_ranges_trash"                                     \
     " WHERE port_list = port_lists_trash.id AND type = 1)",       \
     "udp",                                                        \
     KEYWORD_TYPE_INTEGER                                          \
   },                                                              \
   { "predefined", NULL, KEYWORD_TYPE_INTEGER },                   \
   { NULL, NULL, KEYWORD_TYPE_UNKNOWN }                            \
 }

/**
 * @brief Get filter columns.
 *
 * @return Constant array of filter columns.
 */
const char**
port_list_filter_columns ()
{
  static const char *columns[] = PORT_LIST_ITERATOR_FILTER_COLUMNS;
  return columns;
}

/**
 * @brief Get select columns.
 *
 * @return Constant array of select columns.
 */
column_t*
port_list_select_columns ()
{
  static column_t columns[] = PORT_LIST_ITERATOR_COLUMNS;
  return columns;
}

/**
 * @brief Count the number of Port Lists.
 *
 * @param[in]  get  GET params.
 *
 * @return Total number of Port Lists filtered set.
 */
int
port_list_count (const get_data_t *get)
{
  static const char *filter_columns[] = PORT_LIST_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = PORT_LIST_ITERATOR_COLUMNS;
  static column_t trash_columns[] = PORT_LIST_ITERATOR_TRASH_COLUMNS;

  return count ("port_list", get, columns, trash_columns, filter_columns,
                  0, 0, 0, TRUE);
}

/**
 * @brief Initialise a Port List  iterator, including observed Port Lists.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  get         GET data.
 *
 * @return 0 success, 1 failed to find Port List, 2 failed to find filter,
 *         -1 error.
 */
int
init_port_list_iterator (iterator_t* iterator, const get_data_t *get)
{
  static const char *filter_columns[] = PORT_LIST_ITERATOR_FILTER_COLUMNS;
  static column_t columns[] = PORT_LIST_ITERATOR_COLUMNS;
  static column_t trash_columns[] = PORT_LIST_ITERATOR_TRASH_COLUMNS;

  return init_get_iterator (iterator,
                            "port_list",
                            get,
                            columns,
                            trash_columns,
                            filter_columns,
                            0,
                            NULL,
                            NULL,
                            TRUE);
}

/**
 * @brief Get the port count from a port_list iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return Port count.
 */
int
port_list_iterator_count_all (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT);
}

/**
 * @brief Get the TCP port count from a port_list iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return TCP port count.
 */
int
port_list_iterator_count_tcp (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 1);
}

/**
 * @brief Get the UDP port count from a port_list iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return UDP port count.
 */
int
port_list_iterator_count_udp (iterator_t* iterator)
{
  if (iterator->done) return -1;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 2);
}

/**
 * @brief Get predefined status from a port_list iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if predefined, else 0.
 */
int
port_list_iterator_predefined (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, GET_ITERATOR_COLUMN_COUNT + 3);
}

/**
 * @brief Return the UUID of a port_list.
 *
 * @param[in]  port_list  Port_List.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
port_list_uuid (port_list_t port_list)
{
  return sql_string ("SELECT uuid FROM port_lists WHERE id = %llu;",
                     port_list);
}

/**
 * @brief Return the UUID of a port_range.
 *
 * @param[in]  port_range  Port Range.
 *
 * @return Newly allocated UUID if available, else NULL.
 */
char*
port_range_uuid (port_range_t port_range)
{
  return sql_string ("SELECT uuid FROM port_ranges WHERE id = %llu;",
                     port_range);
}

/**
 * @brief Return whether a port_list is in use by a task.
 *
 * @param[in]  port_list  Port_List.
 *
 * @return 1 if in use, else 0.
 */
int
port_list_in_use (port_list_t port_list)
{
  return !!sql_int ("SELECT count(*) FROM targets"
                    " WHERE port_list = %llu",
                    port_list);
}

/**
 * @brief Check whether a trashcan Port List is in use.
 *
 * @param[in]  port_list Port List.
 *
 * @return 1 yes, 0 no.
 */
int
trash_port_list_in_use (port_list_t port_list)
{
  return !!sql_int ("SELECT count (*) FROM targets_trash"
                    " WHERE port_list = %llu"
                    " AND port_list_location = "
                    G_STRINGIFY (LOCATION_TRASH) ";",
                    port_list);
}

/**
 * @brief Check whether a Port List is writable.
 *
 * @param[in]  port_list  Port List.
 *
 * @return 1 yes, 0 no.
 */
int
port_list_writable (port_list_t port_list)
{
  return port_list_in_use (port_list) == 0;
}

/**
 * @brief Check whether a trashcan Port List is writable.
 *
 * @param[in]  port_list  Port List.
 *
 * @return 1 yes, 0 no.
 */
int
trash_port_list_writable (port_list_t port_list)
{
  return trash_port_list_in_use (port_list) == 0;
}

/**
 * @brief Return whether a trashcan port list is readable.
 *
 * @param[in]  port_list_id  Port list UUID.
 *
 * @return 1 if readable, else 0.
 */
int
trash_port_list_readable_uuid (const gchar *port_list_id)
{
  port_list_t found;

  if (port_list_id == NULL)
    return 0;
  if (find_trash ("port_list", port_list_id, &found))
    return 0;
  return found > 0;
}

/**
 * @brief Initialise a port_range iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  port_list   Port list.
 * @param[in]  trash       Whether port_list is in the trashcan.
 * @param[in]  ascending   Whether to sort ascending or descending.
 * @param[in]  sort_field  Field to sort on, or NULL for type then start.
 */
void
init_port_range_iterator (iterator_t* iterator, port_list_t port_list,
                          int trash, int ascending, const char* sort_field)
{
  assert (current_credentials.uuid);

  if (port_list)
    {
      char *uuid;

      uuid = port_list_uuid (port_list);
      assert (uuid);
      if (acl_user_has_access_uuid ("port_list", uuid, "get_port_lists", trash))
        init_iterator (iterator,
                       "SELECT uuid, comment, start, \"end\", type, exclude"
                       " FROM port_ranges%s"
                       " WHERE port_list = %llu"
                       " ORDER BY %s %s;",
                       trash ? "_trash" : "",
                       port_list,
                       sort_field ? sort_field : "type, CAST (start AS INTEGER)",
                       ascending ? "ASC" : "DESC");
      else
        init_iterator (iterator,
                       "SELECT uuid, comment, start, \"end\", type, exclude"
                       " FROM port_ranges"
                       " WHERE 1 = 0");
      free (uuid);
    }
  else
    init_iterator (iterator,
                   "SELECT uuid, comment, start, end, type, exclude"
                   " FROM port_ranges%s"
                   " WHERE"
                   " (((SELECT owner FROM port_lists%s WHERE id = port_list)"
                   "   IS NULL)"
                   "  OR ((SELECT owner FROM port_lists%s WHERE id = port_list)"
                   "      = (SELECT id FROM users WHERE users.uuid = '%s'))"
                   "  OR (CAST (%i AS boolean)"
                   "      AND (" ACL_USER_MAY ("port_list") ")))"
                   " ORDER BY %s %s;",
                   trash ? "_trash" : "",
                   trash ? "_trash" : "",
                   trash ? "_trash" : "",
                   current_credentials.uuid,
                   trash ? 0 : 1,
                   current_credentials.uuid,
                   current_credentials.uuid,
                   current_credentials.uuid,
                   "get_port_lists",
                   "get_port_lists",
                   "get_port_lists",
                   "get_port_lists",
                   sort_field ? sort_field : "type, CAST (start AS INTEGER)",
                   ascending ? "ASC" : "DESC");
}

/**
 * @brief Get the UUID from a port range iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The UUID of the range, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (port_range_iterator_uuid, 0);

/**
 * @brief Get the comment from a port range iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The comment of the range, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
const char*
port_range_iterator_comment (iterator_t* iterator)
{
  const char *ret;
  if (iterator->done) return "";
  ret = iterator_string (iterator, 1);
  return ret ? ret : "";
}

/**
 * @brief Get the comment from a port range iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The comment of the range, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (port_range_iterator_start, 2);

/**
 * @brief Get the comment from a port range iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The comment of the range, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (port_range_iterator_end, 3);

/**
 * @brief Get the type from a port range iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The type of the range, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
const char*
port_range_iterator_type (iterator_t* iterator)
{
  if (iterator->done) return "";
  switch ((port_protocol_t) iterator_int (iterator, 4))
    {
      case PORT_PROTOCOL_TCP:
        return "tcp";
      case PORT_PROTOCOL_UDP:
        return "udp";
      default:
        return "";
    }
}

/**
 * @brief Get the type from a port range iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The type of the range, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
port_protocol_t
port_range_iterator_type_int (iterator_t* iterator)
{
  if (iterator->done) return PORT_PROTOCOL_OTHER;
  return (port_protocol_t) iterator_int (iterator, 4);
}

/**
 * @brief Initialise a port list target iterator.
 *
 * @param[in]  iterator    Iterator.
 * @param[in]  port_list   Port list.
 * @param[in]  ascending   Whether to sort ascending or descending.
 */
void
init_port_list_target_iterator (iterator_t* iterator, port_list_t port_list,
                                int ascending)
{
  gchar *available, *with_clause;
  get_data_t get;
  array_t *permissions;

  assert (port_list);

  get.trash = 0;
  permissions = make_array ();
  array_add (permissions, g_strdup ("get_targets"));
  available = acl_where_owned ("target", &get, 1, "any", 0, permissions, 0,
                               &with_clause);
  array_free (permissions);

  init_iterator (iterator,
                 "%s"
                 " SELECT uuid, name, %s FROM targets"
                 " WHERE port_list = %llu"
                 " ORDER BY name %s;",
                 with_clause ? with_clause : "",
                 available,
                 port_list,
                 ascending ? "ASC" : "DESC");

  g_free (with_clause);
  g_free (available);
}

/**
 * @brief Get the UUID from a port list target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The UUID of the target, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (port_list_target_iterator_uuid, 0);

/**
 * @brief Get the name from a port list target iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return The name of the target, or NULL if iteration is complete.  Freed by
 *         cleanup_iterator.
 */
DEF_ACCESS (port_list_target_iterator_name, 1);

/**
 * @brief Get the read permission status from a GET iterator.
 *
 * @param[in]  iterator  Iterator.
 *
 * @return 1 if may read, else 0.
 */
int
port_list_target_iterator_readable (iterator_t* iterator)
{
  if (iterator->done) return 0;
  return iterator_int (iterator, 2);
}


/**
 * @brief Try restore a port list.
 *
 * If success, ends transaction for caller before exiting.
 *
 * @param[in]  port_list_id  UUID of resource.
 *
 * @return 0 success, 1 fail because port list is in use, 2 failed to find
 *          port list, -1 error.
 */
int
restore_port_list (const char *port_list_id)
{
  port_list_t port_list, table_port_list;

  if (find_trash ("port_list", port_list_id, &port_list))
    {
      sql_rollback ();
      return -1;
    }

  if (port_list == 0)
    return 2;

  if (sql_int ("SELECT count(*) FROM port_lists"
               " WHERE name ="
               " (SELECT name FROM port_lists_trash WHERE id = %llu)"
               " AND " ACL_USER_OWNS () ";",
               port_list,
               current_credentials.uuid))
    {
      sql_rollback ();
      return 3;
    }

  sql ("INSERT INTO port_lists"
       " (uuid, owner, name, comment, predefined, creation_time,"
       "  modification_time)"
       " SELECT uuid, owner, name, comment, predefined, creation_time,"
       "        modification_time"
       " FROM port_lists_trash WHERE id = %llu;",
       port_list);

  table_port_list = sql_last_insert_id ();

  sql ("INSERT INTO port_ranges"
       " (uuid, port_list, type, start, \"end\", comment, exclude)"
       " SELECT uuid, %llu, type, start, \"end\", comment, exclude"
       " FROM port_ranges_trash WHERE port_list = %llu;",
       table_port_list,
       port_list);

  /* Update the port_list in any trashcan targets. */
  sql ("UPDATE targets_trash"
       " SET port_list = %llu,"
       "     port_list_location = " G_STRINGIFY (LOCATION_TABLE)
       " WHERE port_list = %llu"
       " AND port_list_location = " G_STRINGIFY (LOCATION_TRASH),
       table_port_list,
       port_list);

  permissions_set_locations ("port_list", port_list, table_port_list,
                             LOCATION_TABLE);
  tags_set_locations ("port_list", port_list,
                      sql_last_insert_id (),
                      LOCATION_TABLE);

  sql ("DELETE FROM port_ranges_trash WHERE port_list = %llu;", port_list);
  sql ("DELETE FROM port_lists_trash WHERE id = %llu;", port_list);
  sql_commit ();

  return 0;
}

/**
 * @brief Empty trashcan.
 */
void
empty_trashcan_port_lists ()
{
  sql ("DELETE FROM port_ranges_trash"
       " WHERE port_list IN (SELECT id from port_lists_trash"
       "                     WHERE owner = (SELECT id FROM users"
       "                                    WHERE uuid = '%s'));",
       current_credentials.uuid);

  sql ("DELETE FROM port_lists_trash"
       " WHERE owner = (SELECT id FROM users WHERE uuid = '%s');",
       current_credentials.uuid);
}

/**
 * @brief Change ownership of port lists, for user deletion.
 *
 * @param[in]  user       Current owner.
 * @param[in]  inheritor  New owner.
 */
void
inherit_port_lists (user_t user, user_t inheritor)
{
  sql ("UPDATE port_lists SET owner = %llu WHERE owner = %llu;",
       inheritor, user);

  sql ("UPDATE port_lists_trash SET owner = %llu WHERE owner = %llu;",
       inheritor, user);
}

/**
 * @brief Delete all port lists owned by a user.
 *
 * @param[in]  user  The user.
 */
void
delete_port_lists_user (user_t user)
{
  sql ("DELETE FROM port_ranges"
       " WHERE port_list IN (SELECT id FROM port_lists WHERE owner = %llu);",
       user);
  sql ("DELETE FROM port_ranges_trash"
       " WHERE port_list IN (SELECT id FROM port_lists_trash"
       "                     WHERE owner = %llu);",
       user);
  sql ("DELETE FROM port_lists WHERE owner = %llu;", user);
  sql ("DELETE FROM port_lists_trash WHERE owner = %llu;", user);
}

/**
 * @brief Migrate old ownerless port lists to the Feed Owner.
 */
void
migrate_predefined_port_lists ()
{
  sql ("UPDATE port_lists"
       " SET owner = (SELECT id FROM users"
       "              WHERE uuid = (SELECT value FROM settings"
       "                            WHERE uuid = '%s'))"
       " WHERE owner is NULL;",
       SETTING_UUID_FEED_IMPORT_OWNER);
}


/* Startup. */

/**
 * @brief Check if a port list has been updated in the feed.
 *
 * @param[in]  path       Full path to port list XML in feed.
 * @param[in]  port_list  Port List.
 *
 * @return 1 if updated in feed, else 0.
 */
int
port_list_updated_in_feed (port_list_t port_list, const gchar *path)
{
  GStatBuf state;
  int last_update;

  last_update = sql_int ("SELECT modification_time FROM port_lists"
                         " WHERE id = %llu;",
                         port_list);

  if (g_stat (path, &state))
    {
      g_warning ("%s: Failed to stat feed port_list file: %s",
                 __func__,
                 strerror (errno));
      return 0;
    }

  if (state.st_mtime <= last_update)
    return 0;

  return 1;
}

/**
 * @brief Update a port list from an XML file.
 *
 * @param[in]  port_list    Existing port list.
 * @param[in]  name         New name.
 * @param[in]  comment      New comment.
 * @param[in]  ranges       New port ranges.
 */
void
update_port_list (port_list_t port_list, const gchar *name,
                  const gchar *comment,
                  array_t *ranges /* range_t */)
{
  gchar *quoted_name, *quoted_comment;
  int index;
  range_t *range;

  sql_begin_immediate ();

  quoted_name = sql_quote (name);
  quoted_comment = sql_quote (comment ? comment : "");
  sql ("UPDATE port_lists"
       " SET name = '%s', comment = '%s',"
       " predefined = 1, modification_time = m_now ()"
       " WHERE id = %llu;",
       quoted_name,
       quoted_comment,
       port_list);
  g_free (quoted_name);
  g_free (quoted_comment);

  /* Replace the preferences. */

  sql ("DELETE FROM port_ranges WHERE port_list = %llu;", port_list);
  ranges_sort_merge (ranges);
  array_terminate (ranges);
  index = 0;
  while ((range = (range_t*) g_ptr_array_index (ranges, index++)))
    insert_port_range (port_list, range->type, range->start, range->end);

  sql_commit ();
}

/**
 * @brief Check port lists, for startup.
 */
void
check_db_port_lists ()
{
  migrate_predefined_port_lists ();

  if (sync_port_lists_with_feed (FALSE) <= -1)
    g_warning ("%s: Failed to sync port lists with feed", __func__);

  /*
   * Ensure that the highest number in a port range is 65535.  At some point
   * ranges were initialised to 65536.
   *
   * This should be a migrator, but this way is easier to backport.  */
  sql ("UPDATE port_ranges SET \"end\" = 65535 WHERE \"end\" = 65536;");
  sql ("UPDATE port_ranges SET start = 65535 WHERE start = 65536;");

  /* Warn about feed resources in the trash. */
  if (sql_int ("SELECT EXISTS (SELECT * FROM port_lists_trash"
               "               WHERE predefined = 1);"))
    {
      g_warning ("%s: There are feed port lists in the trash."
                 " These will be excluded from the sync.",
                 __func__);
    }
}
