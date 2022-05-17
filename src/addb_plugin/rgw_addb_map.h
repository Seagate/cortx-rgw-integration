/*
 * Ceph - scalable distributed file system
 *
 * RGW ADDB plugin imports.
 *
 * Copyright (C) 2022 Seagate Technology LLC and/or its Affiliates
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */


#pragma once

#ifndef __RGW_ADDB_MAP_H__
#define __RGW_ADDB_MAP_H__

extern const char* g_rgw_to_addb_idx_func_name_map[];
extern const uint64_t g_rgw_to_addb_idx_func_name_map_size;

const char* addb_idx_to_rgw_state(uint64_t map_idx);

#endif

