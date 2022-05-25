/*
 * Ceph - scalable distributed file system
 *
 * RGW ADDB map between fuction names to ADDB indices.
 *
 * Copyright (C) 2022 Seagate Technology LLC and/or its Affiliates
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */

#include <stdint.h>
#include <assert.h>

#include "rgw_addb_map.h"

const char* g_rgw_to_addb_idx_func_name_map[] = {
  "UNKNOWN_METHOD",
  "rgw::sal::MotrStore::get_new_req_id",
  "rgw::sal::MotrObject::create_mobj",
  "rgw::sal::MotrObject::open_mobj",
  "rgw::sal::MotrObject::delete_mobj",
  "rgw::sal::MotrObject::write_mobj",
  "rgw::sal::MotrObject::read_mobj",
  "rgw::sal::MotrAtomicWriter::write",
  "rgw::sal::MotrStore::open_idx",
  "rgw::sal::MotrStore::do_idx_op",
  "rgw::sal::MotrStore::do_idx_next_op",
  "rgw::sal::MotrStore::delete_motr_idx_by_name",
  "rgw::sal::MotrStore::create_motr_idx_by_name"
};

const uint64_t g_rgw_to_addb_idx_func_name_map_size = 13;

const char* addb_idx_to_rgw_state(uint64_t map_idx) {
  assert(map_idx < g_rgw_to_addb_idx_func_name_map_size);

  return g_rgw_to_addb_idx_func_name_map[map_idx];
}

