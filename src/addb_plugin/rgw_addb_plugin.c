// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=2 sw=2 expandtab ft=cpp

/*
 * Ceph - scalable distributed file system
 *
 * RGW ADDB plugin for CORTX Motr m0addb2dump utility.
 *
 * Copyright (C) 2022 Seagate Technology LLC and/or its Affiliates
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License version 2.1, as published by the Free Software
 * Foundation. See file COPYING.
 *
 */

#include <stdio.h>
#include <addb2/plugin_api.h>
#include <assert.h>

#include "rgw_addb.h"
#include "rgw_addb_map.h"
#include "../../rgw_op_type.h"

#define STR(x) #x
#define ENUM_STR_ENTRY(v, e) case (e): (v) = STR(e); break;

static void dec(struct m0_addb2__context *ctx, const uint64_t *v, char *buf) {
  sprintf(buf, "%" PRId64, v[0]);
}

static void hex(struct m0_addb2__context *ctx, const uint64_t *v, char *buf) {
  sprintf(buf, "%" PRIx64, v[0]);
}

static void hex0x(struct m0_addb2__context *ctx, const uint64_t *v, char *buf) {
  sprintf(buf, "0x%" PRIx64, v[0]);
}

static void oct(struct m0_addb2__context *ctx, const uint64_t *v, char *buf) {
  sprintf(buf, "%" PRIo64, v[0]);
}

static void ptr(struct m0_addb2__context *ctx, const uint64_t *v, char *buf) {
  sprintf(buf, "@%p", *(void **)v);
}

static void bol(struct m0_addb2__context *ctx, const uint64_t *v, char *buf) {
  sprintf(buf, "%s", v[0] ? "true" : "false");
}

static void idx_to_state(struct m0_addb2__context *ctx, const uint64_t *v,
                         char *buf) {
  const char *state;

  switch(v[0]) {
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_CREATE_MOBJ);
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_OPEN_MOBJ);
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_DELETE_MOBJ);
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_WRITE_MOBJ);
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_READ_MOBJ);
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_WRITE);
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_GET_NEW_REQ_ID);
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_DO_IDX_OP);
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_DO_IDX_NEXT_OP);
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_DELETE_IDX_BY_NAME);
    ENUM_STR_ENTRY(state, RGW_ADDB_FUNC_CREATE_IDX_BY_NAME);
  default:
    state = "UNKNOWN";
    break;
  }

  sprintf(buf, "%s", state);
}

static void rgw_phase(struct m0_addb2__context *ctx, const uint64_t *v,
		      char *buf) {
  const char *phase;

  switch (v[0]) {
  case RGW_ADDB_PHASE_START:
    phase = "START";
    break;
  case RGW_ADDB_PHASE_DONE:
    phase = "DONE";
    break;
  case RGW_ADDB_PHASE_ERROR:
    phase = "ERROR";
    break;
  default:
    phase = "UNKNOWN";
    break;
  }

  sprintf(buf, "%s", phase);
}

static void req_opcode(struct m0_addb2__context *ctx,
		       const uint64_t *v, char *buf) {
  const char *opcode;

  switch(v[0]) {
    ENUM_STR_ENTRY(opcode, RGW_OP_GET_OBJ);
    ENUM_STR_ENTRY(opcode, RGW_OP_PUT_OBJ);
    ENUM_STR_ENTRY(opcode, RGW_OP_DELETE_MULTI_OBJ);
  default:
    opcode = "UNKNOWN";
    break;
  }

  sprintf(buf, "RGW_S3_OPCODE: %s", opcode);
}

static struct m0_addb2__id_intrp gs_curr_ids[] = {
    {RGW_ADDB_REQUEST_ID, 
     "rgw-request-state", 
     {&dec, &idx_to_state, &rgw_phase},
     {"rgw_request_id", "state", "phase"}, },

    {RGW_ADDB_REQUEST_OPCODE_ID, 
     "rgw-request-opcode",
     {&dec, &req_opcode,},
     {"entity_id", NULL}, },

    {RGW_ADDB_REQUEST_TO_MOTR_ID,
     "rgw-request-to-motr",
     {&dec, &dec},
     {"rgw_request_id", "motr_id"}},
    {0}};

int m0_addb2_load_interps(uint64_t flags,
                          struct m0_addb2__id_intrp **intrps_array) {
  /* suppres "unused" warnings */
  (void)dec;
  (void)hex0x;
  (void)oct;
  (void)hex;
  (void)bol;
  (void)ptr;

  *intrps_array = gs_curr_ids;
  return 0;
}
