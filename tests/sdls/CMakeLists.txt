# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ccsds_sdls_tests)

target_sources(app PRIVATE
  src/test_sdls_ep.c
  src/test_sdls_sa_management.c
  src/test_sdls_monitoring.c
  src/test_sdls_psa.c
  src/test_sdls_state.c
  src/test_sdls_wire.c
)
