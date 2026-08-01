# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ccsds_frames)

target_sources(app PRIVATE
  src/test_ccsds_cltu.c
  src/test_ccsds_profile.c
  src/test_ccsds_sdls_integration.c
  src/test_ccsds_router.c
  src/test_ccsds_tc_frame.c
  src/test_ccsds_tc_segment.c
  src/test_ccsds_tm_frame.c
)
