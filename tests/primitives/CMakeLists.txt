# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

# Load only the CCSDS module so this test remains independent of AkiraOS.
set(ZEPHYR_MODULES "${CMAKE_CURRENT_LIST_DIR}/../..")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ccsds_primitives)

target_sources(app PRIVATE
  src/test_ccsds_bch.c
  src/test_ccsds_crc16.c
  src/test_ccsds_rnd.c
  src/test_ccsds_rs.c
  src/test_ccsds_space_packet.c
)
