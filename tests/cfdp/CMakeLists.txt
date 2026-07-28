# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

# Load only the CCSDS module so this test remains consumer-independent.
set(ZEPHYR_MODULES "${CMAKE_CURRENT_LIST_DIR}/../..")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(ccsds_cfdp)

target_sources(app PRIVATE
  src/test_ccsds_cfdp_checksum.c
  src/test_ccsds_cfdp_entity.c
  src/test_ccsds_cfdp_filestore.c
  src/test_ccsds_cfdp_pdu.c
  src/test_ccsds_cfdp_ranges.c
  src/test_ccsds_cfdp_service.c
  src/test_ccsds_cfdp_space_packet.c
  src/test_ccsds_cfdp_types.c
  src/test_ccsds_cfdp_ut.c
)
