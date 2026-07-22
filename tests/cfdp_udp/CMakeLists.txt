# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

list(APPEND BOARD_ROOT ${CMAKE_CURRENT_LIST_DIR}/../..)
list(APPEND DTS_ROOT ${CMAKE_CURRENT_LIST_DIR}/../..)
set(KCONFIG_ROOT ${CMAKE_CURRENT_LIST_DIR}/../../Kconfig)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(cfdp_udp_integration)

set(CCSDS_SRC ${CMAKE_CURRENT_LIST_DIR}/../../src/connectivity/ccsds)

target_include_directories(app PRIVATE ${CCSDS_SRC})

target_sources(app PRIVATE
    src/main.c
    ${CCSDS_SRC}/akira_cfdp_service.c
    ${CCSDS_SRC}/akira_cfdp_staging.c
    ${CCSDS_SRC}/ccsds_cfdp_checksum.c
    ${CCSDS_SRC}/ccsds_cfdp_entity.c
    ${CCSDS_SRC}/ccsds_cfdp_pdu.c
    ${CCSDS_SRC}/ccsds_cfdp_ranges.c
    ${CCSDS_SRC}/ccsds_cfdp_space_packet.c
    ${CCSDS_SRC}/ccsds_profile.c
    ${CCSDS_SRC}/ccsds_router.c
    ${CCSDS_SRC}/ccsds_space_packet.c
    ${CCSDS_SRC}/ccsds_udp.c
)
