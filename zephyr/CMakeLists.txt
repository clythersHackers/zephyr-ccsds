# SPDX-License-Identifier: Apache-2.0

zephyr_include_directories(
  ../include
  ../include/ccsds
)
zephyr_compile_definitions(CCSDS_MODULE_CMAKE_LOADED=1)

if(CONFIG_CCSDS)
  zephyr_library()

  zephyr_library_sources(
    ../src/ccsds_crc16.c
    ../src/ccsds_profile.c
    ../src/ccsds_router.c
    ../src/ccsds_space_packet.c
  )

  if(CONFIG_CCSDS_UDP)
    zephyr_library_sources(../src/ccsds_udp.c)
  endif()

  if(CONFIG_CCSDS_FRAME_SUPPORT)
    zephyr_library_sources(
      ../src/ccsds_bch.c
      ../src/ccsds_cltu.c
      ../src/ccsds_tc_frame.c
      ../src/ccsds_tc_segment.c
      ../src/ccsds_tm_frame.c
    )
  endif()

  if(CONFIG_CCSDS_FRAME_SUPPORT AND CONFIG_CCSDS_RS)
    zephyr_library_sources(../src/ccsds_rs.c)
  endif()

  if(CONFIG_CCSDS_RND)
    zephyr_library_sources(../src/ccsds_rnd.c)
  endif()

  if(CONFIG_CCSDS_CFDP)
    zephyr_library_sources(
      ../src/ccsds_cfdp_checksum.c
      ../src/ccsds_cfdp_entity.c
      ../src/ccsds_cfdp_pdu.c
      ../src/ccsds_cfdp_ranges.c
      ../src/ccsds_cfdp_service.c
      ../src/ccsds_cfdp_space_packet.c
    )
  endif()
endif()
