#
#   Copyright (C) 2019-2021 Reiko Asakura. All Rights Reserved.
#
#   Fruitpeel
#

cmake_minimum_required(VERSION 3.19)

set(CMAKE_TOOLCHAIN_FILE "$ENV{SCE_PSP2_SDK_DIR}/host_tools/build/cmake/psp2-snc-toolchain.cmake")

project(fruitpeel LANGUAGES C)

include(VitaDevelopmentSuite)
enable_language(EMD)
set(CMAKE_C_STANDARD 99)

add_compile_options(
  -Xdiag=2 -Xquit=2
)

add_link_options(
  --prx-no-runtime-support
  --strip-duplicates
  --strip-unused-data
  --strip-report=strip-report.txt
)

include_directories(SYSTEM
  ${VDSUITE_USER_INCLUDE_DIRECTORIES}
)

link_directories(
  ${VDSUITE_LIBRARY_DIRECTORIES}
)

# Build self

add_compile_definitions(
  SCE_DBG_LOG_COMPONENT="\\033[0;33;1mFruitpeel\\033[0m"
  SCE_DBG_LOGGING_ENABLED=$<IF:$<CONFIG:Release,MinSizeRel>,0,1>
)

add_library(fruitpeel MODULE
  fruitpeel.c
  fruitpeel.emd
  opcode.c
  patch.c
)

target_link_libraries(fruitpeel
  ScePng
  SceDeflt

  taihen_stub

  SceGxm_stub
  SceKernel_stub
  SceSysmem_stub
  $<$<NOT:$<CONFIG:Release,MinSizeRel>>:SceDbg_stub>
)

VDSuiteSignElf(fruitpeel.suprx fruitpeel)
