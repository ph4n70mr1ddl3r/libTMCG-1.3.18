cmake_minimum_required(VERSION 3.16)

project(libTMCG VERSION 1.3.18 LANGUAGES C CXX)

option(WITH_BOTAN "Enable optional Botan RNG support" OFF)
option(ENABLE_FORKING "Enable forking demo logic" ON)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)

pkg_check_modules(LIBGCRYPT REQUIRED libgcrypt)
pkg_check_modules(GPG_ERROR REQUIRED gpg-error)

pkg_check_modules(GMP gmp)
if(NOT GMP_FOUND)
  find_path(GMP_INCLUDE_DIR gmp.h)
  find_library(GMP_LIBRARY gmp)
  if(NOT GMP_INCLUDE_DIR OR NOT GMP_LIBRARY)
    message(FATAL_ERROR "GMP not found (need gmp.h and -lgmp)")
  endif()
  set(GMP_INCLUDE_DIRS "${GMP_INCLUDE_DIR}")
  set(GMP_LIBRARIES "${GMP_LIBRARY}")
endif()

if(WITH_BOTAN)
  pkg_check_modules(BOTAN REQUIRED botan-2)
endif()

include(CheckSymbolExists)
set(CMAKE_REQUIRED_INCLUDES ${GMP_INCLUDE_DIRS})
set(CMAKE_REQUIRED_LIBRARIES ${GMP_LIBRARIES})
check_symbol_exists(__gmpz_powm_sec "gmp.h" HAVE_POWMSEC)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)

if(WITH_BOTAN)
  set(BOTAN_ENABLED 1)
endif()
if(ENABLE_FORKING)
  set(FORKING 1)
endif()

configure_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/libTMCG_config.h.in
  ${CMAKE_CURRENT_BINARY_DIR}/libTMCG_config.h
)

add_library(TMCG STATIC
  src/mpz_srandom.cc
  src/mpz_sqrtm.cc
  src/mpz_spowm.cc
  src/mpz_sprime.cc
  src/mpz_shash.cc
  src/parse_helper.cc
  src/mpz_helper.cc
  src/BarnettSmartVTMF_dlog.cc
  src/BarnettSmartVTMF_dlog_GroupQR.cc
  src/PedersenCOM.cc
  src/GrothVSSHE.cc
  src/HooghSchoenmakersSkoricVillegasVRHE.cc
  src/NaorPinkasEOTP.cc
  src/aiounicast_nonblock.cc
  src/aiounicast_select.cc
  src/CachinKursawePetzoldShoupSEABP.cc
  src/GennaroJareckiKrawczykRabinDKG.cc
  src/PedersenVSS.cc
  src/CanettiGennaroJareckiKrawczykRabinASTC.cc
  src/JareckiLysyanskayaASTC.cc
  src/CallasDonnerhackeFinneyShawThayerRFC4880.cc
  src/SchindelhauerTMCG.cc
  src/GolleDCPG_elgamal.cc
  src/VTMF_Card.cc
  src/VTMF_CardSecret.cc
  src/TMCG_Card.cc
  src/TMCG_CardSecret.cc
  src/TMCG_SecretKey.cc
  src/TMCG_PublicKey.cc
  src/libTMCG.cc
)

target_include_directories(TMCG PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_BINARY_DIR}
  ${LIBGCRYPT_INCLUDE_DIRS}
  ${GPG_ERROR_INCLUDE_DIRS}
  ${GMP_INCLUDE_DIRS}
)

target_compile_definitions(TMCG PUBLIC HAVE_CONFIG_H)

target_compile_options(TMCG PRIVATE
  ${LIBGCRYPT_CFLAGS_OTHER}
  ${GPG_ERROR_CFLAGS_OTHER}
  ${GMP_CFLAGS_OTHER}
)

target_link_libraries(TMCG PUBLIC
  ${LIBGCRYPT_LIBRARIES}
  ${GPG_ERROR_LIBRARIES}
  ${GMP_LIBRARIES}
)

if(WITH_BOTAN)
  target_include_directories(TMCG PUBLIC ${BOTAN_INCLUDE_DIRS})
  target_compile_definitions(TMCG PUBLIC BOTAN)
  target_link_libraries(TMCG PUBLIC ${BOTAN_LIBRARIES})
endif()

add_executable(t-poker-noninteractive
  tests/test_helper.c
  tests/t-poker-noninteractive.cc
)

target_include_directories(t-poker-noninteractive PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/tests
)

target_link_libraries(t-poker-noninteractive PRIVATE TMCG)

