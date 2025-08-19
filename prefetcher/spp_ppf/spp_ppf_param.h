//---------------------------------------------------------------------------------------//
// File             : spp_ppf/spp_ppf_param.h
// Author           : Rahul Bera, SAFARI Research Group (write2bera@gmail.com)
// Date             : 19/AUG/2025
// Description      : Defines all parameters required for
//                    SPP with Perceptron Prefetch Filter, ISCA'19.
//                    Code is mostly verbatim of the original implementation
//---------------------------------------------------------------------------------------//

#ifndef __SPP_PPF_PARAM_H__
#define __SPP_PPF_PARAM_H__

#include <cstdint>

// SPP functional knobs
#define LOOKAHEAD_ON
#define FILTER_ON
#define GHR_ON
#define SPP_SANITY_CHECK

// #define SPP_DEBUG_PRINT
#ifdef SPP_DEBUG_PRINT
#define SPP_DP(x) x
#else
#define SPP_DP(x)
#endif

// #define SPP_PERC_WGHT
#ifdef SPP_PERC_WGHT
#define SPP_PW(x) x
#else
#define SPP_PW(x)
#endif

// Signature table parameters
constexpr static uint32_t ST_SET = 1;
constexpr static uint32_t ST_WAY = 256;
constexpr static uint32_t ST_TAG_BIT = 16;
constexpr static uint32_t ST_TAG_MASK = ((1 << ST_TAG_BIT) - 1);
constexpr static uint32_t SIG_SHIFT = 3;
constexpr static uint32_t SIG_BIT = 12;
constexpr static uint32_t SIG_MASK = ((1 << SIG_BIT) - 1);
constexpr static uint32_t SIG_DELTA_BIT = 7;

// Pattern table parameters
constexpr static uint32_t PT_SET = 2048;
constexpr static uint32_t PT_WAY = 4;
constexpr static uint32_t C_SIG_BIT = 4;
constexpr static uint32_t C_DELTA_BIT = 4;
constexpr static uint32_t C_SIG_MAX = ((1 << C_SIG_BIT) - 1);
constexpr static uint32_t C_DELTA_MAX = ((1 << C_DELTA_BIT) - 1);

// Prefetch filter parameters
constexpr static uint32_t QUOTIENT_BIT = 10;
constexpr static uint32_t REMAINDER_BIT = 6;
constexpr static uint32_t HASH_BIT = (QUOTIENT_BIT + REMAINDER_BIT + 1);
constexpr static uint32_t FILTER_SET = (1 << QUOTIENT_BIT);
constexpr static uint32_t QUOTIENT_BIT_REJ = 10;
constexpr static uint32_t REMAINDER_BIT_REJ = 8;
constexpr static uint32_t HASH_BIT_REJ = (QUOTIENT_BIT_REJ + REMAINDER_BIT_REJ + 1);
constexpr static uint32_t FILTER_SET_REJ = (1 << QUOTIENT_BIT_REJ);

// Global register parameters
constexpr static uint32_t GLOBAL_COUNTER_BIT = 10;
constexpr static uint32_t GLOBAL_COUNTER_MAX = ((1 << GLOBAL_COUNTER_BIT) - 1);
constexpr static uint32_t MAX_GHR_ENTRY = 8;
constexpr static uint32_t PAGES_TRACKED = 6;

// Perceptron paramaters
constexpr static uint32_t PERC_ENTRIES = 4096;  // Upto 12-bit addressing in hashed perceptron
constexpr static uint32_t PERC_FEATURES = 9;    // Keep increasing based on new features
constexpr static int32_t PERC_COUNTER_MAX = 15; //-16 to +15: 5 bits counter
constexpr static int32_t PERC_THRESHOLD_HI = -5;
constexpr static int32_t PERC_THRESHOLD_LO = -15;
constexpr static int32_t POS_UPDT_THRESHOLD = 90;
constexpr static int32_t NEG_UPDT_THRESHOLD = -80;

#endif /* __SPP_PPF_PARAM_H__ */
