//---------------------------------------------------------------------------------------//
// File             : spp_ppf/spp_ppf_helper.h
// Author           : Rahul Bera, SAFARI Research Group (write2bera@gmail.com)
// Date             : 19/AUG/2025
// Description      : Implements helper functionailty required for
//                    SPP with Perceptron Prefetch Filter, ISCA'19.
//                    Code is mostly verbatim of the original implementation
//---------------------------------------------------------------------------------------//

#ifndef __SPP_PPF_HELPER__
#define __SPP_PPF_HELPER__

#include <cstdint>
#include <iostream>

#include "spp_ppf_param.h"

enum FILTER_REQUEST { SPP_L2C_PREFETCH, SPP_LLC_PREFETCH, L2C_DEMAND, L2C_EVICT, SPP_PERC_REJECT }; // Request type for prefetch filter

uint64_t get_hash(uint64_t key);

class GLOBAL_REGISTER
{
public:
  // Global counters to calculate global prefetching accuracy
  uint64_t pf_useful, pf_issued,
      global_accuracy; // Alpha value in Section III. Equation 3

  // Global History Register (GHR) entries
  uint8_t valid[MAX_GHR_ENTRY];
  uint32_t sig[MAX_GHR_ENTRY], confidence[MAX_GHR_ENTRY], offset[MAX_GHR_ENTRY];
  int delta[MAX_GHR_ENTRY];

  uint64_t ip_0, ip_1, ip_2, ip_3;

  uint64_t page_tracker[PAGES_TRACKED];

  GLOBAL_REGISTER()
  {
    pf_useful = 0;
    pf_issued = 0;
    global_accuracy = 0;
    ip_0 = 0;
    ip_1 = 0;
    ip_2 = 0;
    ip_3 = 0;

    for (uint32_t i = 0; i < MAX_GHR_ENTRY; i++) {
      valid[i] = 0;
      sig[i] = 0;
      confidence[i] = 0;
      offset[i] = 0;
      delta[i] = 0;
    }
  }

  void update_entry(uint32_t pf_sig, uint32_t pf_confidence, uint32_t pf_offset, int pf_delta);
  uint32_t check_entry(uint32_t page_offset);
};

class PERCEPTRON
{
public:
  // Perc Weights
  int32_t perc_weights[PERC_ENTRIES][PERC_FEATURES];

  // CONST depths for different features
  int32_t PERC_DEPTH[PERC_FEATURES];

  PERCEPTRON()
  {
    // std::cout << "\nInitialize PERCEPTRON" << std::endl;
    // std::cout << "PERC_ENTRIES: " << PERC_ENTRIES << std::endl;
    // std::cout << "PERC_FEATURES: " << PERC_FEATURES << std::endl;

    PERC_DEPTH[0] = 2048; // base_addr;
    PERC_DEPTH[1] = 4096; // cache_line;
    PERC_DEPTH[2] = 4096; // page_addr;
    PERC_DEPTH[3] = 4096; // confidence ^ page_addr;
    PERC_DEPTH[4] = 1024; // curr_sig ^ sig_delta;
    PERC_DEPTH[5] = 4096; // ip_1 ^ ip_2 ^ ip_3;
    PERC_DEPTH[6] = 1024; // ip ^ depth;
    PERC_DEPTH[7] = 2048; // ip ^ sig_delta;
    PERC_DEPTH[8] = 128;  // confidence;

    for (uint32_t i = 0; i < PERC_ENTRIES; i++) {
      for (uint32_t j = 0; j < PERC_FEATURES; j++) {
        perc_weights[i][j] = 0;
      }
    }
  }

  void perc_update(uint64_t check_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, int32_t cur_delta, uint32_t last_sig, uint32_t curr_sig,
                   uint32_t confidence, uint32_t depth, bool direction, int32_t perc_sum);
  int32_t perc_predict(uint64_t check_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, int32_t cur_delta, uint32_t last_sig, uint32_t curr_sig,
                       uint32_t confidence, uint32_t depth);
  void get_perc_index(uint64_t base_addr, uint64_t ip, uint64_t ip_1, uint64_t ip_2, uint64_t ip_3, int32_t cur_delta, uint32_t last_sig, uint32_t curr_sig,
                      uint32_t confidence, uint32_t depth, uint64_t perc_set[PERC_FEATURES]);
};

class PREFETCH_FILTER
{
public:
  /* cross-reference pointers */
  GLOBAL_REGISTER* ghr;
  PERCEPTRON* perc;

  uint64_t remainder_tag[FILTER_SET], pc[FILTER_SET], pc_1[FILTER_SET], pc_2[FILTER_SET], pc_3[FILTER_SET], address[FILTER_SET];
  bool valid[FILTER_SET], // Consider this as "prefetched"
      useful[FILTER_SET]; // Consider this as "used"
  int32_t delta[FILTER_SET], perc_sum[FILTER_SET];
  uint32_t last_signature[FILTER_SET], confidence[FILTER_SET], cur_signature[FILTER_SET], la_depth[FILTER_SET];

  uint64_t remainder_tag_reject[FILTER_SET_REJ], pc_reject[FILTER_SET_REJ], pc_1_reject[FILTER_SET_REJ], pc_2_reject[FILTER_SET_REJ],
      pc_3_reject[FILTER_SET_REJ], address_reject[FILTER_SET_REJ];
  bool valid_reject[FILTER_SET_REJ]; // Entries which the perceptron rejected
  int32_t delta_reject[FILTER_SET_REJ], perc_sum_reject[FILTER_SET_REJ];
  uint32_t last_signature_reject[FILTER_SET_REJ], confidence_reject[FILTER_SET_REJ], cur_signature_reject[FILTER_SET_REJ], la_depth_reject[FILTER_SET_REJ];

  PREFETCH_FILTER()
  {
    // std::cout << std::endl << "Initialize PREFETCH FILTER" << std::endl;
    // std::cout << "FILTER_SET: " << FILTER_SET << std::endl;

    for (uint32_t set = 0; set < FILTER_SET; set++) {
      remainder_tag[set] = 0;
      valid[set] = 0;
      useful[set] = 0;
    }
    for (uint32_t set = 0; set < FILTER_SET_REJ; set++) {
      valid_reject[set] = 0;
      remainder_tag_reject[set] = 0;
    }
  }

  bool check(uint64_t pf_addr, uint64_t base_addr, uint64_t ip, FILTER_REQUEST filter_request, int32_t cur_delta, uint32_t last_sign, uint32_t cur_sign,
             uint32_t confidence, int32_t sum, uint32_t depth);
};

class SIGNATURE_TABLE
{
public:
  /* cross-reference pointers */
  GLOBAL_REGISTER* ghr;

  bool valid[ST_SET][ST_WAY];
  uint32_t tag[ST_SET][ST_WAY], last_offset[ST_SET][ST_WAY], sig[ST_SET][ST_WAY], lru[ST_SET][ST_WAY];

  SIGNATURE_TABLE()
  {
    // std::cout << "Initialize SIGNATURE TABLE" << std::endl;
    // std::cout << "ST_SET: " << ST_SET << std::endl;
    // std::cout << "ST_WAY: " << ST_WAY << std::endl;
    // std::cout << "ST_TAG_BIT: " << ST_TAG_BIT << std::endl;
    // std::cout << "ST_TAG_MASK: " << std::hex << ST_TAG_MASK << std::dec << std::endl;

    for (uint32_t set = 0; set < ST_SET; set++)
      for (uint32_t way = 0; way < ST_WAY; way++) {
        valid[set][way] = 0;
        tag[set][way] = 0;
        last_offset[set][way] = 0;
        sig[set][way] = 0;
        lru[set][way] = way;
      }
  };

  void read_and_update_sig(uint64_t page, uint32_t page_offset, uint32_t& last_sig, uint32_t& curr_sig, int32_t& delta);
};

class PATTERN_TABLE
{
public:
  /* cross-reference pointers */
  GLOBAL_REGISTER* ghr;
  PERCEPTRON* perc;
  PREFETCH_FILTER* filter;

  int delta[PT_SET][PT_WAY];
  uint32_t c_delta[PT_SET][PT_WAY], c_sig[PT_SET];

  PATTERN_TABLE()
  {
    // std::cout << std::endl << "Initialize PATTERN TABLE" << std::endl;
    // std::cout << "PT_SET: " << PT_SET << std::endl;
    // std::cout << "PT_WAY: " << PT_WAY << std::endl;
    // std::cout << "SIG_DELTA_BIT: " << SIG_DELTA_BIT << std::endl;
    // std::cout << "C_SIG_BIT: " << C_SIG_BIT << std::endl;
    // std::cout << "C_DELTA_BIT: " << C_DELTA_BIT << std::endl;

    for (uint32_t set = 0; set < PT_SET; set++) {
      for (uint32_t way = 0; way < PT_WAY; way++) {
        delta[set][way] = 0;
        c_delta[set][way] = 0;
      }
      c_sig[set] = 0;
    }
  }

  void update_pattern(uint32_t last_sig, int curr_delta),
      read_pattern(uint32_t curr_sig, int* prefetch_delta, uint32_t* confidence_q, int32_t* perc_sum_q, uint32_t& lookahead_way, uint32_t& lookahead_conf,
                   uint32_t& pf_q_tail, uint32_t& depth, uint64_t addr, uint64_t base_addr, uint64_t train_addr, uint64_t curr_ip, int32_t train_delta,
                   uint32_t last_sig, std::size_t pq_occupancy, std::size_t pq_SIZE, std::size_t mshr_occupancy, std::size_t mshr_SIZE);
};
#endif /* __SPP_PPF_HELPER__ */
