//---------------------------------------------------------------------------------------//
// File             : spp_ppf/spp_ppf.cc
// Author           : Rahul Bera, SAFARI Research Group (write2bera@gmail.com)
// Date             : 19/AUG/2025
// Description      : Implements SPP with Perceptron Prefetch Filter, ISCA'19.
//                    Code is mostly verbatim of the original implementation
//---------------------------------------------------------------------------------------//

#include "spp_ppf.h"

#include "cache.h"

void spp_ppf::prefetcher_initialize()
{
  /* set cross-pointers */
  ST.ghr = &GHR;
  PT.ghr = &GHR;
  PT.perc = &PERC;
  PT.filter = &FILTER;
  FILTER.ghr = &GHR;
  FILTER.perc = &PERC;
}

uint32_t spp_ppf::prefetcher_cache_operate(champsim::address address, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                           uint32_t metadata_in)
{
  uint64_t addr = address.to<uint64_t>();
  uint64_t page = addr >> LOG2_PAGE_SIZE;
  uint32_t page_offset = (uint32_t)((addr >> LOG2_BLOCK_SIZE) & (PAGE_SIZE / BLOCK_SIZE - 1));

  std::size_t mshr_size = intern_->get_mshr_size();
  std::size_t mshr_occupancy = intern_->get_mshr_occupancy();
  std::size_t pq_size = intern_->get_pq_size()[0];
  std::size_t pq_occupancy = intern_->get_pq_occupancy()[0];

  uint32_t last_sig = 0, curr_sig = 0, depth = 0;
  int32_t delta = 0;

  std::size_t q_size = (100 * mshr_size);
  uint32_t* confidence_q = (uint32_t*)calloc(q_size, sizeof(uint32_t));
  int32_t* delta_q = (int32_t*)calloc(q_size, sizeof(int32_t));
  int32_t* perc_sum_q = (int32_t*)calloc(q_size, sizeof(int32_t));

  for (uint32_t i = 0; i < q_size; i++) {
    confidence_q[i] = 0;
    delta_q[i] = 0;
    perc_sum_q[i] = 0;
  }
  confidence_q[0] = 100;
  GHR.global_accuracy = GHR.pf_issued ? ((100 * GHR.pf_useful) / GHR.pf_issued) : 0;

  for (int i = SPP_PPF::PAGES_TRACKED - 1; i > 0; i--) { // N down to 1
    GHR.page_tracker[i] = GHR.page_tracker[i - 1];
  }
  GHR.page_tracker[0] = page;

  int distinct_pages = 0;
  uint8_t num_pf = 0;
  for (uint32_t i = 0; i < SPP_PPF::PAGES_TRACKED; i++) {
    uint32_t j;
    for (j = 0; j < i; j++) {
      if (GHR.page_tracker[i] == GHR.page_tracker[j])
        break;
    }
    if (i == j)
      distinct_pages++;
  }
  // cout << "Distinct Pages: " << distinct_pages << endl;

  SPP_DP(cout << endl
              << "[ChampSim] " << __func__ << " addr: " << hex << addr << " cache_line: " << (addr >> LOG2_BLOCK_SIZE);
         cout << " page: " << page << " page_offset: " << dec << page_offset << endl;);

  // Stage 1: Read and update a sig stored in ST
  // last_sig and delta are used to update (sig, delta) correlation in PT
  // curr_sig is used to read prefetch candidates in PT
  ST.read_and_update_sig(page, page_offset, last_sig, curr_sig, delta);

  // Also check the prefetch filter in parallel to update global accuracy counters
  FILTER.check(addr, 0, 0, L2C_DEMAND, 0, 0, 0, 0, 0, 0);

  // Stage 2: Update delta patterns stored in PT
  if (last_sig)
    PT.update_pattern(last_sig, delta);

  // Stage 3: Start prefetching
  uint64_t base_addr = addr;
  uint64_t curr_ip = ip.to<uint64_t>();
  uint32_t lookahead_conf = 100, pf_q_head = 0, pf_q_tail = 0;
  uint8_t do_lookahead = 0;
  int32_t prev_delta = 0;

  uint64_t train_addr = addr;
  int32_t train_delta = 0;

  GHR.ip_3 = GHR.ip_2;
  GHR.ip_2 = GHR.ip_1;
  GHR.ip_1 = GHR.ip_0;
  GHR.ip_0 = ip.to<uint64_t>();

#ifdef LOOKAHEAD_ON
  do {
#endif
    uint32_t lookahead_way = SPP_PPF::PT_WAY;

    train_addr = addr;
    train_delta = prev_delta;
    // Remembering the original addr here and accumulating the deltas in lookahead stages

    // Read the PT. Also passing info required for perceptron inferencing as PT calls perc_predict()
    PT.read_pattern(curr_sig, delta_q, confidence_q, perc_sum_q, lookahead_way, lookahead_conf, pf_q_tail, depth, addr, base_addr, train_addr, curr_ip,
                    train_delta, last_sig, pq_occupancy, pq_size, mshr_occupancy, mshr_size);

    do_lookahead = 0;
    for (uint32_t i = pf_q_head; i < pf_q_tail; i++) {

      uint64_t pf_addr = (base_addr & ~(BLOCK_SIZE - 1)) + (delta_q[i] << LOG2_BLOCK_SIZE);
      int32_t perc_sum = perc_sum_q[i];

      SPP_DP(cout << "[ChampSim] State of features: \nTrain addr: " << train_addr << "\tCurr IP: " << curr_ip << "\tIP_1: " << GHR.ip_1
                  << "\tIP_2: " << GHR.ip_2 << "\tIP_3: " << GHR.ip_3 << "\tDelta: " << train_delta + delta_q[i] << "\t:LastSig " << last_sig << "\t:CurrSig "
                  << curr_sig << "\t:Conf " << confidence_q[i] << "\t:Depth " << depth << "\tSUM: " << perc_sum << endl;);
      FILTER_REQUEST fill_level = (perc_sum >= SPP_PPF::PERC_THRESHOLD_HI) ? SPP_L2C_PREFETCH : SPP_LLC_PREFETCH;

      if ((addr & ~(PAGE_SIZE - 1)) == (pf_addr & ~(PAGE_SIZE - 1))) { // Prefetch request is in the same physical page

        // Filter checks for redundancy and returns FALSE if redundant
        // Else it returns TRUE and logs the features for future retrieval
        if (num_pf < ceil(((double)(pq_size) / distinct_pages))) {
          if (FILTER.check(pf_addr, train_addr, curr_ip, fill_level, train_delta + delta_q[i], last_sig, curr_sig, confidence_q[i], perc_sum, (depth - 1))) {

            //[DO NOT TOUCH]:
            // Use addr (not base_addr) to obey the same physical page boundary
            champsim::address pref_addr{pf_addr};
            prefetch_line(pref_addr, (fill_level == SPP_L2C_PREFETCH), 5);
            num_pf++;

            // FILTER.valid_reject[quotient] = 0;
            if (fill_level == SPP_L2C_PREFETCH) {
              GHR.pf_issued++;
              if (GHR.pf_issued > SPP_PPF::GLOBAL_COUNTER_MAX) {
                GHR.pf_issued >>= 1;
                GHR.pf_useful >>= 1;
              }
              SPP_DP(cout << "[ChampSim] SPP L2 prefetch issued GHR.pf_issued: " << GHR.pf_issued << " GHR.pf_useful: " << GHR.pf_useful << endl;);
            }

            SPP_DP(cout << "[ChampSim] " << __func__ << " base_addr: " << hex << base_addr << " pf_addr: " << pf_addr;
                   cout << " pf_cache_line: " << (pf_addr >> LOG2_BLOCK_SIZE);
                   cout << " prefetch_delta: " << dec << delta_q[i] << " confidence: " << confidence_q[i];
                   cout << " depth: " << i << " fill_level: " << ((fill_level == SPP_L2C_PREFETCH) ? FILL_L2 : FILL_LLC) << endl;);
          }
        }
      } else { // Prefetch request is crossing the physical page boundary
#ifdef GHR_ON
               // Store this prefetch request in GHR to bootstrap SPP learning when we see a ST miss (i.e., accessing a new page)
        GHR.update_entry(curr_sig, confidence_q[i], (pf_addr >> LOG2_BLOCK_SIZE) & 0x3F, delta_q[i]);
#endif
      }
      do_lookahead = 1;
      pf_q_head++;
    }

    // Update base_addr and curr_sig
    if (lookahead_way < SPP_PPF::PT_WAY) {
      uint32_t set = get_hash(curr_sig) % SPP_PPF::PT_SET;
      base_addr += (PT.delta[set][lookahead_way] << LOG2_BLOCK_SIZE);
      prev_delta += PT.delta[set][lookahead_way];

      // PT.delta uses a 7-bit sign magnitude representation to generate sig_delta
      // int sig_delta = (PT.delta[set][lookahead_way] < 0) ? ((((-1) * PT.delta[set][lookahead_way]) & 0x3F) + 0x40) : PT.delta[set][lookahead_way];
      int sig_delta =
          (PT.delta[set][lookahead_way] < 0) ? (((-1) * PT.delta[set][lookahead_way]) + (1 << (SPP_PPF::SIG_DELTA_BIT - 1))) : PT.delta[set][lookahead_way];
      curr_sig = ((curr_sig << SPP_PPF::SIG_SHIFT) ^ sig_delta) & SPP_PPF::SIG_MASK;
    }

    SPP_DP(cout << "Looping curr_sig: " << hex << curr_sig << " base_addr: " << base_addr << dec;
           cout << " pf_q_head: " << pf_q_head << " pf_q_tail: " << pf_q_tail << " depth: " << depth << endl;);
#ifdef LOOKAHEAD_ON
  } while (do_lookahead);
#endif

  free(confidence_q);
  free(delta_q);
  free(perc_sum_q);

  return 0;
}

uint32_t spp_ppf::prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in)
{
#ifdef FILTER_ON
  SPP_DP(cout << endl;);
  FILTER.check(evicted_addr.to<uint64_t>(), 0, 0, L2C_EVICT, 0, 0, 0, 0, 0, 0);
#endif
  return 0;
}