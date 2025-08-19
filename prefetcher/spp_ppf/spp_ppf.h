//---------------------------------------------------------------------------------------//
// File             : spp_ppf/spp_ppf.h
// Author           : Rahul Bera, SAFARI Research Group (write2bera@gmail.com)
// Date             : 19/AUG/2025
// Description      : Implements SPP with Perceptron Prefetch Filter, ISCA'19.
//                    Code is mostly verbatim of the original implementation
//---------------------------------------------------------------------------------------//

#ifndef __SPP_PPF_H__
#define __SPP_PPF_H__

#include "champsim.h"
#include "modules.h"
#include "spp_ppf_helper.h"

struct spp_ppf : public champsim::modules::prefetcher {
private:
  SIGNATURE_TABLE ST;
  PATTERN_TABLE PT;
  PREFETCH_FILTER FILTER;
  GLOBAL_REGISTER GHR;
  PERCEPTRON PERC;

public:
  using champsim::modules::prefetcher::prefetcher;

  // champsim interface prototypes
  void prefetcher_initialize();
  uint32_t prefetcher_cache_operate(champsim::address addr, champsim::address ip, uint8_t cache_hit, bool useful_prefetch, access_type type,
                                    uint32_t metadata_in);
  uint32_t prefetcher_cache_fill(champsim::address addr, long set, long way, uint8_t prefetch, champsim::address evicted_addr, uint32_t metadata_in);
};

#endif /* __SPP_PPF_H__ */