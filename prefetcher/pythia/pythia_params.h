//=======================================================================================//
// File             : pythia/pythia_params.h
// Author           : Rahul Bera, SAFARI Research Group (write2bera@gmail.com)
// Date             : 20/AUG/2025
// Description      : Defines all parameters of Pythia (Bera+, MICRO'21)
//=======================================================================================//

#ifndef __PYTHIA_PARAMS_H__
#define __PYTHIA_PARAMS_H__

#include <cstdint>
#include <string>
#include <vector>

#if 0
#define LOCKED(...) \
  {                 \
    fflush(stdout); \
    __VA_ARGS__;    \
    fflush(stdout); \
  }
#define LOGID() fprintf(stdout, "[%25s@%3u] ", __FUNCTION__, __LINE__);
#define MYLOG(...) LOCKED(LOGID(); fprintf(stdout, __VA_ARGS__); fprintf(stdout, "\n");)
#else
#define MYLOG(...) \
  {                \
  }
#endif

#define NOT_PORTED \
  do {             \
    assert(false); \
  } while (false)

#define FABS(x) ((x) < 0.0f ? -(x) : (x))

#define DELTA_BITS 7
#define FK_MAX_TILINGS 32

#define MAX_ACTIONS 64
#define MAX_REWARDS 16
#define MAX_SCOOBY_DEGREE 16
#define SCOOBY_MAX_IPC_LEVEL 4
#define CACHE_ACC_LEVELS 4
#define DRAM_BW_LEVELS 4

#define DELTA_SIG_MAX_BITS 12
#define DELTA_SIG_SHIFT 3
#define PC_SIG_MAX_BITS 32
#define PC_SIG_SHIFT 4
#define OFFSET_SIG_MAX_BITS 24
#define OFFSET_SIG_SHIFT 4

#define SIG_SHIFT 3
#define SIG_BIT 12
#define SIG_MASK ((1 << SIG_BIT) - 1)
#define SIG_DELTA_BIT 7

namespace PYTHIA
{
static const float scooby_alpha = (float)0.006508802942367162;
static const float scooby_gamma = (float)0.556300959940946;
static const float scooby_epsilon = (float)0.0018228444309622588;
static const uint32_t scooby_state_num_bits = 10;
static const uint32_t scooby_max_states = 1024;
static const uint32_t scooby_seed = 200;
static const std::string scooby_policy = std::string("EGreedy");
static const std::string scooby_learning_type = std::string("SARSA");
static const std::vector<int32_t> scooby_actions = {1, 3, 4, 5, 10, 11, 12, 22, 23, 30, 32, -1, -3, -6, 0};
static const uint32_t scooby_max_actions = 128;
static const uint32_t scooby_pt_size = 256;
static const uint32_t scooby_st_size = 64;
static const uint32_t scooby_max_pcs = 5;
static const uint32_t scooby_max_offsets = 5;
static const uint32_t scooby_max_deltas = 5;

//----------------------------//
// Reward structure
//----------------------------//
static const bool scooby_enable_hbw_reward = true;
static const bool scooby_enable_reward_out_of_bounds = true;

static const int32_t scooby_reward_correct_timely = 20;
static const int32_t scooby_reward_hbw_correct_timely = 20;
static const int32_t scooby_reward_correct_untimely = 12;
static const int32_t scooby_reward_hbw_correct_untimely = 12;
static const int32_t scooby_reward_incorrect = -8;
static const int32_t scooby_reward_hbw_incorrect = -14;
static const int32_t scooby_reward_none = -4;
static const int32_t scooby_reward_hbw_none = -2;
static const int32_t scooby_reward_out_of_bounds = -12;
static const int32_t scooby_reward_hbw_out_of_bounds = -12;

static const bool scooby_enable_reward_all = false;         // deprecated
static const bool scooby_enable_reward_tracker_hit = false; // deprecated
static const int32_t scooby_reward_tracker_hit = -2;        // deprecated
static const int32_t scooby_reward_hbw_tracker_hit = -2;    // deprecated

//----------------------------//
// Knobs to gain visibility
//----------------------------//
// static const bool scooby_access_debug = false;
// static const bool scooby_print_access_debug = false;
// static const uint64_t scooby_print_access_debug_pc = 0xdeadbeef;
// static const uint32_t scooby_print_access_debug_pc_count = 1000000;
// static const bool scooby_print_trace = false;

//----------------------------//
// Knobs defining the RL engine
//----------------------------//
static const bool scooby_enable_featurewise_engine = true;
static const bool scooby_brain_zero_init = false;
static const bool scooby_enable_track_multiple = false; // deprecated
static const uint32_t scooby_state_type = 1;
static const bool scooby_enable_state_action_stats = true; // deprecated -- CHECK
static const uint32_t scooby_state_hash_type = 11;
static const uint32_t scooby_pref_degree = 1; // deprecated
static const bool scooby_enable_dyn_degree = true;
static const std::vector<float> scooby_max_to_avg_q_thresholds = {0.5, 1, 2}; // this is most-likely deprecated
static const std::vector<int32_t> scooby_dyn_degrees = {1, 2, 4, 4};          // deprecated -- CHECK
static const uint64_t scooby_early_exploration_window = 0;                    // deprecated
static const uint32_t scooby_multi_deg_select_type = 2;                       // deprecated
static const std::vector<int32_t> scooby_last_pref_offset_conf_thresholds = {1, 3, 8};
static const std::vector<int32_t> scooby_dyn_degrees_type2 = {1, 2, 4, 6}; // this is the final one in-use
static const uint32_t scooby_action_tracker_size = 2;
static const uint32_t scooby_high_bw_thresh = 4;                                           // deprecated -- CHECK
static const std::vector<int32_t> scooby_last_pref_offset_conf_thresholds_hbw = {1, 3, 8}; // deprecated
static const std::vector<int32_t> scooby_dyn_degrees_type2_hbw = {1, 2, 4, 6};             // deprecated

//------------------------------------//
// Knobs for generic learning engine
//------------------------------------//
// static const bool le_enable_trace;
// static const uint32_t le_trace_interval;
// static const std::string le_trace_file_name;
// static const uint32_t le_trace_state;
// static const bool le_enable_score_plot;
// static const std::vector<int32_t> le_plot_actions;
// static const std::string le_plot_file_name;
// static const bool le_enable_action_trace;
// static const uint32_t le_action_trace_interval;
// static const std::string le_action_trace_name;
// static const bool le_enable_action_plot;

//------------------------------------//
// Knobs for featurewise learning engine
//------------------------------------//
static const std::vector<int32_t> le_featurewise_active_features = {0, 10};
static const std::vector<int32_t> le_featurewise_num_tilings = {3, 3};
static const std::vector<int32_t> le_featurewise_num_tiles = {12, 128};
static const std::vector<int32_t> le_featurewise_hash_types = {2, 2};
static const std::vector<int32_t> le_featurewise_enable_tiling_offset = {1, 1};
static const float le_featurewise_max_q_thresh = 0.50;
static const bool le_featurewise_enable_action_fallback = true;                   // deprecated
static const std::vector<float> le_featurewise_feature_weights = {1.0, 1.0};      // deprecated
static const bool le_featurewise_enable_dynamic_weight = false;                   // deprecated
static const float le_featurewise_weight_gradient = (float)0.001;                 // deprecated
static const bool le_featurewise_disable_adjust_weight_all_features_align = true; // deprecated
static const bool le_featurewise_selective_update = false;                        // deprecated
static const uint32_t le_featurewise_pooling_type = 2;
static const bool le_featurewise_enable_dyn_action_fallback = true;
static const uint32_t le_featurewise_bw_acc_check_level = 1;
static const uint32_t le_featurewise_acc_thresh = 2;

// tracing and plotting
// static const bool le_featurewise_enable_trace;
// static const uint32_t le_featurewise_trace_feature_type;
// static const std::string le_featurewise_trace_feature;
// static const uint32_t le_featurewise_trace_interval;
// static const uint32_t le_featurewise_trace_record_count;
// static const std::string le_featurewise_trace_file_name;
// static const bool le_featurewise_enable_score_plot;
// static const std::vector<int32_t> le_featurewise_plot_actions;
// static const std::string le_featurewise_plot_file_name;
// static const bool le_featurewise_remove_plot_script;

} // namespace PYTHIA

#endif /* __PYTHIA_PARAMS_H__ */
