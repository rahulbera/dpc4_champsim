#include "learning_engine_featurewise.h"

#include <assert.h>
#include <iostream>
#include <numeric>
#include <strings.h>
#include <vector>

#include "util/util.h"

void LearningEngineFeaturewise::init_knobs()
{
  assert(PYTHIA::le_featurewise_active_features.size() == PYTHIA::le_featurewise_num_tilings.size());
  assert(PYTHIA::le_featurewise_active_features.size() == PYTHIA::le_featurewise_num_tiles.size());
  assert(PYTHIA::le_featurewise_active_features.size() == PYTHIA::le_featurewise_enable_tiling_offset.size());
  assert(PYTHIA::le_featurewise_active_features.size() == PYTHIA::le_featurewise_feature_weights.size());
  if (PYTHIA::le_featurewise_enable_dyn_action_fallback) {
    assert(PYTHIA::le_featurewise_enable_action_fallback);
  }
}

void LearningEngineFeaturewise::init_stats() {}

LearningEngineFeaturewise::LearningEngineFeaturewise(float alpha, float gamma, float epsilon, uint32_t actions, uint64_t seed, std::string policy,
                                                     std::string type, bool zero_init)
    : LearningEngineBase(alpha, gamma, epsilon, actions, 0 /*dummy state value*/, seed, policy, type)
{
  /* init each feature engine */
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    m_feature_knowledges[index] = NULL;
  }
  for (uint32_t index = 0; index < PYTHIA::le_featurewise_active_features.size(); ++index) {
    assert(PYTHIA::le_featurewise_active_features[index] < NumFeatureTypes);
    m_feature_knowledges[PYTHIA::le_featurewise_active_features[index]] = new FeatureKnowledge(
        (FeatureType)PYTHIA::le_featurewise_active_features[index], alpha, gamma, actions, PYTHIA::le_featurewise_feature_weights[index],
        PYTHIA::le_featurewise_weight_gradient, PYTHIA::le_featurewise_num_tilings[index], PYTHIA::le_featurewise_num_tiles[index], zero_init,
        PYTHIA::le_featurewise_hash_types[index], PYTHIA::le_featurewise_enable_tiling_offset[index], PYTHIA::le_featurewise_enable_action_fallback);
    assert(m_feature_knowledges[PYTHIA::le_featurewise_active_features[index]]);
  }

  m_max_q_value = (double)1 / (1 - gamma) * (double)std::accumulate(PYTHIA::le_featurewise_num_tilings.begin(), PYTHIA::le_featurewise_num_tilings.end(), 0);
  /* init Q-value buckets */
  m_q_value_buckets.push_back((-1) * 0.50 * m_max_q_value);
  m_q_value_buckets.push_back((-1) * 0.25 * m_max_q_value);
  m_q_value_buckets.push_back((-1) * 0.00 * m_max_q_value);
  m_q_value_buckets.push_back((+1) * 0.25 * m_max_q_value);
  m_q_value_buckets.push_back((+1) * 0.50 * m_max_q_value);
  m_q_value_buckets.push_back((+1) * 1.00 * m_max_q_value);
  m_q_value_buckets.push_back((+1) * 2.00 * m_max_q_value);
  /* init histogram */
  m_q_value_histogram.resize(m_q_value_buckets.size() + 1, 0);

  /* init random generators */
  m_generator.seed(m_seed);
  m_explore = new std::bernoulli_distribution(epsilon);
  m_actiongen = new std::uniform_int_distribution<int>(0, m_actions - 1);

  /* init stats */
  bzero(&stats, sizeof(stats));
}

LearningEngineFeaturewise::~LearningEngineFeaturewise()
{
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (m_feature_knowledges[index])
      delete m_feature_knowledges[index];
  }
}

uint32_t LearningEngineFeaturewise::chooseAction(State* state, float& max_to_avg_q_ratio, std::vector<bool>& consensus_vec)
{
  stats.action.called++;
  uint32_t action = 0;
  max_to_avg_q_ratio = 0.0;
  consensus_vec.resize(NumFeatureTypes, false);

  if (m_type == LearningType::SARSA && m_policy == Policy::EGreedy) {
    if ((*m_explore)(m_generator)) {
      action = (*m_actiongen)(m_generator); // take random action
      stats.action.explore++;
      stats.action.dist[action][0]++;
      MYLOG("action taken %u explore, state %s, scores %s", action, state->to_string().c_str(), getStringQ(state).c_str());
    } else {
      float max_q = 0.0;
      action = getMaxAction(state, max_q, max_to_avg_q_ratio, consensus_vec);
      stats.action.exploit++;
      stats.action.dist[action][1]++;
      gather_stats(max_q, max_to_avg_q_ratio); /* for only stats collection's sake */
      MYLOG("action taken %u exploit, state %s, scores %s", action, state->to_string().c_str(), getStringQ(state).c_str());
    }
  } else {
    printf("learning_type %s policy %s not supported!\n", MapLearningTypeString(m_type), MapPolicyString(m_policy));
    assert(false);
  }

  return action;
}

void LearningEngineFeaturewise::learn(State* state1, uint32_t action1, int32_t reward, State* state2, uint32_t action2, std::vector<bool> consensus_vec,
                                      RewardType reward_type)
{
  stats.learn.called++;
  if (m_type == LearningType::SARSA && m_policy == Policy::EGreedy) {
    for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
      if (m_feature_knowledges[index]) {
        if (!PYTHIA::le_featurewise_selective_update || consensus_vec[index]) {
          m_feature_knowledges[index]->updateQ(state1, action1, reward, state2, action2);
        } else if (PYTHIA::le_featurewise_selective_update && !consensus_vec[index]) {
          stats.learn.su_skip[index]++;
        }
      }
    }

    if (PYTHIA::le_featurewise_enable_dynamic_weight) {
      adjust_feature_weights(consensus_vec, reward_type);
    }
  } else {
    printf("learning_type %s policy %s not supported!\n", MapLearningTypeString(m_type), MapPolicyString(m_policy));
    assert(false);
  }
}

uint32_t LearningEngineFeaturewise::getMaxAction(State* state, float& max_q, float& max_to_avg_q_ratio, std::vector<bool>& consensus_vec)
{
  float max_q_value = 0.0, q_value = 0.0, total_q_value = 0.0;
  uint32_t selected_action = 0, init_index = 0;

  bool fallback = do_fallback(state);

  if (!fallback) {
    max_q_value = consultQ(state, 0);
    total_q_value += max_q_value;
    init_index = 1;
  }
  for (uint32_t action = init_index; action < m_actions; ++action) {
    q_value = consultQ(state, action);
    total_q_value += q_value;
    if (q_value > max_q_value) {
      max_q_value = q_value;
      selected_action = action;
    }
  }
  if (fallback && max_q_value == 0.0) {
    stats.action.fallback++;
  }

  /* max to avg ratio calculation */
  float avg_q_value = total_q_value / (float)m_actions;
  if ((max_q_value > 0 && avg_q_value > 0) || (max_q_value < 0 && avg_q_value < 0)) {
    max_to_avg_q_ratio = FABS(max_q_value) / FABS(avg_q_value) - 1;
  } else {
    max_to_avg_q_ratio = (max_q_value - avg_q_value) / FABS(avg_q_value);
  }
  if (max_q_value < PYTHIA::le_featurewise_max_q_thresh * m_max_q_value) {
    max_to_avg_q_ratio = 0.0;
  }
  max_q = max_q_value;

  action_selection_consensus(state, selected_action, consensus_vec);

  return selected_action;
}

float LearningEngineFeaturewise::consultQ(State* state, uint32_t action)
{
  assert(action < m_actions);
  float q_value = 0.0;
  float max = -1000000000.0;

  /* pool Q-value accross all feature tables */
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (m_feature_knowledges[index]) {
      if (PYTHIA::le_featurewise_pooling_type == 1) /* sum pooling */
      {
        q_value += m_feature_knowledges[index]->retrieveQ(state, action);
      } else if (PYTHIA::le_featurewise_pooling_type == 2) /* max pooling */
      {
        float tmp = m_feature_knowledges[index]->retrieveQ(state, action);
        if (tmp >= max) {
          max = tmp;
          q_value = tmp;
        }
      } else {
        assert(false);
      }
    }
  }
  return q_value;
}

void LearningEngineFeaturewise::dump_stats()
{
  fprintf(stdout, "learning_engine_featurewise.action.called %lu\n", stats.action.called);
  fprintf(stdout, "learning_engine_featurewise.action.explore %lu\n", stats.action.explore);
  fprintf(stdout, "learning_engine_featurewise.action.exploit %lu\n", stats.action.exploit);
  fprintf(stdout, "learning_engine_featurewise.action.fallback %lu\n", stats.action.fallback);
  fprintf(stdout, "learning_engine_featurewise.action.dyn_fallback_saved_bw %lu\n", stats.action.dyn_fallback_saved_bw);
  fprintf(stdout, "learning_engine_featurewise.action.dyn_fallback_saved_bw_acc %lu\n", stats.action.dyn_fallback_saved_bw_acc);
  for (uint32_t action = 0; action < m_actions; ++action) {
    fprintf(stdout, "learning_engine_featurewise.action.index_%d_explored %lu\n", action, stats.action.dist[action][0]);
    fprintf(stdout, "learning_engine_featurewise.action.index_%d_exploited %lu\n", action, stats.action.dist[action][1]);
  }
  fprintf(stdout, "learning_engine_featurewise.learn.called %lu\n", stats.learn.called);
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (m_feature_knowledges[index]) {
      fprintf(stdout, "learning_engine_featurewise.learn.su_skip_%s %lu\n", FeatureKnowledge::getFeatureString((FeatureType)index).c_str(),
              stats.learn.su_skip[index]);
    }
  }
  fprintf(stdout, "\n");

  /* plot histogram */
  for (uint32_t index = 0; index < m_q_value_histogram.size(); ++index) {
    fprintf(stdout, "learning_engine_featurewise.q_value_histogram.bucket_%u %lu\n", index, m_q_value_histogram[index]);
  }
  fprintf(stdout, "\n");

  /* consensus stats */
  fprintf(stdout, "learning_engine_featurewise.consensus.total %lu\n", stats.consensus.total);
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (m_feature_knowledges[index]) {
      fprintf(stdout, "learning_engine_featurewise.consensus.feature_align_%s %lu\n", FeatureKnowledge::getFeatureString((FeatureType)index).c_str(),
              stats.consensus.feature_align_dist[index]);
      fprintf(stdout, "learning_engine_featurewise.consensus.feature_align_%s_ratio %0.2f\n", FeatureKnowledge::getFeatureString((FeatureType)index).c_str(),
              (float)stats.consensus.feature_align_dist[index] / (float)stats.consensus.total);
    }
  }
  fprintf(stdout, "learning_engine_featurewise.consensus.feature_align_all %lu\n", stats.consensus.feature_align_all);
  fprintf(stdout, "learning_engine_featurewise.consensus.feature_align_all_ratio %0.2f\n",
          (float)stats.consensus.feature_align_all / (float)stats.consensus.total);
  fprintf(stdout, "\n");

  /* weight stats */
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (m_feature_knowledges[index]) {
      fprintf(stdout, "learning_engine_featurewise.feature_%s_min_weight %0.8f\n", FeatureKnowledge::getFeatureString((FeatureType)index).c_str(),
              m_feature_knowledges[index]->get_min_weight());
      fprintf(stdout, "learning_engine_featurewise.feature_%s_max_weight %0.8f\n", FeatureKnowledge::getFeatureString((FeatureType)index).c_str(),
              m_feature_knowledges[index]->get_max_weight());
    }
  }
}

void LearningEngineFeaturewise::gather_stats(float max_q, float max_to_avg_q_ratio)
{
  double high = 0.0, low = 0.0;
  for (uint32_t index = 0; index < m_q_value_buckets.size(); ++index) {
    low = index ? m_q_value_buckets[index - 1] : -1000000000;
    high = (index < m_q_value_buckets.size() - 1) ? m_q_value_buckets[index + 1] : +1000000000;
    if (max_q >= low && max_q < high) {
      m_q_value_histogram[index]++;
      break;
    }
  }
}

/* consensus stats: whether each feature's maxAction decision aligns with the final selected action */
void LearningEngineFeaturewise::action_selection_consensus(State* state, uint32_t selected_action, std::vector<bool>& consensus_vec)
{
  stats.consensus.total++;
  bool all_features_align = true;
  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (m_feature_knowledges[index]) {
      if (m_feature_knowledges[index]->getMaxAction(state) == selected_action) {
        stats.consensus.feature_align_dist[index]++;
        consensus_vec[index] = true;
      } else {
        all_features_align = false;
      }
    }
  }
  if (all_features_align) {
    stats.consensus.feature_align_all++;
  }
}

void LearningEngineFeaturewise::adjust_feature_weights(std::vector<bool> consensus_vec, RewardType reward_type)
{
  assert(consensus_vec.size() == NumFeatureTypes);

  if (PYTHIA::le_featurewise_disable_adjust_weight_all_features_align
      && (uint32_t)std::accumulate(consensus_vec.begin(), consensus_vec.end(), 0) == PYTHIA::le_featurewise_active_features.size()) {
    return;
  }

  for (uint32_t index = 0; index < NumFeatureTypes; ++index) {
    if (consensus_vec[index]) /* the feature algined with the overall decision */
    {
      assert(m_feature_knowledges[index]);

      /* if the prefetch decision is indeed proven to be correct
       * increase the weight of the feature, else decrease it */
      if (isRewardCorrect(reward_type)) {
        m_feature_knowledges[index]->increase_weight();
      } else if (isRewardIncorrect(reward_type)) {
        m_feature_knowledges[index]->decrease_weight();
      }
    }
  }
}

bool LearningEngineFeaturewise::do_fallback(State* state)
{
  /* set fallback to whatever the knob value is, if dynamic fallback is turned off */
  if (!PYTHIA::le_featurewise_enable_dyn_action_fallback) {
    return PYTHIA::le_featurewise_enable_action_fallback;
  }

  if (state->is_high_bw) {
    stats.action.dyn_fallback_saved_bw++;
    return false;
  } else if (state->bw_level >= PYTHIA::le_featurewise_bw_acc_check_level && state->acc_level <= PYTHIA::le_featurewise_acc_thresh) {
    stats.action.dyn_fallback_saved_bw_acc++;
    return false;
  }

  return true;
}
