import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  LearningInventoryItem,
  ControlledExperiment,
  DistributionShiftResult,
  LearningDataset,
} from '../types';

describe('Prompt 38: Controlled Experiments and Defensible Adaptive Learning Frontend Tests', () => {
  it('should fetch adaptive learning inventory with zero online self-tuning', async () => {
    const mockInventory: LearningInventoryItem[] = [
      {
        component_name: 'False Positive Predictor',
        prediction_type: 'FALSE_POSITIVE_LIKELIHOOD',
        objective: 'Classifies incoming scanner observations',
        input_features: ['severity', 'confidence', 'target_length'],
        decision_impact: 'Triage prioritization',
        governance_mode: 'SUPERVISED_OFFLINE',
        online_self_tuning: false,
      },
      {
        component_name: 'Exploitation Probability Engine',
        prediction_type: 'EXPLOITATION_PROBABILITY',
        objective: 'Forecasts threat exploitation probability',
        input_features: ['cve_id', 'epss_score'],
        decision_impact: 'Risk scoring',
        governance_mode: 'SUPERVISED_OFFLINE',
        online_self_tuning: false,
      },
    ];

    vi.spyOn(api, 'getLearningInventory').mockResolvedValue(mockInventory);

    const res = await api.getLearningInventory();
    expect(res.length).toBe(2);
    expect(res[0].component_name).toBe('False Positive Predictor');
    expect(res[0].online_self_tuning).toBe(false);
    expect(res[1].online_self_tuning).toBe(false);
  });

  it('should curate time-aware dataset using chronological ordering', async () => {
    const mockDataset: LearningDataset = {
      id: 'ds-chrono-1',
      project_id: 'proj-1',
      name: 'Time-Aware Benchmark',
      version: 'v1.0.0',
      dataset_hash: 'sha256-hash-chrono',
      total_records: 100,
      train_count: 70,
      val_count: 15,
      test_count: 15,
      created_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'curateTimeAwareDataset').mockResolvedValue(mockDataset);

    const res = await api.curateTimeAwareDataset('proj-1', 'Time-Aware Benchmark', 'v1.0.0', 'TEMPORAL_AWARE');
    expect(res.id).toBe('ds-chrono-1');
    expect(res.total_records).toBe(100);
    expect(res.train_count).toBe(70);
    expect(res.test_count).toBe(15);
  });

  it('should execute controlled benchmark experiment on held-out test data', async () => {
    const mockExp: ControlledExperiment = {
      id: 'exp-1',
      project_id: 'proj-1',
      model_id: 'model-1',
      dataset_id: 'ds-chrono-1',
      experiment_name: 'Empirical Holdout Evaluation',
      split_strategy: 'TEMPORAL_AWARE',
      training_sample_size: 70,
      test_sample_size: 15,
      class_imbalance_ratio: 1.0,
      data_leakage_detected: false,
      leakage_details: [],
      insufficient_data_flag: false,
      metrics: {
        f1_score: 0.92,
        brier_score: 0.04,
        expected_calibration_error: 0.02,
      },
      distribution_shift_detected: false,
      decision_outcome: 'ACCEPTED',
      decision_rationale: 'Evaluated cleanly on held-out test partition with zero leakage.',
      created_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'runControlledExperiment').mockResolvedValue(mockExp);

    const res = await api.runControlledExperiment('proj-1', {
      model_id: 'model-1',
      experiment_name: 'Empirical Holdout Evaluation',
      split_strategy: 'TEMPORAL_AWARE',
    });

    expect(res.decision_outcome).toBe('ACCEPTED');
    expect(res.data_leakage_detected).toBe(false);
    expect(res.metrics.f1_score).toBe(0.92);
    expect(res.metrics.brier_score).toBe(0.04);
  });

  it('should reject candidate model when data leakage is detected', async () => {
    const mockLeakageExp: ControlledExperiment = {
      id: 'exp-2',
      project_id: 'proj-1',
      model_id: 'model-2',
      dataset_id: 'ds-chrono-1',
      experiment_name: 'Leakage Evaluation',
      split_strategy: 'TEMPORAL_AWARE',
      training_sample_size: 70,
      test_sample_size: 15,
      class_imbalance_ratio: 1.0,
      data_leakage_detected: true,
      leakage_details: ['Temporal leakage detected: test record precedes train record'],
      insufficient_data_flag: false,
      metrics: {},
      distribution_shift_detected: false,
      decision_outcome: 'REJECTED_LEAKAGE',
      decision_rationale: 'Data leakage detected between training and test partitions.',
      created_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'runControlledExperiment').mockResolvedValue(mockLeakageExp);

    const res = await api.runControlledExperiment('proj-1', {
      model_id: 'model-2',
      experiment_name: 'Leakage Evaluation',
    });

    expect(res.data_leakage_detected).toBe(true);
    expect(res.decision_outcome).toBe('REJECTED_LEAKAGE');
    expect(res.leakage_details[0]).toContain('Temporal leakage detected');
  });

  it('should flag insufficient data rather than fabricating synthetic metrics', async () => {
    const mockLowSampleExp: ControlledExperiment = {
      id: 'exp-3',
      project_id: 'proj-1',
      model_id: 'model-3',
      dataset_id: 'ds-tiny',
      experiment_name: 'Low Sample Size Run',
      split_strategy: 'TEMPORAL_AWARE',
      training_sample_size: 4,
      test_sample_size: 2,
      class_imbalance_ratio: 1.0,
      data_leakage_detected: false,
      leakage_details: [],
      insufficient_data_flag: true,
      metrics: {},
      distribution_shift_detected: false,
      decision_outcome: 'REJECTED_INSUFFICIENT_DATA',
      decision_rationale: 'Sample size is below minimum statistical significance threshold (< 10 samples).',
      created_at: new Date().toISOString(),
    };

    vi.spyOn(api, 'runControlledExperiment').mockResolvedValue(mockLowSampleExp);

    const res = await api.runControlledExperiment('proj-1', {
      model_id: 'model-3',
      experiment_name: 'Low Sample Size Run',
    });

    expect(res.insufficient_data_flag).toBe(true);
    expect(res.decision_outcome).toBe('REJECTED_INSUFFICIENT_DATA');
  });

  it('should detect distribution shift without automatically applying model updates', async () => {
    const mockShift: DistributionShiftResult = {
      model_id: 'model-1',
      project_id: 'proj-1',
      distribution_shift_detected: true,
      evaluated_count: 50,
      accuracy_rate: 0.65,
      brier_score: 0.18,
      status: 'SHIFT_DETECTED',
      recommended_action: 'Review recent prediction failures; curate fresh time-aware dataset before evaluating candidate update.',
    };

    vi.spyOn(api, 'detectDistributionShift').mockResolvedValue(mockShift);

    const res = await api.detectDistributionShift('proj-1', 'model-1');
    expect(res.distribution_shift_detected).toBe(true);
    expect(res.status).toBe('SHIFT_DETECTED');
    expect(res.recommended_action).toContain('curate fresh time-aware dataset');
  });
});
