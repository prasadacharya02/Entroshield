# ============================================================
# ENTROPY - DQN Trainer
# ai/trainer.py
#
# WHAT THIS DOES:
# Trains the DQN model using the generated training data.
#
# TRAINING PROCESS:
# 1. Load training data (600 samples)
# 2. For each sample, create a simulated environment
# 3. Run DQN through the experience
# 4. Calculate reward (correct=positive, wrong=negative)
# 5. Train the network
# 6. Repeat for many episodes
# 7. Save the trained model
# ============================================================

from __future__ import annotations

import os
import sys
import json
import random
import time

import numpy as np

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from ai.dqn_model import DQNAgent, FeatureExtractor


# ============================================================
# REWARD FUNCTION
# Defines what is good and bad behavior for the AI.
# ============================================================

def calculate_reward(action: int, true_label: int,
                     threat_score: float) -> float:
    """Calculate reward for the DQN action.

    REWARD TABLE:
    ─────────────────────────────────────────────────
    Situation                    │ Action  │ Reward
    ─────────────────────────────┼─────────┼────────
    Ransomware + Terminate+Quar  │ 3       │ +50
    Ransomware + Terminate       │ 2       │ +40
    Ransomware + Alert only      │ 1       │ +10
    Ransomware + Ignore          │ 0       │ -100
    Normal + Ignore              │ 0       │ +20
    Normal + Alert               │ 1       │ -10
    Normal + Terminate           │ 2       │ -50
    Normal + Terminate+Quarantine│ 3       │ -80
    ─────────────────────────────────────────────────
    """
    is_ransomware = (true_label == 1)

    if is_ransomware:
        if action == config.ACTION_TERMINATE_QUARANTINE:
            return 50.0    # Perfect response
        elif action == config.ACTION_TERMINATE:
            return 40.0    # Good response
        elif action == config.ACTION_ALERT:
            return 10.0    # Partial response
        else:  # IGNORE
            return -100.0  # Catastrophic failure
    else:
        if action == config.ACTION_IGNORE:
            return 20.0    # Correct (no false alarm)
        elif action == config.ACTION_ALERT:
            return -10.0   # Minor false positive
        elif action == config.ACTION_TERMINATE:
            return -50.0   # Major false positive
        else:  # TERMINATE + QUARANTINE
            return -80.0   # Severe false positive


# ============================================================
# TRAINING ENVIRONMENT
# ============================================================

class SecurityEnvironment:
    """Simulated security environment for DQN training."""

    def __init__(self, training_data: list):
        self.training_data = list(training_data)
        self.feature_extractor = FeatureExtractor()
        self.current_sample = None
        self.step_count = 0

    def reset(self) -> np.ndarray:
        self.current_sample = random.choice(self.training_data)
        self.step_count = 0
        return self.feature_extractor.extract_from_dict(self.current_sample)

    def step(self, action: int):
        self.step_count += 1
        true_label = self.current_sample.get('label', 0)
        threat_score = self._estimate_threat_score()
        reward = calculate_reward(action, true_label, threat_score)
        self.current_sample = random.choice(self.training_data)
        next_state = self.feature_extractor.extract_from_dict(self.current_sample)
        return next_state, reward, True

    def _estimate_threat_score(self) -> float:
        entropy = self.current_sample.get('entropy_score', 0)
        speed = self.current_sample.get('files_per_sec', 0)
        delta = self.current_sample.get('entropy_delta', 0)
        score = 0.0
        if entropy >= 7.5:
            score += 40
        if speed >= 5.0:
            score += 30
        if delta >= 2.0:
            score += 30
        return min(score, 100.0)


# ============================================================
# TRAINER
# ============================================================

class DQNTrainer:
    """Trains the DQN agent."""

    def __init__(self, training_data: list):
        self.training_data = list(training_data)
        self.agent = DQNAgent()
        self.env = SecurityEnvironment(self.training_data)

    def train(self, num_episodes: int = 1500):
        print()
        print("=" * 60)
        print("  ENTROPY - DQN Training")
        print("=" * 60)
        print(f"  Training samples : {len(self.training_data)}")
        print(f"  Episodes         : {num_episodes}")
        print(f"  Batch size       : {config.BATCH_SIZE}")
        print(f"  Learning rate    : {config.LEARNING_RATE}")
        print(f"  Device           : {self.agent.device}")
        print("=" * 60)
        print()

        episode_rewards = []
        correct_decisions = 0
        total_decisions = 0
        start_time = time.time()

        for episode in range(num_episodes):
            self.agent.episode = episode
            state = self.env.reset()
            action = self.agent.select_action(state, training=True)
            next_state, reward, done = self.env.step(action)
            self.agent.store_experience(state, action, reward, next_state, done)
            self.agent.train_step()
            episode_rewards.append(reward)

            true_label = self.env.current_sample.get('label', 0)
            if self._is_correct_action(action, true_label):
                correct_decisions += 1
            total_decisions += 1

            if (episode + 1) % 250 == 0:
                recent_reward = float(np.mean(episode_rewards[-250:]))
                accuracy = correct_decisions / max(total_decisions, 1)
                stats = self.agent.get_stats()
                elapsed = time.time() - start_time
                print(f"  Episode {episode+1:5d}/{num_episodes} | "
                      f"Reward: {recent_reward:7.2f} | "
                      f"Accuracy: {accuracy:.1%} | "
                      f"Epsilon: {stats['epsilon']:.4f} | "
                      f"Elapsed: {elapsed:.1f}s")
                correct_decisions = 0
                total_decisions = 0

        elapsed = time.time() - start_time
        print()
        print("=" * 60)
        print(f"  Training Complete in {elapsed:.1f} seconds!")
        print("=" * 60)

        self.agent.save()
        print("  Model weights successfully saved to ai/dqn_weights.pth!")

        self._evaluate()
        return self.agent

    def _is_correct_action(self, action: int, true_label: int) -> bool:
        if true_label == 1:
            return action in (config.ACTION_TERMINATE, config.ACTION_TERMINATE_QUARANTINE)
        return action in (config.ACTION_IGNORE, config.ACTION_ALERT)

    def _evaluate(self, num_samples: int = 200):
        """Evaluate the trained model on random samples."""
        print()
        print("  Evaluation Results:")
        print("  " + "-" * 40)

        normal_correct = ransom_correct = 0
        normal_total = ransom_total = 0

        test_samples = random.sample(
            self.training_data, min(num_samples, len(self.training_data))
        )
        for sample in test_samples:
            state = self.env.feature_extractor.extract_from_dict(sample)
            action = self.agent.select_action(state, training=False)
            true_label = sample.get('label', 0)
            if true_label == 0:
                normal_total += 1
                if action in (config.ACTION_IGNORE, config.ACTION_ALERT):
                    normal_correct += 1
            else:
                ransom_total += 1
                if action in (config.ACTION_TERMINATE, config.ACTION_TERMINATE_QUARANTINE):
                    ransom_correct += 1

        normal_acc = normal_correct / max(normal_total, 1)
        ransom_acc = ransom_correct / max(ransom_total, 1)
        overall = (normal_correct + ransom_correct) / max(normal_total + ransom_total, 1)

        print(f"  Normal files accuracy  : {normal_correct}/{normal_total} = {normal_acc:.1%}")
        print(f"  Ransomware accuracy    : {ransom_correct}/{ransom_total} = {ransom_acc:.1%}")
        print(f"  Overall accuracy       : {overall:.1%}")
        print()


# ============================================================
# STANDALONE TRAINING SCRIPT
# ============================================================

def _load_training_samples(path: str) -> list:
    """Robustly load training samples from JSON (dict or list form)."""
    with open(path, 'r', encoding='utf-8') as f:
        raw = json.load(f)

    if isinstance(raw, list):
        return [s for s in raw if isinstance(s, dict)]
    if isinstance(raw, dict):
        for key in ('samples', 'data'):
            if key in raw and isinstance(raw[key], list):
                return [s for s in raw[key] if isinstance(s, dict)]
        lists = [v for v in raw.values() if isinstance(v, list)]
        if lists:
            return [s for s in lists[0] if isinstance(s, dict)]
    return []


if __name__ == "__main__":
    training_file = os.path.join(config.TRAINING_DATA_DIR, "training_data.json")

    if not os.path.exists(training_file):
        print(f"ERROR: Training data not found at {training_file}")
        print()
        print("Run first:")
        print("  python data/ransomware_simulator.py  -> option 5 (Generate training data)")
        sys.exit(1)

    print(f"Loading training data from: {training_file}")

    # Prefer schema-validated loader, fall back to robust JSON loader.
    try:
        from data.training_schema import load_samples, validate_sample
        training_data = [s for s in load_samples(training_file) if validate_sample(s)]
    except Exception:
        training_data = _load_training_samples(training_file)

    if not training_data:
        print("ERROR: No usable training samples found.")
        sys.exit(2)

    print(f"Loaded {len(training_data)} samples.")
    normal_count = sum(1 for d in training_data if d.get('label') == 0)
    ransom_count = sum(1 for d in training_data if d.get('label') == 1)
    print(f"  Normal    : {normal_count}")
    print(f"  Ransomware: {ransom_count}")

    trainer = DQNTrainer(training_data)
    agent = trainer.train(num_episodes=1500)
    print()
    print("Training complete!")
    print(f"Model saved to: {getattr(agent, 'model_path', 'ai/dqn_weights.pth')}")
