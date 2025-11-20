# Ablation Study Framework

**Version:** 1.0
**Last Updated:** 2025-11-19
**Purpose:** Enable systematic testing of ensemble component contributions

---

## Overview

An **ablation study** systematically removes or disables components of a system to understand their impact on overall performance. This framework enables testing different ensemble weight configurations to:

1. Understand which components contribute most to accuracy
2. Optimize ensemble weights for specific threat types
3. Enable user-configurable verdict modes (LLM-only, Rules-only, etc.)
4. Support research and publication

---

## Current Ensemble Architecture

### Default Configuration

**File:** `config/config.yaml:13-18`

```yaml
ensemble:
  weights:
    ollama: 0.40    # LLM threat analysis
    rules: 0.30     # Rule-based scoring (SOP logic)
    defender: 0.30  # Microsoft Defender signals
```

**Implementation:** `src/core/ensemble_verdict_engine.py:38-48`

```python
self.weights = weights or {
    "ollama": 0.40,
    "rules": 0.30,
    "defender": 0.30
}

# Ensure weights sum to 1.0
total_weight = sum(self.weights.values())
if abs(total_weight - 1.0) > 0.01:
    logger.warning(f"Weights sum to {total_weight}, normalizing...")
    self.weights = {k: v/total_weight for k, v in self.weights.items()}
```

### Current Limitations

1. **Fixed weights** - Cannot easily test alternative configurations
2. **No UI for switching** - Requires config file editing
3. **No performance tracking** - Cannot compare configurations scientifically
4. **No saved presets** - Cannot quickly switch between known-good configurations

---

## Ablation Study Configurations

### Proposed Test Matrix

| Configuration | Ollama | Rules | Defender | Use Case | Expected Performance |
|---------------|--------|-------|----------|----------|---------------------|
| **LLM Only** | 100% | 0% | 0% | Maximum AI analysis | High precision, slower |
| **Rules Only** | 0% | 100% | 0% | Deterministic, fast | Fast, conservative |
| **Defender Only** | 0% | 0% | 100% | Microsoft signals only | Baseline MS accuracy |
| **Default Ensemble** | 40% | 30% | 30% | Current balanced | Balanced accuracy/speed |
| **LLM Heavy** | 60% | 20% | 20% | AI-first approach | Higher recall, slower |
| **Rules Heavy** | 20% | 50% | 30% | Rule-first approach | Fast, may miss novel threats |
| **Defender Heavy** | 20% | 20% | 60% | Trust MS signals | Good for known threats |
| **LLM + Rules** | 50% | 50% | 0% | No MS dependency | Test without Defender data |
| **LLM + Defender** | 50% | 0% | 50% | Skip manual rules | AI + threat intel |
| **Rules + Defender** | 0% | 50% | 50% | No LLM (fastest) | Fast, no AI costs |

### Research Hypotheses

**H1:** LLM-heavy configurations have higher recall (detect more phishing) but lower precision (more false positives)

**H2:** Rule-heavy configurations have faster processing time but miss novel phishing patterns

**H3:** Defender-heavy configurations perform well on known threats but poorly on zero-day attacks

**H4:** Balanced ensemble (40/30/30) optimizes accuracy vs. speed trade-off

---

## Implementation Architecture

### Configuration Manager

**File to create:** `src/core/ensemble_config_manager.py`

```python
class EnsembleConfigManager:
    """
    Manage ensemble weight configurations and presets
    """

    PRESETS = {
        "llm_only": {"ollama": 1.0, "rules": 0.0, "defender": 0.0},
        "rules_only": {"ollama": 0.0, "rules": 1.0, "defender": 0.0},
        "defender_only": {"ollama": 0.0, "rules": 0.0, "defender": 1.0},
        "default": {"ollama": 0.40, "rules": 0.30, "defender": 0.30},
        "llm_heavy": {"ollama": 0.60, "rules": 0.20, "defender": 0.20},
        "rules_heavy": {"ollama": 0.20, "rules": 0.50, "defender": 0.30},
        "defender_heavy": {"ollama": 0.20, "rules": 0.20, "defender": 0.60},
        "no_defender": {"ollama": 0.50, "rules": 0.50, "defender": 0.0},
        "no_rules": {"ollama": 0.50, "rules": 0.0, "defender": 0.50},
        "no_llm": {"ollama": 0.0, "rules": 0.50, "defender": 0.50},
    }

    def __init__(self, config_path: str = "config/ensemble_configs.yaml"):
        """
        Load ensemble configurations from YAML

        Args:
            config_path: Path to ensemble configs YAML file
        """
        self.config_path = config_path
        self.custom_configs = self._load_custom_configs()

    def _load_custom_configs(self) -> Dict[str, Dict]:
        """Load user-defined custom configurations"""

    def get_config(self, config_name: str) -> Dict[str, float]:
        """
        Get ensemble weights by name

        Args:
            config_name: Preset name or custom config name

        Returns:
            Weight dictionary {ollama: float, rules: float, defender: float}

        Raises:
            ValueError: If config_name not found
        """
        if config_name in self.PRESETS:
            return self.PRESETS[config_name].copy()
        elif config_name in self.custom_configs:
            return self.custom_configs[config_name].copy()
        else:
            raise ValueError(f"Configuration '{config_name}' not found")

    def list_configs(self) -> List[str]:
        """Return list of available configuration names"""
        return list(self.PRESETS.keys()) + list(self.custom_configs.keys())

    def save_custom_config(self, name: str, weights: Dict[str, float]):
        """
        Save a custom weight configuration

        Args:
            name: Config name
            weights: Weight dictionary

        Validates that weights sum to 1.0
        """

    def validate_weights(self, weights: Dict[str, float]) -> bool:
        """
        Validate weight configuration

        Checks:
        - All components present (ollama, rules, defender)
        - All weights >= 0
        - Weights sum to 1.0 (within tolerance)

        Returns:
            True if valid, False otherwise
        """
```

### Configuration File Format

**File to create:** `config/ensemble_configs.yaml`

```yaml
# Ensemble Weight Configurations
# Each configuration must have weights that sum to 1.0

# Built-in presets (do not modify)
presets:
  llm_only:
    ollama: 1.0
    rules: 0.0
    defender: 0.0
    description: "LLM-only analysis (slowest, most thorough)"

  rules_only:
    ollama: 0.0
    rules: 1.0
    defender: 0.0
    description: "Rule-based only (fastest, deterministic)"

  defender_only:
    ollama: 0.0
    rules: 0.0
    defender: 1.0
    description: "Microsoft Defender signals only (baseline)"

  default:
    ollama: 0.40
    rules: 0.30
    defender: 0.30
    description: "Balanced ensemble (recommended)"

# Custom user configurations
custom:
  high_security:
    ollama: 0.50
    rules: 0.30
    defender: 0.20
    description: "Prioritize AI analysis for high-security environments"

  fast_triage:
    ollama: 0.10
    rules: 0.45
    defender: 0.45
    description: "Minimize LLM calls for faster processing"

# Ablation study test matrix
ablation_study:
  llm_heavy:
    ollama: 0.60
    rules: 0.20
    defender: 0.20

  rules_heavy:
    ollama: 0.20
    rules: 0.50
    defender: 0.30

  defender_heavy:
    ollama: 0.20
    rules: 0.20
    defender: 0.60

  no_defender:
    ollama: 0.50
    rules: 0.50
    defender: 0.0

  no_rules:
    ollama: 0.50
    rules: 0.0
    defender: 0.50

  no_llm:
    ollama: 0.0
    rules: 0.50
    defender: 0.50
```

---

## Ablation Study Runner

### Evaluation Framework

**File to create:** `src/evaluation/ablation_study.py`

```python
class AblationStudy:
    """
    Run systematic ablation studies across ensemble configurations
    """

    def __init__(
        self,
        dataset_path: str,
        ground_truth_manager: GroundTruthManager,
        config_manager: EnsembleConfigManager
    ):
        """
        Initialize ablation study

        Args:
            dataset_path: Path to normalized evaluation dataset
            ground_truth_manager: Ground truth labels
            config_manager: Ensemble configuration manager
        """
        self.dataset_path = dataset_path
        self.ground_truth = ground_truth_manager
        self.config_manager = config_manager

    def run_ablation_study(
        self,
        config_names: List[str] = None,
        email_count: int = None
    ) -> Dict[str, Any]:
        """
        Run ablation study across multiple configurations

        Args:
            config_names: List of config names to test (default: all presets)
            email_count: Number of emails to test (default: all)

        Returns:
            {
                "study_metadata": {
                    "dataset": str,
                    "email_count": int,
                    "configs_tested": int,
                    "timestamp": str
                },
                "results": {
                    "llm_only": {
                        "metrics": {...},
                        "resource_usage": {...},
                        "verdict_distribution": {...}
                    },
                    "rules_only": {...},
                    ...
                },
                "comparative_analysis": {
                    "best_config_precision": str,
                    "best_config_recall": str,
                    "best_config_f1": str,
                    "fastest_config": str,
                    "most_accurate_config": str
                },
                "recommendations": List[str]
            }
        """

    def compare_configs(self, results: Dict) -> Dict[str, Any]:
        """
        Compare configurations across metrics

        Returns:
            {
                "precision_ranking": [(config_name, precision), ...],
                "recall_ranking": [(config_name, recall), ...],
                "f1_ranking": [(config_name, f1), ...],
                "speed_ranking": [(config_name, emails_per_sec), ...],
                "trade_off_analysis": {
                    "accuracy_vs_speed": [...],
                    "precision_vs_recall": [...]
                }
            }
        """

    def generate_recommendations(self, results: Dict) -> List[str]:
        """
        Generate actionable recommendations from ablation study

        Examples:
        - "For high-security environments, use 'llm_heavy' (F1: 94%, slower by 2x)"
        - "For high-volume triage, use 'no_llm' (F1: 88%, 10x faster)"
        - "Default ensemble provides best balance (F1: 91%, 3s avg)"
        """

    def plot_results(self, results: Dict, output_dir: str):
        """
        Generate visualization plots

        Creates:
        - Precision-Recall curves for each config
        - F1 scores bar chart
        - Processing time comparison
        - Trade-off scatter plot (accuracy vs speed)
        - Component contribution stacked bar chart
        """

    def export_results(self, results: Dict, output_path: str):
        """
        Export results to JSON, CSV, and Markdown

        Files created:
        - ablation_study_results.json (full results)
        - ablation_study_metrics.csv (metrics table)
        - ablation_study_report.md (summary report)
        - ablation_study_plots/ (visualizations)
        """
```

### Usage Example

```python
from src.evaluation.ablation_study import AblationStudy
from src.datasets.ground_truth_manager import GroundTruthManager
from src.core.ensemble_config_manager import EnsembleConfigManager

# Initialize
config_manager = EnsembleConfigManager()
ground_truth = GroundTruthManager()

study = AblationStudy(
    dataset_path="data/established_datasets/nazario_phishing/normalized/",
    ground_truth_manager=ground_truth,
    config_manager=config_manager
)

# Run ablation study on all preset configurations
results = study.run_ablation_study(
    config_names=["llm_only", "rules_only", "defender_only", "default", "llm_heavy", "rules_heavy"],
    email_count=1000  # Test on 1000 emails
)

# Print summary
print("\n=== Ablation Study Results ===\n")
for config_name, config_results in results["results"].items():
    metrics = config_results["metrics"]
    resources = config_results["resource_usage"]

    print(f"{config_name}:")
    print(f"  Precision: {metrics['precision']:.2%}")
    print(f"  Recall: {metrics['recall']:.2%}")
    print(f"  F1 Score: {metrics['f1_score']:.2%}")
    print(f"  Avg Time: {resources['avg_time_per_email']:.2f}s")
    print()

# Best configurations
print("\n=== Recommendations ===")
for rec in results["recommendations"]:
    print(f"- {rec}")

# Export results
study.export_results(results, "results/ablation_studies/nazario_phishing_ablation.json")
study.plot_results(results, "results/ablation_studies/plots/")
```

---

## User Interface for Configuration Switching

### Command-Line Interface

**File to modify:** `src/main.py` or create `src/cli/ensemble_config_cli.py`

```python
import argparse
from src.core.ensemble_config_manager import EnsembleConfigManager

def main():
    parser = argparse.ArgumentParser(description="Email Triage Automation")

    # Existing arguments...
    parser.add_argument("--config", type=str, default="default",
                        help="Ensemble configuration preset (default: 'default')")
    parser.add_argument("--list-configs", action="store_true",
                        help="List available ensemble configurations")
    parser.add_argument("--show-config", type=str,
                        help="Show details of a specific configuration")

    args = parser.parse_args()

    config_manager = EnsembleConfigManager()

    if args.list_configs:
        print("\n=== Available Ensemble Configurations ===\n")
        for config_name in config_manager.list_configs():
            print(f"  - {config_name}")
        return

    if args.show_config:
        weights = config_manager.get_config(args.show_config)
        print(f"\nConfiguration: {args.show_config}")
        print(f"  Ollama (LLM):  {weights['ollama']*100:.0f}%")
        print(f"  Rules:         {weights['rules']*100:.0f}%")
        print(f"  Defender:      {weights['defender']*100:.0f}%")
        return

    # Load selected configuration
    weights = config_manager.get_config(args.config)
    print(f"\nUsing ensemble configuration: {args.config}")
    print(f"  Ollama: {weights['ollama']*100:.0f}% | Rules: {weights['rules']*100:.0f}% | Defender: {weights['defender']*100:.0f}%")

    # Initialize engine with selected weights
    ollama = OllamaSecurityAnalyst()
    engine = EnsembleVerdictEngine(ollama, weights=weights)

    # Continue with normal processing...
```

### Example Usage

```bash
# List available configurations
python src/main.py --list-configs

# Show specific configuration
python src/main.py --show-config llm_heavy

# Run with custom configuration
python src/main.py --config llm_only --input data/test_emails.csv

# Run with rules-only (fastest)
python src/main.py --config rules_only --input data/bulk_emails.csv

# Run default
python src/main.py --input data/emails.csv  # Uses 'default' config
```

---

## Dashboard Integration

### Real-Time Configuration Switching

**File to modify:** `src/dashboard/app.py`

Add configuration selector to dashboard:

```python
from src.core.ensemble_config_manager import EnsembleConfigManager

config_manager = EnsembleConfigManager()

# Streamlit UI
st.sidebar.title("Ensemble Configuration")
selected_config = st.sidebar.selectbox(
    "Select Configuration",
    options=config_manager.list_configs(),
    index=config_manager.list_configs().index("default")
)

# Show weights
weights = config_manager.get_config(selected_config)
st.sidebar.metric("Ollama Weight", f"{weights['ollama']*100:.0f}%")
st.sidebar.metric("Rules Weight", f"{weights['rules']*100:.0f}%")
st.sidebar.metric("Defender Weight", f"{weights['defender']*100:.0f}%")

# Use selected configuration
engine = EnsembleVerdictEngine(ollama, weights=weights)
```

### Custom Configuration Builder

```python
st.sidebar.subheader("Custom Configuration")

ollama_weight = st.sidebar.slider("Ollama Weight (%)", 0, 100, 40)
rules_weight = st.sidebar.slider("Rules Weight (%)", 0, 100, 30)
defender_weight = 100 - ollama_weight - rules_weight

st.sidebar.metric("Defender Weight (auto)", f"{defender_weight}%")

if st.sidebar.button("Save Custom Config"):
    custom_weights = {
        "ollama": ollama_weight / 100.0,
        "rules": rules_weight / 100.0,
        "defender": defender_weight / 100.0
    }

    config_name = st.sidebar.text_input("Config Name")
    if config_name:
        config_manager.save_custom_config(config_name, custom_weights)
        st.sidebar.success(f"Saved '{config_name}'")
```

---

## Expected Research Outputs

### Academic Publication Support

The ablation study framework enables:

1. **Component Contribution Analysis**
   - Quantify importance of each component (LLM, Rules, Defender)
   - Compare ensemble vs. individual components
   - Justify ensemble approach scientifically

2. **Optimal Configuration Discovery**
   - Data-driven weight selection
   - Trade-off analysis (accuracy vs. speed vs. cost)
   - Environment-specific recommendations

3. **Reproducible Experiments**
   - Standardized test matrix
   - Automated evaluation pipeline
   - Exportable results in publication-ready format

### Example Research Questions

1. **RQ1:** What is the marginal contribution of each ensemble component to overall accuracy?
   - Test: Compare default vs. single-component configs

2. **RQ2:** What is the optimal weight distribution for minimizing false negatives?
   - Test: Sweep weight ranges, optimize for recall

3. **RQ3:** How much does LLM analysis improve over rule-based systems alone?
   - Test: Compare rules_only vs. default vs. llm_heavy

4. **RQ4:** What is the trade-off between accuracy and processing time?
   - Test: Plot F1 score vs. emails/sec across all configs

---

## Implementation Roadmap

### Phase 1: Configuration Management (Week 1)

- [ ] Implement `EnsembleConfigManager` class
- [ ] Create `config/ensemble_configs.yaml` with presets
- [ ] Add CLI arguments for config selection
- [ ] Unit tests for config validation

### Phase 2: Ablation Study Runner (Week 1-2)

- [ ] Implement `AblationStudy` class
- [ ] Create evaluation metrics tracking
- [ ] Build comparison and ranking logic
- [ ] Implement visualization (plots)

### Phase 3: Dashboard Integration (Week 2)

- [ ] Add config selector to Streamlit dashboard
- [ ] Implement custom config builder UI
- [ ] Add real-time weight adjustment
- [ ] Display performance predictions for each config

### Phase 4: Research Execution (Week 3)

- [ ] Run full ablation study on all datasets
- [ ] Analyze results and identify optimal configs
- [ ] Generate publication-quality plots and tables
- [ ] Document findings in research paper

### Phase 5: Production Deployment (Week 4)

- [ ] Deploy recommended configurations
- [ ] Add config switching to production UI
- [ ] Monitor performance metrics in production
- [ ] Iterate based on real-world feedback

---

## Success Metrics

After implementing this framework, you will achieve:

1. ✅ **Quantified component contributions** - Know exactly how much each component helps
2. ✅ **Optimized weights** - Data-driven configuration selection
3. ✅ **User flexibility** - Toggle between modes (fast vs. accurate vs. balanced)
4. ✅ **Research publication** - Reproducible ablation study results
5. ✅ **Continuous improvement** - Framework for testing new components

---

**Document Version:** 1.0
**Status:** Design Complete - Implementation Pending
**Dependencies:** Dataset integration, metrics calculator
**Next Steps:** Implement Phase 1 (Configuration Management)
