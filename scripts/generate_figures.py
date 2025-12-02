#!/usr/bin/env python3
"""
Generate research paper figures for phishing detection system.

Figures:
1. Confusion Matrix (SpamAssassin Spam_2 validation)
2. Prototype Architecture Diagram
3. Performance Comparison Chart
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import seaborn as sns
from pathlib import Path
import json

# Set publication-quality style
plt.style.use('seaborn-v0_8-paper')
sns.set_palette("husl")

# Output directory
FIGURES_DIR = Path(__file__).parent.parent / "docs" / "figures"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)


def create_confusion_matrix():
    """
    Generate confusion matrix for SpamAssassin Spam_2 dataset validation.
    F1: 91.74%, Precision: 100%, Recall: 84.74%
    """
    print("Creating confusion matrix figure...")

    # Actual values from validation
    tp = 1183  # True Positives (correctly identified spam)
    fp = 0     # False Positives (legitimate marked as spam)
    tn = 0     # True Negatives (legitimate correctly identified) - None in spam-only dataset
    fn = 213   # False Negatives (missed spam)

    # Create figure
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Confusion Matrix Heatmap
    confusion_matrix = np.array([[tn, fp], [fn, tp]])
    labels = np.array([['TN\n0', 'FP\n0'], ['FN\n213', 'TP\n1,183']])

    sns.heatmap(confusion_matrix, annot=labels, fmt='', cmap='RdYlGn',
                cbar_kws={'label': 'Count'}, ax=ax1, vmin=0, vmax=1396,
                linewidths=2, linecolor='black', square=True, annot_kws={"size": 14, "weight": "bold"})

    ax1.set_xlabel('Predicted Label', fontsize=12, fontweight='bold')
    ax1.set_ylabel('Actual Label', fontsize=12, fontweight='bold')
    ax1.set_title('Confusion Matrix\nSpamAssassin Spam_2 (N=1,396)', fontsize=14, fontweight='bold')
    ax1.set_xticklabels(['CLEAN', 'MALICIOUS'], fontsize=11)
    ax1.set_yticklabels(['CLEAN', 'MALICIOUS'], fontsize=11, rotation=0)

    # Performance Metrics Bar Chart
    metrics = ['Precision', 'Recall', 'F1 Score', 'Accuracy']
    values = [100.0, 84.74, 91.74, 84.74]
    colors = ['#2ecc71', '#3498db', '#9b59b6', '#f39c12']

    bars = ax2.barh(metrics, values, color=colors, edgecolor='black', linewidth=1.5)
    ax2.set_xlabel('Percentage (%)', fontsize=12, fontweight='bold')
    ax2.set_title('Performance Metrics\n(Metadata-Only, Rules-Based)', fontsize=14, fontweight='bold')
    ax2.set_xlim(0, 105)
    ax2.grid(axis='x', alpha=0.3, linestyle='--')

    # Add value labels on bars
    for bar, value in zip(bars, values):
        ax2.text(value + 1, bar.get_y() + bar.get_height()/2,
                f'{value:.2f}%', va='center', fontsize=11, fontweight='bold')

    plt.tight_layout()
    output_path = FIGURES_DIR / "figure1_confusion_matrix.png"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"  ✓ Saved: {output_path}")
    plt.close()


def create_architecture_diagram():
    """
    Generate system architecture diagram for research paper.
    """
    print("Creating prototype architecture diagram...")

    fig, ax = plt.subplots(figsize=(12, 10))
    ax.axis('off')
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 12)

    # Title
    ax.text(5, 11.5, 'HIPAA-Compliant Phishing Triage System Architecture',
            ha='center', fontsize=16, fontweight='bold')

    # Layer 1: Input Sources
    ax.text(5, 10.5, 'INPUT LAYER', ha='center', fontsize=11, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.5', facecolor='lightblue', edgecolor='black', linewidth=2))

    input_sources = ['User Reports', 'Email Gateway', 'Microsoft Defender', 'SIEM Exports']
    for i, source in enumerate(input_sources):
        x = 1.5 + i * 2
        rect = mpatches.FancyBboxPatch((x-0.6, 9.3), 1.2, 0.6,
                                       boxstyle="round,pad=0.1",
                                       edgecolor='black', facecolor='#e8f4f8', linewidth=1.5)
        ax.add_patch(rect)
        ax.text(x, 9.6, source, ha='center', va='center', fontsize=8, weight='bold')
        ax.arrow(x, 9.3, 0, -0.5, head_width=0.15, head_length=0.2, fc='black', ec='black')

    # Layer 2: Email Parser (Metadata Extraction)
    ax.text(5, 8.3, 'METADATA EXTRACTION LAYER (HIPAA-Compliant)', ha='center',
            fontsize=11, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.5', facecolor='#ffe6cc', edgecolor='black', linewidth=2))

    parser_box = mpatches.FancyBboxPatch((1.5, 6.8), 7, 1.2,
                                         boxstyle="round,pad=0.15",
                                         edgecolor='black', facecolor='#fff4e6', linewidth=2)
    ax.add_patch(parser_box)
    ax.text(5, 7.6, 'Email Parser', ha='center', fontsize=10, weight='bold')
    ax.text(5, 7.2, 'Extracts: Headers | Auth (SPF/DKIM/DMARC) | Sender IP | URLs | Attachment Metadata',
            ha='center', fontsize=7, style='italic')
    ax.text(5, 6.9, 'NO EMAIL BODY CONTENT (PHI Protection)', ha='center', fontsize=7,
            weight='bold', color='red')

    ax.arrow(5, 6.8, 0, -0.5, head_width=0.2, head_length=0.2, fc='black', ec='black', linewidth=2)

    # Layer 3: Ensemble Verdict Engine
    ax.text(5, 6.0, 'ENSEMBLE VERDICT ENGINE', ha='center', fontsize=11, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.5', facecolor='#d5f4e6', edgecolor='black', linewidth=2))

    # Three components of ensemble
    components = [
        ('Rule-Based\nScoring', 2, '#c8e6c9',
         'SPF/DKIM Fail: +20\nURL Shorteners: +15\nRisky Attachments: +20\nUrgency Keywords: +12'),
        ('Local LLM\n(Ollama)', 5, '#b3e5fc',
         'Metadata-only\nanalysis\nNo cloud API\nHIPAA-compliant'),
        ('Microsoft\nDefender Signals', 8, '#f8bbd0',
         'ThreatTypes\nDeliveryAction\nBCL Score\nDetection Tech')
    ]

    for label, x, color, details in components:
        # Main box
        rect = mpatches.FancyBboxPatch((x-0.9, 4.2), 1.8, 1.5,
                                       boxstyle="round,pad=0.1",
                                       edgecolor='black', facecolor=color, linewidth=2)
        ax.add_patch(rect)
        ax.text(x, 5.4, label, ha='center', va='center', fontsize=9, weight='bold')
        ax.text(x, 4.5, details, ha='center', va='center', fontsize=6, style='italic')

        # Arrow to next layer
        ax.arrow(x, 4.2, 0, -0.5, head_width=0.15, head_length=0.15, fc='black', ec='black')

    # Weights annotation
    ax.text(5, 3.5, '50% Rules + 50% LLM (Ensemble Weights)', ha='center', fontsize=8,
            style='italic', bbox=dict(boxstyle='round,pad=0.3', facecolor='yellow', alpha=0.5))

    # Layer 4: Verdict Calculation
    ax.text(5, 3.0, 'VERDICT DECISION LAYER', ha='center', fontsize=11, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.5', facecolor='#e1bee7', edgecolor='black', linewidth=2))

    verdict_box = mpatches.FancyBboxPatch((2, 1.8), 6, 0.9,
                                          boxstyle="round,pad=0.1",
                                          edgecolor='black', facecolor='#f3e5f5', linewidth=2)
    ax.add_patch(verdict_box)
    ax.text(5, 2.5, 'Confidence Threshold Routing', ha='center', fontsize=9, weight='bold')
    ax.text(5, 2.15, '≥75%: Auto-Resolve | 40-74%: Analyst Review | <40%: Auto-Clean',
            ha='center', fontsize=7, style='italic')

    ax.arrow(5, 1.8, 0, -0.4, head_width=0.2, head_length=0.15, fc='black', ec='black', linewidth=2)

    # Layer 5: Output Actions
    ax.text(5, 1.2, 'OUTPUT LAYER', ha='center', fontsize=11, fontweight='bold',
            bbox=dict(boxstyle='round,pad=0.5', facecolor='#ffccbc', edgecolor='black', linewidth=2))

    outputs = [
        ('Auto-Block\nMALICIOUS', 1.8, '#ef5350'),
        ('Analyst\nReview Queue', 4.2, '#ffa726'),
        ('Auto-Resolve\nCLEAN', 6.6, '#66bb6a')
    ]

    for label, x, color in outputs:
        rect = mpatches.FancyBboxPatch((x-0.6, 0.1), 1.2, 0.7,
                                       boxstyle="round,pad=0.1",
                                       edgecolor='black', facecolor=color, linewidth=1.5)
        ax.add_patch(rect)
        ax.text(x, 0.45, label, ha='center', va='center', fontsize=7, weight='bold', color='white')

    # Add audit logging annotation
    ax.text(9.5, 5, 'Audit\nLogging', ha='center', fontsize=7, weight='bold',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='lightgray', edgecolor='black'))
    ax.annotate('', xy=(8.5, 4.5), xytext=(9.3, 5),
                arrowprops=dict(arrowstyle='->', lw=1.5, color='gray'))

    # Add performance annotation
    ax.text(0.5, 7.4, '91.74% F1\n100% Precision\n84.74% Recall\n(Spam_2)',
            ha='center', fontsize=7, weight='bold',
            bbox=dict(boxstyle='round,pad=0.3', facecolor='#c8e6c9', edgecolor='black'))

    plt.tight_layout()
    output_path = FIGURES_DIR / "figure2_architecture.png"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"  ✓ Saved: {output_path}")
    plt.close()


def create_multi_dataset_comparison():
    """
    Generate multi-dataset performance comparison chart.
    """
    print("Creating multi-dataset comparison chart...")

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5))

    # Dataset 1: Performance on different datasets
    datasets = ['SpamAssassin\nSpam_2', 'Easy Ham\n(Sample)', 'Hard Ham']
    precision = [100.0, 0.0, 0.0]  # Precision values
    recall = [84.74, 0.0, 0.0]  # Recall values
    f1 = [91.74, 0.0, 0.0]  # F1 scores

    x = np.arange(len(datasets))
    width = 0.25

    bars1 = ax1.bar(x - width, precision, width, label='Precision', color='#2ecc71', edgecolor='black')
    bars2 = ax1.bar(x, recall, width, label='Recall', color='#3498db', edgecolor='black')
    bars3 = ax1.bar(x + width, f1, width, label='F1 Score', color='#9b59b6', edgecolor='black')

    ax1.set_ylabel('Percentage (%)', fontweight='bold')
    ax1.set_title('Performance Across Multiple Datasets\n(Metadata-Only, Rules-Based)', fontweight='bold')
    ax1.set_xticks(x)
    ax1.set_xticklabels(datasets)
    ax1.legend()
    ax1.set_ylim(0, 110)
    ax1.grid(axis='y', alpha=0.3, linestyle='--')

    # Add value labels
    for bars in [bars1, bars2, bars3]:
        for bar in bars:
            height = bar.get_height()
            if height > 0:
                ax1.text(bar.get_x() + bar.get_width()/2., height + 2,
                        f'{height:.1f}%', ha='center', va='bottom', fontsize=8)

    # Dataset 2: False Positive Rate Comparison
    datasets2 = ['Spam_2\n(N=1,396)', 'Easy Ham\n(N=500)', 'Hard Ham\n(N=251)']
    fp_rates = [0.0, 93.40, 97.61]
    colors = ['#2ecc71', '#e74c3c', '#c0392b']

    bars = ax2.bar(datasets2, fp_rates, color=colors, edgecolor='black', linewidth=1.5)
    ax2.set_ylabel('False Positive Rate (%)', fontweight='bold')
    ax2.set_title('False Positive Rate Analysis\n(Critical Finding)', fontweight='bold', color='red')
    ax2.set_ylim(0, 105)
    ax2.grid(axis='y', alpha=0.3, linestyle='--')

    # Add value labels and threshold line
    for bar, value in zip(bars, fp_rates):
        ax2.text(bar.get_x() + bar.get_width()/2, value + 2,
                f'{value:.2f}%', ha='center', va='bottom', fontsize=10, fontweight='bold')

    ax2.axhline(y=10, color='orange', linestyle='--', linewidth=2, label='Acceptable Threshold (10%)')
    ax2.legend()

    plt.tight_layout()
    output_path = FIGURES_DIR / "figure3_multi_dataset_comparison.png"
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"  ✓ Saved: {output_path}")
    plt.close()


def main():
    """Generate all figures for research paper"""
    print("\n" + "="*70)
    print(" RESEARCH PAPER FIGURE GENERATION")
    print("="*70 + "\n")

    create_confusion_matrix()
    create_architecture_diagram()
    create_multi_dataset_comparison()

    print("\n" + "="*70)
    print(" FIGURE GENERATION COMPLETE")
    print("="*70)
    print(f"\nAll figures saved to: {FIGURES_DIR}")
    print("\nGenerated figures:")
    print("  1. figure1_confusion_matrix.png - Confusion matrix + metrics (SpamAssassin Spam_2)")
    print("  2. figure2_architecture.png - System architecture diagram")
    print("  3. figure3_multi_dataset_comparison.png - Multi-dataset performance comparison")
    print("\nThese figures are ready to be included in the research paper.")
    print("Recommended placement:")
    print("  - Figure 1: Section 4 (Results)")
    print("  - Figure 2: Section 3 (Methods) or Section 5.3 (Prototype)")
    print("  - Figure 3: Section 4 (Results) or Section 6 (Discussion)")
    print("")


if __name__ == "__main__":
    main()
