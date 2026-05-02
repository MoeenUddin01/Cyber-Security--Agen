"""Create architecture diagram showing how the CyberShield AI system works."""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

# Set up the figure
fig, ax = plt.subplots(1, 1, figsize=(14, 10))
ax.set_xlim(0, 14)
ax.set_ylim(0, 10)
ax.axis('off')

# Color scheme
colors = {
    'input': '#3b82f6',      # Blue
    'model': '#8b5cf6',      # Purple
    'agent': '#10b981',      # Green
    'threat': '#ef4444',     # Red
    'benign': '#22c55e',     # Light green
    'action': '#f59e0b',     # Orange
    'output': '#06b6d4',     # Cyan
    'bg': '#1f2937',         # Dark gray
    'text': '#ffffff'        # White
}

def draw_box(ax, x, y, width, height, text, color, fontsize=10, bold=False):
    """Draw a rounded box with text."""
    box = FancyBboxPatch((x - width/2, y - height/2), width, height,
                         boxstyle="round,pad=0.05,rounding_size=0.2",
                         facecolor=color, edgecolor='white',
                         linewidth=2, alpha=0.9)
    ax.add_patch(box)
    weight = 'bold' if bold else 'normal'
    ax.text(x, y, text, ha='center', va='center', fontsize=fontsize,
            color='white', fontweight=weight, wrap=True)

def draw_arrow(ax, x1, y1, x2, y2, color='white', style='->'):
    """Draw an arrow between two points."""
    ax.annotate('', xy=(x2, y2), xytext=(x1, y1),
                arrowprops=dict(arrowstyle='->', color=color, lw=2))

# Title
ax.text(7, 9.5, '🔒 CyberShield AI - System Architecture', 
        ha='center', va='center', fontsize=18, fontweight='bold', color='white')
ax.text(7, 9.1, 'How the Model & Agents Work Together', 
        ha='center', va='center', fontsize=12, color='#9ca3af')

# === INPUT LAYER ===
ax.text(1.5, 7.8, '📥 INPUT', ha='center', fontsize=11, 
        fontweight='bold', color=colors['input'])

draw_box(ax, 1.5, 6.8, 2.2, 1.0, 'Network Traffic\n17 Features\n(Dest Port, Flow Duration,\nPackets, Bytes...)', 
         colors['input'], fontsize=8)

draw_box(ax, 1.5, 5.5, 2.0, 0.6, 'Source IP\n(optional)', colors['input'], fontsize=9)

# === MODEL LAYER ===
ax.text(5.5, 7.8, '🧠 THREAT MODEL', ha='center', fontsize=11, 
        fontweight='bold', color=colors['model'])

draw_box(ax, 5.5, 6.5, 2.5, 1.2, 'Neural Network\nClassifier\n(PyTorch)', 
         colors['model'], fontsize=10, bold=True)

draw_box(ax, 5.5, 5.2, 2.0, 0.7, 'Output:\nThreat / Benign', 
         colors['model'], fontsize=9)

# === DECISION ===
draw_box(ax, 9, 6.5, 1.8, 1.0, 'Is Threat?', 
         '#374151', fontsize=10, bold=True)

# === AGENTS LAYER (for threats) ===
ax.text(12, 7.8, '🤖 SECURITY AGENTS', ha='center', fontsize=11, 
        fontweight='bold', color=colors['agent'])

# IP Interrogator
draw_box(ax, 12, 6.2, 2.2, 0.9, 'IP Interrogator\n• WHOIS lookup\n• Port scan', 
         colors['agent'], fontsize=8)

# AI Advisor
draw_box(ax, 12, 5.0, 2.2, 0.9, 'AI Advisor (Groq)\n• Attack analysis\n• Recommendations', 
         colors['agent'], fontsize=8)

# Mitigation Engine
draw_box(ax, 12, 3.8, 2.2, 0.9, 'Mitigation Engine\n• Block IP\n• Log incident', 
         colors['action'], fontsize=8)

# === OUTPUTS ===
ax.text(5.5, 2.8, '📤 OUTPUTS', ha='center', fontsize=11, 
        fontweight='bold', color=colors['output'])

# Threat detected output
draw_box(ax, 4, 2.0, 1.8, 0.8, '🚨 THREAT DETECTED\nAlert + Block', 
         colors['threat'], fontsize=9, bold=True)

# Benign output
draw_box(ax, 7, 2.0, 1.8, 0.8, '✅ BENIGN\nAllow traffic', 
         colors['benign'], fontsize=9, bold=True)

# Incident log
draw_box(ax, 5.5, 0.8, 2.5, 0.6, '📝 Incident Log (CSV)', 
         '#6b7280', fontsize=9)

# === ARROWS ===
# Input to Model
draw_arrow(ax, 2.6, 6.3, 4.2, 6.5)

# Model to Decision
draw_arrow(ax, 6.8, 6.5, 8.0, 6.5)

# Decision branches
draw_arrow(ax, 9.9, 6.5, 10.8, 6.2, color=colors['threat'])  # Threat path
ax.text(10.3, 6.5, 'YES', ha='center', fontsize=8, color=colors['threat'], fontweight='bold')

draw_arrow(ax, 9, 5.9, 9, 2.4, color=colors['benign'])  # Benign path
ax.text(9.2, 4.2, 'NO', ha='left', fontsize=8, color=colors['benign'], fontweight='bold')

# Threat path arrows
# IP Interrogator connections
draw_arrow(ax, 10.8, 5.7, 10.8, 5.0, color='white')
draw_arrow(ax, 10.8, 4.5, 10.8, 3.8, color='white')

# Output arrows
draw_arrow(ax, 3.0, 2.0, 4.1, 1.6, color='white')
draw_arrow(ax, 8.0, 2.0, 6.9, 1.6, color='white')

# Legend box
legend_x, legend_y = 0.3, 0.3
legend_elements = [
    ('Input Layer', colors['input']),
    ('ML Model', colors['model']),
    ('AI Agents', colors['agent']),
    ('Threat', colors['threat']),
    ('Mitigation', colors['action']),
]

for i, (label, color) in enumerate(legend_elements):
    y_pos = legend_y + i * 0.35
    ax.add_patch(plt.Rectangle((legend_x, y_pos), 0.2, 0.2, facecolor=color, edgecolor='white'))
    ax.text(legend_x + 0.3, y_pos + 0.1, label, fontsize=8, color='white', va='center')

# Workflow description
workflow_text = """
🔹 WORKFLOW:
1. Network traffic enters with 17 features
2. Neural Network classifies as Threat/Benign
3. If Benign → Traffic allowed ✓
4. If Threat → Agents activate:
   • IP Interrogator gathers intel
   • AI Advisor analyzes & recommends
   • Mitigation Engine blocks IP
5. All actions logged to CSV
"""

ax.text(10, 0.8, workflow_text, ha='left', va='center', fontsize=8,
        color='#d1d5db', family='monospace',
        bbox=dict(boxstyle='round', facecolor='#1f2937', alpha=0.8))

# Set background color
fig.patch.set_facecolor('#111827')
ax.set_facecolor('#111827')

plt.tight_layout()
plt.savefig('/home/moeen/projects/Cyber-Security--Agen/artifacts/system_architecture.png', 
            dpi=150, bbox_inches='tight', facecolor='#111827', edgecolor='none')
print("✅ Architecture diagram saved to: artifacts/system_architecture.png")
