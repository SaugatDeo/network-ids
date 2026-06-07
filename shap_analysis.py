import pandas as pd
import numpy as np
import shap
import joblib
import matplotlib.pyplot as plt
import os

# ── Load saved model and preprocessors ───────────────────────────────────────
print("Loading model and preprocessors...")
model = joblib.load("model/xgb_model.pkl")
scaler = joblib.load("model/scaler.pkl")
encoders = joblib.load("model/encoders.pkl")
feature_names = joblib.load("model/feature_names.pkl")

# ── Load and preprocess test data ─────────────────────────────────────────────
print("Loading test data...")
test_df = pd.read_csv("data/archive/UNSW_NB15_testing-set.csv")
test_df = test_df.drop(columns=['id', 'attack_cat'])

cat_cols = ['proto', 'service', 'state']
for col in cat_cols:
    le = encoders[col]
    test_df[col] = test_df[col].astype(str).map(
        lambda x: x if x in le.classes_ else le.classes_[0]
    )
    test_df[col] = le.transform(test_df[col])

X_test = test_df.drop(columns=['label'])
X_test_scaled = scaler.transform(X_test)

# ── Use a sample for SHAP (full dataset is too large) ─────────────────────────
print("Computing SHAP values on sample...")
sample_size = 500
np.random.seed(42)
sample_idx = np.random.choice(len(X_test_scaled), sample_size, replace=False)
X_sample = X_test_scaled[sample_idx]

# ── Create SHAP explainer ─────────────────────────────────────────────────────
explainer = shap.TreeExplainer(model)
shap_values = explainer.shap_values(X_sample)

# ── Plot 1 — Feature importance (summary plot) ────────────────────────────────
print("Generating SHAP summary plot...")
os.makedirs("plots", exist_ok=True)

plt.figure(figsize=(10, 8))
shap.summary_plot(
    shap_values,
    X_sample,
    feature_names=feature_names,
    show=False
)
plt.title("SHAP Feature Importance — Network Intrusion Detection")
plt.tight_layout()
plt.savefig("plots/shap_summary.png", dpi=150, bbox_inches='tight')
plt.close()
print("Saved: plots/shap_summary.png")

# ── Plot 2 — Bar plot (mean absolute SHAP values) ─────────────────────────────
plt.figure(figsize=(10, 8))
shap.summary_plot(
    shap_values,
    X_sample,
    feature_names=feature_names,
    plot_type="bar",
    show=False
)
plt.title("Mean SHAP Values — Top Features")
plt.tight_layout()
plt.savefig("plots/shap_bar.png", dpi=150, bbox_inches='tight')
plt.close()
print("Saved: plots/shap_bar.png")

# ── Print top 10 most important features ──────────────────────────────────────
mean_shap = np.abs(shap_values).mean(axis=0)
feature_importance = pd.DataFrame({
    'feature': feature_names,
    'mean_shap': mean_shap
}).sort_values('mean_shap', ascending=False)

print("\nTop 10 Most Important Features:")
print("-" * 40)
print(feature_importance.head(10).to_string(index=False))

print("\nSHAP analysis complete.")