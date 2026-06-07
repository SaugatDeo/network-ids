import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import xgboost as xgb
import joblib
import os

# ── Load data ────────────────────────────────────────────────────────────────
print("Loading data...")
train_df = pd.read_csv("data/archive/UNSW_NB15_training-set.csv")
test_df = pd.read_csv("data/archive/UNSW_NB15_testing-set.csv")

# ── Drop unnecessary columns ─────────────────────────────────────────────────
drop_cols = ['id', 'attack_cat']
train_df = train_df.drop(columns=drop_cols)
test_df = test_df.drop(columns=drop_cols)

# ── Encode categorical columns ───────────────────────────────────────────────
cat_cols = ['proto', 'service', 'state']
encoders = {}

for col in cat_cols:
    le = LabelEncoder()
    train_df[col] = le.fit_transform(train_df[col].astype(str))
    # Handle unseen labels in test set
    test_df[col] = test_df[col].astype(str).map(
        lambda x: x if x in le.classes_ else le.classes_[0]
    )
    test_df[col] = le.transform(test_df[col])
    encoders[col] = le

# ── Split features and labels ────────────────────────────────────────────────
X_train = train_df.drop(columns=['label'])
y_train = train_df['label']
X_test = test_df.drop(columns=['label'])
y_test = test_df['label']

print(f"X_train shape: {X_train.shape}")
print(f"X_test shape: {X_test.shape}")

# ── Scale features ───────────────────────────────────────────────────────────
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ── Train XGBoost ────────────────────────────────────────────────────────────
print("\nTraining XGBoost model...")
model = xgb.XGBClassifier(
    n_estimators=300,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    use_label_encoder=False,
    eval_metric='logloss',
    random_state=42,
    n_jobs=-1
)

model.fit(
    X_train_scaled, y_train,
    eval_set=[(X_test_scaled, y_test)],
    verbose=50
)

# ── Evaluate ─────────────────────────────────────────────────────────────────
print("\nEvaluating...")
y_pred = model.predict(X_test_scaled)
y_prob = model.predict_proba(X_test_scaled)[:, 1]

print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))

auc = roc_auc_score(y_test, y_prob)
print(f"AUC-ROC: {auc:.4f}")

# ── Save model and preprocessors ─────────────────────────────────────────────
os.makedirs("model", exist_ok=True)
joblib.dump(model, "model/xgb_model.pkl")
joblib.dump(scaler, "model/scaler.pkl")
joblib.dump(encoders, "model/encoders.pkl")

# Save feature names
feature_names = X_train.columns.tolist()
joblib.dump(feature_names, "model/feature_names.pkl")

print("\nModel saved to model/ folder")
print(f"Features: {len(feature_names)}")