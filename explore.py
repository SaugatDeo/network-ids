import pandas as pd
import numpy as np
import os

# Load training and testing sets
train_path = "data/archive/UNSW_NB15_training-set.csv"
test_path = "data/archive/UNSW_NB15_testing-set.csv"

train_df = pd.read_csv(train_path)
test_df = pd.read_csv(test_path)

print(f"Training set shape: {train_df.shape}")
print(f"Testing set shape: {test_df.shape}")
print(f"\nColumns: {train_df.columns.tolist()}")
print(f"\nAttack categories:")
print(train_df['attack_cat'].value_counts())
print(f"\nLabel distribution:")
print(train_df['label'].value_counts())
print(f"\nMissing values: {train_df.isnull().sum().sum()}")