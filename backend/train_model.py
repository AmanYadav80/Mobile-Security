import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib
import os

print("[*] Using standard Kaggle dataset to train a new model.")

# --- Part 1: Load the Standard Dataset ---
data_path = os.path.join('data', 'Phishing_Legitimate_full.csv')

try:
    df = pd.read_csv(data_path)
except FileNotFoundError:
    print(f"[!] ERROR: Dataset not found at '{data_path}'")
    print("[!] Please download it from Kaggle and place it in your 'backend/data' folder.")
    exit()

# The dataset already has features extracted. We will use a few key ones.
# 1 = Phishing, 0 = Legitimate
features_to_use = [
    'NumDots',
    'SubdomainLevel',
    'PathLevel',
    'UrlLength',
    'NumDash',
    'NumSensitiveWords',
    'PctExtHyperlinks',
    'PctExtResourceUrls',
    'InsecureForms',
    'CLASS_LABEL' # This is our target
]
df = df[features_to_use]

print(f"[*] Dataset loaded with {len(df)} samples.")

# --- Part 2: Prepare Data for the Model ---
X = df.drop('CLASS_LABEL', axis=1)
y = df['CLASS_LABEL']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# --- Part 3: Train the Model ---
print("[*] Training the RandomForest model on pre-extracted features...")
# Using parameters known to work well with this dataset
model = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# --- Part 4: Evaluate the Model ---
print("[*] Evaluating the new model...")
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)
print(f"[*] Final Model Accuracy: {accuracy * 100:.2f}%")

# --- Part 5: Save the Final Model ---
# NOTE: We don't need a vectorizer anymore because the features are already numbers.
print("[*] Saving the final model to disk...")
joblib.dump(model, 'model.joblib')

print("\n[+] Training complete! Final model based on standard dataset has been saved.")