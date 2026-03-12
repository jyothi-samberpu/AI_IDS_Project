import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.metrics import classification_report, accuracy_score

# Load dataset
data = pd.read_csv("dataset/DrDoS_DNS.csv")

# Convert labels to numbers
data['label'] = data['label'].apply(lambda x: 1 if x != "BENIGN" else 0)

# Features and labels
X = data.drop('label', axis=1)
y = data['label']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Training Samples:", X_train.shape)
print("Testing Samples:", X_test.shape)

# -------------------------
# Random Forest Model
# -------------------------

rf = RandomForestClassifier(n_estimators=100, class_weight='balanced')
rf.fit(X_train, y_train)

rf_pred = rf.predict(X_test)

print("\nRandom Forest Results")
print("Accuracy:", accuracy_score(y_test, rf_pred))
print(classification_report(y_test, rf_pred))

# -------------------------
# Support Vector Machine
# -------------------------

svm = SVC(class_weight='balanced')
svm.fit(X_train, y_train)

svm_pred = svm.predict(X_test)

print("\nSVM Results")
print("Accuracy:", accuracy_score(y_test, svm_pred))
print(classification_report(y_test, svm_pred))


import joblib

# Save trained Random Forest model
joblib.dump(rf, "models/ids_model.pkl")

print("Model saved successfully!")