import pandas as pd

# Load dataset
data = pd.read_csv("dataset/DrDoS_DNS.csv")

print("Dataset Shape:", data.shape)

print("\nFirst 5 rows:")
print(data.head())

print("\nColumns:")
print(data.columns)

print("\nLabel Counts:")
print(data['label'].value_counts())

import matplotlib.pyplot as plt
import seaborn as sns

# Plot label distribution
plt.figure(figsize=(6,4))
sns.countplot(x='label', data=data)

plt.title("Attack vs Normal Traffic")
plt.xlabel("Traffic Type")
plt.ylabel("Count")

plt.show()

#Prepare Data for Machine Learning
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Convert label to numeric
data['label'] = data['label'].apply(lambda x: 0 if x == "BENIGN" else 1)

# Separate features and labels
X = data.drop('label', axis=1)
y = data['label']

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

print("Training data:", X_train.shape)
print("Testing data:", X_test.shape)

# Feature scaling
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

print("Data preprocessing completed")

#Build the AI Model
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# Convert label to numeric
data['label'] = data['label'].apply(lambda x: 0 if x == "BENIGN" else 1)

X = data.drop('label', axis=1)
y = data['label']

# Train test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Predict
predictions = model.predict(X_test)

print(classification_report(y_test, predictions))


plt.show()