import joblib
from sklearn.dummy import DummyClassifier

# Create a dummy model just to test your IDS
dummy_model = DummyClassifier(strategy="most_frequent")
dummy_model.fit([[0,0,0,0,0]], [0])  # dummy training data

# Save it to the models folder
joblib.dump(dummy_model, "models/trained_model.pkl")
print("Dummy model created successfully!")