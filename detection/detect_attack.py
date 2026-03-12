import joblib
import pandas as pd

# Load trained model
model = joblib.load("models/ids_model.pkl")

# Example network traffic sample
sample = {
    "protocol":17,
    "flow_duration":1000,
    "total_forward_packets":10,
    "total_backward_packets":2,
    "total_forward_packets_length":500,
    "total_backward_packets_length":200,
    "forward_packet_length_mean":50,
    "backward_packet_length_mean":100,
    "forward_packets_per_second":5,
    "backward_packets_per_second":2,
    "forward_iat_mean":100,
    "backward_iat_mean":50,
    "flow_iat_mean":75,
    "flow_packets_per_seconds":7,
    "flow_bytes_per_seconds":700
}

df = pd.DataFrame([sample])

prediction = model.predict(df)

if prediction[0] == 1:
    print("⚠ Attack Detected!")
else:
    print("Normal Traffic")