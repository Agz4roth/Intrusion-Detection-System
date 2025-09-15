from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Sample log lines representing system activity (both benign and malicious)
logs = [
    "Failed password for root from 45.134.20.55 port 2222 ssh2",  # suspicious login attempt
    "Accepted password for user from 192.168.1.10 port 22 ssh2",  # normal login
    "DROP connection from suspicious IP",                         # firewall drop event
    "Normal system activity detected"                             # benign system message
]

# Corresponding labels for each log line
labels = ["malicious", "benign", "malicious", "benign"]

# Feature extraction function: converts a log line into a numeric feature vector
def extract_features(log_line):
    return [
        len(log_line),                              # total length of the log line
        int("failed" in log_line.lower()),          # presence of the word 'failed'
        int("root" in log_line.lower()),            # presence of the word 'root'
        sum(c.isdigit() for c in log_line)          # count of numeric characters
    ]

# Generate feature matrix and label vector
X = [extract_features(line) for line in logs]
y = labels

# Train a Random Forest classifier on the sample data
model = RandomForestClassifier()
model.fit(X, y)

# Save the trained model to disk for later use in the IDS
joblib.dump(model, "models/log_model.pkl")
