class LogClassifier:
    def __init__(self, model_path="models/log_model.pkl"):
        import joblib
        # Load the pre-trained ML model from disk
        self.model = joblib.load(model_path)

    def extract_features(self, log_line: str) -> list:
        # Simple feature extraction:
        # - Length of the log line
        # - Presence of the keyword 'failed'
        # - Presence of the keyword 'root'
        # - Count of numeric characters in the log
        return [
            len(log_line),
            int("failed" in log_line.lower()),
            int("root" in log_line.lower()),
            sum(c.isdigit() for c in log_line)
        ]

    def predict(self, log_line: str) -> str:
        # Convert the log line into features and predict its label
        features = self.extract_features(log_line)
        return self.model.predict([features])[0]
