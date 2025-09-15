import requests

class IPReputationChecker:
    def __init__(self, api_key, threshold=50, debug_mode=False):
        self.api_key = api_key
        self.threshold = threshold
        self.debug_mode = debug_mode
        self.url = "https://api.abuseipdb.com/api/v2/check"
        self.headers = {
            "Key": self.api_key,
            "Accept": "application/json"
        }

    def _debug(self, msg):
        if self.debug_mode:
            print(f"[DEBUG] {msg}")

    def check_ip(self, ip):
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }
        try:
            response = requests.get(self.url, headers=self.headers, params=params)
            data = response.json()

            if "data" in data and "abuseConfidenceScore" in data["data"]:
                score = data["data"]["abuseConfidenceScore"]
                self._debug(f"AbuseIPDB raw response for {ip}: {score}")
                return score
            else:
                print(f"[LOG] IP reputation check failed: Unexpected response format → {data}")
                return None

        except Exception as e:
            print(f"[LOG] IP reputation check failed: {e}")
            return None

    def is_malicious(self, ip):
        score = self.check_ip(ip)
        if score is not None:
            self._debug(f"AbuseIPDB score for {ip}: {score}")
            return score >= self.threshold
        return False
