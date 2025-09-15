import requests

class VirusTotalChecker:
    def __init__(self, api_key, debug_mode=False):
        self.api_key = api_key
        self.base_url = "https://www.virustotal.com/api/v3"
        self.debug_mode = debug_mode

    def _debug(self, msg):
        if self.debug_mode:
            print(f"[DEBUG] {msg}")

    def check_ip(self, ip):
        url = f"{self.base_url}/ip_addresses/{ip}"
        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers)
            data = response.json()

            if "data" in data and "attributes" in data["data"]:
                score = data["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", 0)
                self._debug(f"VirusTotal malicious score for {ip}: {score}")
                return score
            else:
                print(f"[LOG] VirusTotal IP check failed: Unexpected response format → {data}")
                return 0

        except Exception as e:
            print(f"[LOG] VirusTotal IP check failed: {e}")
            return 0

    def check_hash(self, file_hash):
        url = f"{self.base_url}/files/{file_hash}"
        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(url, headers=headers)
            data = response.json()

            if "data" in data and "attributes" in data["data"]:
                score = data["data"]["attributes"].get("last_analysis_stats", {}).get("malicious", 0)
                self._debug(f"VirusTotal malicious score for hash {file_hash}: {score}")
                return score
            else:
                print(f"[LOG] VirusTotal hash check failed: Unexpected response format → {data}")
                return 0

        except Exception as e:
            print(f"[LOG] VirusTotal hash check failed: {e}")
            return 0
