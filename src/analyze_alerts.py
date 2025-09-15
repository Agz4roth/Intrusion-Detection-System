import sqlite3
import pandas as pd
import matplotlib.pyplot as plt

DB_PATH = "data/ids.db"

def load_data():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM alerts", conn)
    conn.close()
    df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
    return df

def show_summary(df):
    print("\n--- Severity Distribution ---")
    print(df["severity"].value_counts())

    print("\n--- Top Source IPs ---")
    print(df["src_ip"].value_counts().head(5))

    print("\n--- Average Reputation Score ---")
    print(df["rep_score"].mean())

def plot_alerts_over_time(df):
    hourly = df.set_index("timestamp").resample("1h").size()
    plt.figure(figsize=(10, 4))
    plt.plot(hourly, marker="o", linestyle="-", color="red")
    plt.title("Alerts Over Time (Hourly)")
    plt.xlabel("Time")
    plt.ylabel("Number of Alerts")
    plt.grid(True)
    plt.tight_layout()
    plt.savefig("alerts_over_time.png")
    print("Chart saved as alerts_over_time.png")


def main():
    df = load_data()
    show_summary(df)
    plot_alerts_over_time(df)

if __name__ == "__main__":
    main()
