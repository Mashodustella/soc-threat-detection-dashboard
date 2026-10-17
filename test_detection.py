import pandas as pd

def detect_bruteforce(df, threshold=5):
    failures = df[df["Result"].str.lower() == "failure"]
    grouped = failures.groupby(["User", "IPAddress"]).size().reset_index(name="FailedAttempts")
    return grouped[grouped["FailedAttempts"] >= threshold]

if __name__ == "__main__":
    df = pd.read_csv("data/signin_events.csv")
    detections = detect_bruteforce(df, threshold=5)
    assert not detections.empty, "Expected at least one detection group"
    assert ((detections["User"] == "alice") & (detections["IPAddress"] == "203.0.113.50")).any()
    assert (detections["FailedAttempts"] >= 5).all()
    print("PASS: expected brute-force groups were detected.")
