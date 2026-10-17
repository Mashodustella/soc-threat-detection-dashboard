import pandas as pd
import streamlit as st

st.set_page_config(page_title="SOC Threat Detection Dashboard", page_icon="🛡️", layout="wide")
st.title("🛡️ SOC Threat Detection Dashboard")
st.caption("Beginner portfolio project • Synthetic sign-in logs only • Detection threshold: 5 failed attempts per user/IP")

@st.cache_data
def load_data():
    df = pd.read_csv("data/signin_events.csv")
    df["TimeGenerated"] = pd.to_datetime(df["TimeGenerated"], utc=True, errors="coerce")
    df["Result"] = df["Result"].astype(str).str.strip().str.title()
    df["User"] = df["User"].astype(str)
    df["IPAddress"] = df["IPAddress"].astype(str)
    return df.dropna(subset=["TimeGenerated"])

try:
    df = load_data()
except Exception as exc:
    st.error("Could not load data/signin_events.csv. Run the app from the project folder and check the file exists.")
    st.exception(exc)
    st.stop()

st.info("Training environment: all records are fabricated. IPs use documentation ranges and are not indicators of real attackers.")

with st.sidebar:
    st.header("Filters")
    users = sorted(df["User"].unique().tolist())
    selected_users = st.multiselect("User", users, default=users)
    results = sorted(df["Result"].unique().tolist())
    selected_results = st.multiselect("Result", results, default=results)
    apps = sorted(df["Application"].unique().tolist())
    selected_apps = st.multiselect("Application", apps, default=apps)
    threshold = st.slider("Failed attempts threshold", min_value=3, max_value=10, value=5)

filtered = df[
    df["User"].isin(selected_users)
    & df["Result"].isin(selected_results)
    & df["Application"].isin(selected_apps)
].copy()

failed = filtered[filtered["Result"] == "Failure"]
success = filtered[filtered["Result"] == "Success"]

# Detection groups failures by user and source IP. It is a triage signal, not proof of compromise.
failed_by_pair = (
    failed.groupby(["User", "IPAddress"], as_index=False)
    .agg(FailedAttempts=("EventID", "count"), FirstSeen=("TimeGenerated", "min"), LastSeen=("TimeGenerated", "max"))
)
alerts = failed_by_pair[failed_by_pair["FailedAttempts"] >= threshold].copy()
alerts["Severity"] = alerts["FailedAttempts"].apply(lambda n: "High" if n >= threshold + 3 else "Medium")

# Flag a successful event for the same user/IP after a threshold-sized failure cluster.
success_pairs = success[["User", "IPAddress", "TimeGenerated"]].rename(columns={"TimeGenerated": "SuccessTime"})
if not alerts.empty and not success_pairs.empty:
    alerts = alerts.merge(success_pairs, on=["User", "IPAddress"], how="left")
    alerts["SuccessAfterFailures"] = alerts["SuccessTime"].notna() & (alerts["SuccessTime"] >= alerts["LastSeen"])
else:
    alerts["SuccessTime"] = pd.NaT
    alerts["SuccessAfterFailures"] = False

c1, c2, c3, c4 = st.columns(4)
c1.metric("Events in view", f"{len(filtered):,}")
c2.metric("Failed sign-ins", f"{len(failed):,}")
c3.metric("Successful sign-ins", f"{len(success):,}")
c4.metric("Detection groups", f"{len(alerts):,}")

left, right = st.columns(2)
with left:
    st.subheader("Sign-in outcomes")
    outcome_counts = filtered["Result"].value_counts().rename_axis("Result").reset_index(name="Events")
    if outcome_counts.empty:
        st.write("No events match the filters.")
    else:
        st.bar_chart(outcome_counts.set_index("Result"))
with right:
    st.subheader("Failed attempts by source IP")
    ip_counts = failed.groupby("IPAddress").size().sort_values(ascending=False)
    if ip_counts.empty:
        st.write("No failed events match the filters.")
    else:
        st.bar_chart(ip_counts)

st.subheader(f"Potential brute-force activity (threshold: {threshold} failures)")
if alerts.empty:
    st.success("No user/IP pair met the selected threshold in the current filtered data.")
else:
    display_alerts = alerts.copy()
    for col in ["FirstSeen", "LastSeen", "SuccessTime"]:
        if col in display_alerts.columns:
            display_alerts[col] = display_alerts[col].astype(str).replace("NaT", "—")
    display_alerts["Analyst note"] = display_alerts["SuccessAfterFailures"].map({
        True: "Review: success recorded for same user/IP after failures",
        False: "Review failed attempts; success not confirmed by this simple rule"
    })
    st.dataframe(
        display_alerts[["User", "IPAddress", "FailedAttempts", "Severity", "FirstSeen", "LastSeen", "SuccessAfterFailures", "Analyst note"]],
        use_container_width=True,
        hide_index=True
    )
    st.warning("A detection is not proof of compromise. Verify time ordering, MFA, device context, and whether the activity is expected.")

st.subheader("Recent sign-in events")
recent = filtered.sort_values("TimeGenerated", ascending=False).copy()
recent["TimeGenerated"] = recent["TimeGenerated"].astype(str)
st.dataframe(recent, use_container_width=True, hide_index=True)

st.download_button(
    "Download filtered events as CSV",
    data=filtered.to_csv(index=False).encode("utf-8"),
    file_name="filtered_signin_events.csv",
    mime="text/csv"
)

st.subheader("Detection logic")
st.code(
    f"Group failed sign-ins by User and IPAddress; flag groups with FailedAttempts >= {threshold}. "
    "If a success event exists for the same user/IP after the failures, mark it for priority review.",
    language="text"
)
st.caption("Demo only. This app does not connect to Microsoft Sentinel, block IP addresses, or perform live response.")
