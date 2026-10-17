# SOC Threat Detection Dashboard

Beginner-friendly SC-200 portfolio project for analysing synthetic sign-in events and identifying possible brute-force activity.

## What it does

- Loads simulated sign-in records from `data/signin_events.csv`.
- Shows total events, failed sign-ins, successful sign-ins, and potential detection groups.
- Charts sign-in outcomes and failed events by source IP.
- Flags a user/IP pair when failed attempts meet a configurable threshold.
- Provides filters and a CSV export.
- Includes separate Microsoft Sentinel KQL examples in `kql/sentinel_queries.kql`.

## Important scope and safety

This is a local simulation. It does not connect to Microsoft Sentinel, ingest real logs, block an IP, or perform incident response. The dataset is fabricated; the IP addresses use documentation ranges. A detection is a lead for investigation, not proof of compromise.

## Requirements

- Python 3.10 or newer
- Visual Studio Code or another code editor
- Internet connection only to install packages

## Run locally

1. Download and unzip the project.
2. Open the `soc-threat-detection-dashboard` folder in VS Code.
3. Open a terminal in that folder.
4. Create a virtual environment:

   Windows:
   ```powershell
   py -m venv .venv
   .venv\Scripts\Activate.ps1
   ```

   macOS/Linux:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

5. Install dependencies:
   ```bash
   python -m pip install -r requirements.txt
   ```

6. Run the dashboard:
   ```bash
   streamlit run app.py
   ```

7. Streamlit will print a local URL, normally `http://localhost:8501`. Open it in your browser.

If `streamlit` is not found, try:
```bash
python -m streamlit run app.py
```

## Sample data fields

| Field | Meaning |
|---|---|
| TimeGenerated | Synthetic UTC event timestamp |
| User | Fictional account name |
| IPAddress | Documentation-range sample IP |
| Result | Success or Failure |
| Reason | Synthetic result reason |
| Application | VPN, WebPortal, or Email |
| EventID | Unique event identifier |
| IsSynthetic | Marks records as simulated |

## Detection logic

The dashboard groups failed events by user and source IP. If the count meets the selected threshold (default 5), it raises a potential brute-force detection group. It then checks whether the same user/IP has a success event at or after the last failure in the selected data. This simplified logic is intended for learning and should be enhanced before any production use.

## Testing checklist

- [ ] Dashboard opens without errors.
- [ ] Total events is greater than zero.
- [ ] Filtering to `Failure` reduces the event table to failed records.
- [ ] Increasing the threshold reduces or keeps the same number of detection groups.
- [ ] The `alice` / `203.0.113.50` group is flagged at threshold 5.
- [ ] A success is shown for that group in the synthetic data and marked for review.
- [ ] CSV export downloads the filtered events.
- [ ] No real credentials, personal data, or live indicators are included.

## Microsoft Sentinel extension

The KQL file is for a Sentinel workspace with the `SigninLogs` table populated. It will not run directly against the local CSV. To test it in Sentinel, use an authorised training workspace with the appropriate data connector configured.

To create a workbook:
1. Open Microsoft Sentinel in the Microsoft Defender portal or Azure portal as available in your environment.
2. Select **Workbooks** and create a new workbook.
3. Add a query element with **Logs / Log Analytics** as the data source and select your workspace.
4. Paste one KQL query from `kql/sentinel_queries.kql`.
5. Select a suitable visualization, such as a table or time chart.
6. Save the workbook with the name **SOC Threat Detection Dashboard**.

Workspace permissions and ingestion costs may apply. Check your Azure pricing and budgets before enabling data collection.

## Suggested repository structure

```text
soc-threat-detection-dashboard/
├── app.py
├── requirements.txt
├── README.md
├── data/
│   └── signin_events.csv
├── kql/
│   └── sentinel_queries.kql
└── screenshots/
```

## Portfolio description

**SOC Threat Detection Dashboard | Python, Streamlit, Pandas, KQL**

Built a beginner security operations dashboard using synthetic authentication logs. Implemented filtering, event summaries, failed-login analysis, threshold-based brute-force detection, and exportable investigation data. Documented equivalent Microsoft Sentinel KQL queries for workspace-based threat hunting. This project demonstrates introductory SIEM concepts, log analysis, detection logic, and security incident triage.

## Future improvements

- Add a time-range filter.
- Add detection severity and analyst case status.
- Add unit tests for the detection logic.
- Add a proper time-window correlation rule.
- Rebuild the visualisations as a Microsoft Sentinel workbook when workspace access is available.
