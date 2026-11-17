"""
Risk Scanner -- Web Vulnerability + Payroll Fraud
==================================================

Two small, education-focused scanners live in this one file:

1. A web application scanner that checks a target for a handful of
   classic OWASP Top 10 issues: reflected XSS, SQL injection, missing
   security headers, IDOR / broken access control, privilege escalation,
   weak passwords (optional brute-force check), and a basic indicator of
   unrestricted file upload / RCE risk.

2. A payroll fraud scanner that reads a single Excel workbook containing
   an employee sheet and a payments sheet, and flags duplicate employee
   records, bank accounts shared across employees, payments made before
   the recorded hire date, and mismatches between recorded tenure and
   actual payment history.

All settings are read from environment variables below, so nothing
machine-specific or target-specific is hard-coded in the script itself.
See the README for how to set these (a .env file or your shell).
"""

import os
import time
import random
import string
from datetime import datetime

import requests
import pandas as pd


# ===========================================================================
# CONFIGURATION -- set these via environment variables, not by editing code.
# ===========================================================================

# Defaults to a local OWASP Juice Shop instance. Juice Shop is a
# deliberately vulnerable practice application maintained by OWASP; it is
# used here as a safe stand-in for a real-world site (e.g. a payroll or
# other financial web app) so the scanner can be run and demonstrated
# without pointing it at anything live or production.
WEB_TARGET = os.environ.get("RISK_SCANNER_WEB_TARGET", "http://localhost:3000")

# Wordlist for the optional brute-force check. Not included in this repo --
# supply your own path for local testing (e.g. a copy of rockyou.txt).
ROCKYOU_PATH = os.environ.get("RISK_SCANNER_WORDLIST_PATH", "wordlists/rockyou.txt")
BRUTE_FORCE_LIMIT = int(os.environ.get("RISK_SCANNER_BRUTE_FORCE_LIMIT", "200"))
BRUTE_FORCE_TARGET_EMAIL = os.environ.get("RISK_SCANNER_BRUTE_FORCE_EMAIL", "admin@juice-sh.op")

# Workbook to analyse for the payroll fraud scan. Defaults to the small
# sample workbook that ships with this repo under sample_data/.
PAYROLL_WORKBOOK_PATH = os.environ.get("RISK_SCANNER_PAYROLL_PATH", "payroll_sample.xlsx")
TENURE_MISMATCH_THRESHOLD_DAYS = int(os.environ.get("RISK_SCANNER_TENURE_THRESHOLD_DAYS", "30"))

# ===========================================================================
# SHARED REPORTING HELPERS
# ===========================================================================
SEVERITY_ORDER = { "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def print_findings(findings, empty_message):
    if not findings:
        print(f"\n[+] {empty_message}\n")
        return

    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))
    for idx, f in enumerate(findings_sorted, 1):
        print(f"\n{idx}. {f['name']}  [{f['severity']}]")
        print(f"   Evidence        : {f['evidence']}")
        if f.get("message"):
            print(f"   Description     : {f['message']}")
        print(f"   Business impact : {f['business_impact']}")
        print(f"   Root cause      : {f['root_cause']}")
        if f.get("iso_control"):
            print(f"   ISO 27001 ref   : {f['iso_control']}")
        print(f"   Remediation     : {f['remediation']}")
        if f.get("references"):
            print(f"   Further reading :")
            for ref in f["references"]:
                print(f"     - {ref}")
    print()

# ===========================================================================
# PART 1: WEB APPLICATION SCAN
# ===========================================================================

WEB_VULN_INFO = {
    "reflected_xss": {
        "name": "Reflected Cross-Site Scripting (XSS)",
        "severity": "HIGH",
        "message": "A script payload sent in a request was echoed back unescaped.",
        "iso_control": "A.14 System Acquisition, Development & Maintenance",
        "business_impact": "An attacker can craft a malicious link that, when "
                            "clicked by a logged-in user, runs arbitrary "
                            "JavaScript in their session — stealing session "
                            "cookies, defacing the page, or performing actions "
                            "as that user without their knowledge.",
        "root_cause": "User-supplied input is reflected into the HTML response "
                       "without output encoding.",
        "remediation": "Encode all user-supplied output for its context and "
                        "apply a Content-Security-Policy as defense in depth.",
        "references": [
            "https://owasp.org/www-community/attacks/xss/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ],
    },
    "sql_injection": {
        "name": "SQL Injection",
        "severity": "CRITICAL",
        "message": "A SQLi payload caused an abnormal response (auth bypass or DB error leakage).",
        "iso_control": "A.14 System Acquisition, Development & Maintenance",
        "business_impact": "An attacker can bypass authentication entirely, "
                            "or read/modify/delete arbitrary data in the "
                            "database, including other users' personal and "
                            "payment data.",
        "root_cause": "User input is concatenated directly into a SQL query "
                       "instead of being passed as a parameter.",
        "remediation": "Use parameterized queries / prepared statements or an "
                        "ORM everywhere.",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "https://portswigger.net/web-security/sql-injection",
        ],
    },
    "missing_security_headers": {
        "name": "Missing Security Headers",
        "severity": "MEDIUM",
        "message": "Response is missing one or more recommended security headers.",
        "iso_control": "A.13 Communications Security",
        "business_impact": "Missing headers make other attacks (XSS, "
                            "clickjacking, MIME-sniffing) easier to pull off.",
        "root_cause": "The application/server is not configured to emit "
                       "standard protective headers on responses.",
        "remediation": "Add Content-Security-Policy, X-Content-Type-Options, "
                        "X-Frame-Options, and Strict-Transport-Security headers.",
        "references": ["https://owasp.org/www-project-secure-headers/"],
    },
    "idor": {
        "name": "Insecure Direct Object Reference (IDOR) / Broken Access Control",
        "severity": "HIGH",
        "message": "Sequential/guessable IDs returned data belonging to other "
                    "accounts with no ownership check.",
        "iso_control": "A.9 Access Control",
        "business_impact": "Any authenticated user can view or modify other "
                            "users' orders, baskets, or personal data simply "
                            "by changing an ID in the URL — routinely the "
                            "single most common finding in real-world web "
                            "app pentests.",
        "root_cause": "The endpoint trusts the object ID supplied by the "
                       "client without verifying ownership.",
        "remediation": "Enforce server-side authorization on every object "
                        "access.",
        "references": [
            "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control",
            "https://portswigger.net/web-security/access-control/idor",
        ],
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "severity": "CRITICAL",
        "message": "A low-privilege account was able to access an admin-only endpoint.",
        "iso_control": "A.9 Access Control",
        "business_impact": "A regular user, or an attacker who registers a "
                            "throwaway account, can gain administrative "
                            "control over the platform.",
        "root_cause": "Role/permission checks are missing or only enforced "
                       "client-side, not re-verified on the server.",
        "remediation": "Enforce role-based access control (RBAC) server-side "
                        "on every privileged endpoint.",
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
        ],
    },
    "weak_password_policy": {
        "name": "Weak Password / Successful Brute Force",
        "severity": "HIGH",
        "message": "A password from the supplied wordlist successfully "
                    "authenticated as a known account.",
        "iso_control": "A.9 Access Control",
        "business_impact": "A weak or reused password lets an attacker take "
                            "over an account using publicly available "
                            "wordlists like rockyou.txt.",
        "root_cause": "No minimum password complexity and/or no rate-limiting "
                       "or lockout on failed login attempts.",
        "remediation": "Enforce a strong password policy, add rate-limiting "
                        "and lockout, and offer multi-factor authentication.",
        "references": [
            "https://owasp.org/www-community/attacks/Brute_force_attack",
        ],
    },
    "rce_indicator": {
        "name": "Remote Code Execution (RCE) Indicator",
        "severity": "CRITICAL",
        "message": "An upload endpoint showed signs it may accept and store "
                    "attacker-controlled content.",
        "iso_control": "A.14 System Acquisition, Development & Maintenance",
        "business_impact": "RCE is the most severe class of web vulnerability "
                            "— a successful exploit gives an attacker a "
                            "foothold to run arbitrary commands on the server.",
        "root_cause": "Uploaded files are processed without strict "
                       "type/content validation.",
        "remediation": "Strictly validate file type/content on upload, store "
                        "uploads outside the web root, disable execution "
                        "permissions on upload directories.",
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
        ],
    },
}


def build_web_finding(vuln_id, evidence):
    finding = {"id": vuln_id, "evidence": evidence}
    finding.update(WEB_VULN_INFO[vuln_id])
    return finding


def register_test_account(session, base_url):
    """Registers a throwaway low-privilege account and logs in."""
    suffix = "".join(random.choices(string.ascii_lowercase, k=8))
    email = f"scanner_test_{suffix}@example.com"
    password = "TestPass123!"
    try:
        session.post(
            f"{base_url}/api/Users/",
            json={"email": email, "password": password, "passwordRepeat": password},
            timeout=5,
        )
        login_resp = session.post(
            f"{base_url}/rest/user/login",
            json={"email": email, "password": password},
            timeout=5,
        )
        token = login_resp.json().get("authentication", {}).get("token")
        return {"email": email, "token": token}
    except (requests.RequestException, ValueError):
        return None


def check_reflected_xss(session, base_url, account):
    payload = "<script>alert('xss_test')</script>"
    try:
        resp = session.get(f"{base_url}/rest/products/search", params={"q": payload}, timeout=5)
    except requests.RequestException:
        return None
    if payload in resp.text:
        return build_web_finding("reflected_xss", evidence=f"{base_url}/rest/products/search")
    return None


def check_sql_injection(session, base_url, account):
    url = f"{base_url}/rest/user/login"
    payload = {"email": "' OR 1=1--", "password": "anything"}
    try:
        resp = session.post(url, json=payload, timeout=5)
    except requests.RequestException:
        return None
    body_lower = resp.text.lower()
    if resp.status_code == 200 and "token" in body_lower:
        return build_web_finding("sql_injection", evidence=f"{url} (auth bypass)")
    if resp.status_code >= 400 and any(s in body_lower for s in ["sql", "sqlite", "syntax error"]):
        return build_web_finding("sql_injection", evidence=f"{url} (error leakage)")
    return None


def check_security_headers(session, base_url, account):
    required = ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options"]
    try:
        resp = session.get(base_url, timeout=5)
    except requests.RequestException:
        return None
    missing = [h for h in required if h not in resp.headers]
    if missing:
        return build_web_finding("missing_security_headers", evidence=f"Missing: {', '.join(missing)}")
    return None


def check_idor(session, base_url, account):
    if not account or not account.get("token"):
        return None
    headers = {"Authorization": f"Bearer {account['token']}"}
    try:
        own = session.get(f"{base_url}/rest/basket/1", headers=headers, timeout=5)
        other = session.get(f"{base_url}/rest/basket/2", headers=headers, timeout=5)
    except requests.RequestException:
        return None
    if other.status_code == 200 and own.text != other.text and "data" in other.text.lower():
        return build_web_finding("idor", evidence=f"{base_url}/rest/basket/2 (as a different user)")
    return None


def check_privilege_escalation(session, base_url, account):
    if not account or not account.get("token"):
        return None
    headers = {"Authorization": f"Bearer {account['token']}"}
    try:
        resp = session.get(f"{base_url}/rest/admin/application-configuration", headers=headers, timeout=5)
    except requests.RequestException:
        return None
    if resp.status_code == 200:
        return build_web_finding(
            "privilege_escalation",
            evidence=f"{base_url}/rest/admin/application-configuration reachable as low-priv user",
        )
    return None


def check_brute_force(session, base_url, account):
    try:
        with open(ROCKYOU_PATH, "r", encoding="latin-1") as f:
            for i, line in enumerate(f):
                if i >= BRUTE_FORCE_LIMIT:
                    break
                password = line.strip()
                if not password:
                    continue
                try:
                    resp = session.post(
                        f"{base_url}/rest/user/login",
                        json={"email": BRUTE_FORCE_TARGET_EMAIL, "password": password},
                        timeout=5,
                    )
                except requests.RequestException:
                    continue
                if resp.status_code == 200 and "token" in resp.text.lower():
                    return build_web_finding(
                        "weak_password_policy",
                        evidence=f"Password cracked after {i + 1} attempts (wordlist: {ROCKYOU_PATH})",
                    )
                time.sleep(0.05)
    except FileNotFoundError:
        print(f"[-] Wordlist not found at {ROCKYOU_PATH} — skipping brute force check.")
        return None
    return None


def check_rce_indicator(session, base_url, account):
    if not account or not account.get("token"):
        return None
    headers = {"Authorization": f"Bearer {account['token']}"}
    files = {"file": ("test.php.pdf", b"<?php echo 'rce_test'; ?>", "application/pdf")}
    try:
        resp = session.post(f"{base_url}/file-upload", headers=headers, files=files, timeout=5)
    except requests.RequestException:
        return None
    if resp.status_code in (200, 201):
        return build_web_finding(
            "rce_indicator",
            evidence="Double-extension file (test.php.pdf) accepted by upload endpoint",
        )
    return None


def run_web_scan(base_url=WEB_TARGET, include_brute_force=False):
    session = requests.Session()
    account = register_test_account(session, base_url)

    checks = [
        check_reflected_xss,
        check_sql_injection,
        check_security_headers,
        check_idor,
        check_privilege_escalation,
        check_rce_indicator,
    ]
    if include_brute_force:
        checks.append(check_brute_force)

    findings = []
    for check in checks:
        result = check(session, base_url, account)
        if result:
            findings.append(result)
    return findings


# ===========================================================================
# PART 2: PAYROLL FRAUD SCAN
# Reads ONE Excel workbook containing multiple sheets, works out which
# sheet holds employee data and which holds payment data, cleans both,
# merges them, derives tenure/payment columns, and runs fraud checks.
# ===========================================================================

PAYROLL_FRAUD_INFO = {
    "duplicate_employee": {
        "name": "Duplicate Employee Record",
        "severity": "HIGH",
        "business_impact": "Duplicate records can mean the same person is "
                            "paid twice for one period, or a data-entry "
                            "error is masking a deliberate ghost-employee "
                            "attempt.",
        "root_cause": "No unique-key enforcement on employee ID when records "
                       "are created or imported.",
        "remediation": "Enforce a unique constraint on employee ID; review "
                        "and merge duplicates found.",
    },
    "duplicate_bank_account": {
        "name": "Duplicate Bank Account Across Employees",
        "severity": "CRITICAL",
        "business_impact": "Multiple 'different' employees paid into the "
                            "same bank account is one of the strongest "
                            "indicators of a ghost employee scheme.",
        "root_cause": "Bank account numbers are not validated for uniqueness "
                       "before payroll runs.",
        "remediation": "Flag and manually investigate any bank account "
                        "shared by more than one employee ID before release.",
    },
    "payment_before_hire": {
        "name": "Payment Recorded Before Official Hire Date",
        "severity": "CRITICAL",
        "business_impact": "An employee ID receiving payment before its "
                            "official hire date suggests the ID was used, or "
                            "payments routed, before the role or person was "
                            "formally approved.",
        "root_cause": "Payroll processing does not cross-check payment dates "
                       "against the employee master record's hire date.",
        "remediation": "Reject or flag any payment dated earlier than the "
                        "employee's recorded hire date.",
    },
    "tenure_payment_mismatch": {
        "name": "Tenure vs. Payment Duration Mismatch",
        "severity": "HIGH",
        "business_impact": "A significant gap between recorded tenure and "
                            "actual payment history suggests either a "
                            "record-keeping failure or deliberate "
                            "manipulation, e.g. continued payment after a "
                            "recorded termination date.",
        "root_cause": "Hire/termination dates are not kept in sync with "
                       "actual payment history.",
        "remediation": "Reconcile tenure dates against payment history "
                        "regularly; require sign-off for payments outside "
                        "the recorded employment window.",
    },
}


def build_payroll_finding(fraud_id, evidence):
    finding = {"id": fraud_id, "evidence": evidence}
    finding.update(PAYROLL_FRAUD_INFO[fraud_id])
    return finding


def load_workbook(path):
    """Reads every sheet in the workbook into a dict of DataFrames,
    keyed by sheet name."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"Workbook not found at {path}")
    return pd.read_excel(path, sheet_name=None)


def identify_sheets(sheets):
    """Looks at the columns in each sheet to work out which one is the
    employee master sheet and which is the payments sheet, rather than
    relying on the sheet being named a specific thing.
    Falls back to sheet name hints if column-based detection is ambiguous."""
    employees_df, payments_df = None, None

    for name, df in sheets.items():
        cols = {c.lower().strip() for c in df.columns}
        looks_like_employees = {"employee_id", "hire_date"}.issubset(cols) or "bank_account" in cols
        looks_like_payments = {"employee_id", "payment_date", "amount"}.issubset(cols)

        if looks_like_payments and not looks_like_employees:
            payments_df = df
        elif looks_like_employees and not looks_like_payments:
            employees_df = df
        else:
            # ambiguous — fall back to sheet name
            lname = name.lower()
            if "pay" in lname and payments_df is None:
                payments_df = df
            elif ("emp" in lname or "staff" in lname) and employees_df is None:
                employees_df = df

    if employees_df is None or payments_df is None:
        raise ValueError(
            "Could not identify employee and payment sheets in the workbook. "
            "Expected an employee sheet with columns like employee_id, "
            "hire_date, bank_account, and a payments sheet with employee_id, "
            "payment_date, amount."
        )
    return employees_df, payments_df


def clean_dataframe(df, dedupe_subset=None):
    df = df.drop_duplicates()
    if dedupe_subset:
        df = df.drop_duplicates(subset=dedupe_subset, keep="first")
    for col in df.select_dtypes(include="object").columns:
        df[col] = df[col].astype(str).str.strip()
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    return df


def merge_sheets(employees_df, payments_df):
    return pd.merge(
        payments_df, employees_df, on="employee_id", how="left",
        suffixes=("_payment", "_employee"),
    )


def add_derived_columns(employees_df, merged_df):
    today = pd.Timestamp(datetime.today().date())

    employees_df["hire_date"] = pd.to_datetime(employees_df["hire_date"], errors="coerce")
    employees_df["tenure_days"] = (today - employees_df["hire_date"]).dt.days

    merged_df["payment_date"] = pd.to_datetime(merged_df["payment_date"], errors="coerce")
    payment_span = merged_df.groupby("employee_id")["payment_date"].agg(["min", "max"])
    payment_span["payment_duration_days"] = (payment_span["max"] - payment_span["min"]).dt.days
    payment_span = payment_span.rename(columns={"min": "first_payment_date", "max": "last_payment_date"})

    employees_df = employees_df.merge(payment_span, on="employee_id", how="left")
    employees_df["tenure_vs_payment_gap_days"] = (
        employees_df["payment_duration_days"] - employees_df["tenure_days"]
    )
    return employees_df


def check_duplicate_employee(employees_raw_df):
    dupes = employees_raw_df[employees_raw_df.duplicated(subset=["employee_id"], keep=False)]
    findings = []
    for emp_id, group in dupes.groupby("employee_id"):
        findings.append(build_payroll_finding(
            "duplicate_employee", evidence=f"employee_id {emp_id} appears {len(group)} times",
        ))
    return findings


def check_duplicate_bank_account(employees_raw_df):
    if "bank_account" not in employees_raw_df.columns:
        return []
    dupes = employees_raw_df[employees_raw_df.duplicated(subset=["bank_account"], keep=False)]
    findings = []
    for acct, group in dupes.groupby("bank_account"):
        ids = ", ".join(group["employee_id"].astype(str))
        findings.append(build_payroll_finding(
            "duplicate_bank_account", evidence=f"bank_account {acct} shared by employee_ids: {ids}",
        ))
    return findings


def check_payment_before_hire(merged_df):
    merged_df["hire_date"] = pd.to_datetime(merged_df["hire_date"], errors="coerce")
    bad = merged_df[merged_df["payment_date"] < merged_df["hire_date"]]
    findings = []
    for _, row in bad.iterrows():
        findings.append(build_payroll_finding(
            "payment_before_hire",
            evidence=f"employee_id {row['employee_id']}: paid on "
                     f"{row['payment_date'].date()} but hired on {row['hire_date'].date()}",
        ))
    return findings


def check_tenure_payment_mismatch(employees_derived_df, threshold_days=TENURE_MISMATCH_THRESHOLD_DAYS):
    mismatches = employees_derived_df[employees_derived_df["tenure_vs_payment_gap_days"].abs() > threshold_days]
    findings = []
    for _, row in mismatches.iterrows():
        findings.append(build_payroll_finding(
            "tenure_payment_mismatch",
            evidence=f"employee_id {row['employee_id']}: tenure {row['tenure_days']} days "
                     f"vs. payment span {row.get('payment_duration_days', 'N/A')} days "
                     f"(gap: {row['tenure_vs_payment_gap_days']} days)",
        ))
    return findings


def run_payroll_scan(workbook_path=PAYROLL_WORKBOOK_PATH):
    sheets = load_workbook(workbook_path)
    employees_df, payments_df = identify_sheets(sheets)

    employees_clean = clean_dataframe(employees_df.copy())          # keep separately for duplicate checks
    payments_clean = clean_dataframe(payments_df.copy(), dedupe_subset=None)

    merged_df = merge_sheets(employees_clean, payments_clean)
    employees_derived_df = add_derived_columns(employees_clean.copy(), merged_df)

    findings = []
    findings += check_duplicate_employee(employees_clean)
    findings += check_duplicate_bank_account(employees_clean)
    findings += check_payment_before_hire(merged_df)
    findings += check_tenure_payment_mismatch(employees_derived_df)
    return findings


# ===========================================================================
# ENTRY POINT — simple menu so one file drives both halves of the tool.
# ===========================================================================
def main():
    print_section("RISK SCANNER — Web Vulnerability + Payroll Fraud")
    print("1. Web application scan")
    print("2. Payroll fraud scan")
    print("3. Both")
    choice = input("\nChoose an option (1/2/3): ").strip()

    if choice in ("1", "3"):
        print_section(f"WEB APPLICATION SECURITY ASSESSMENT — target: {WEB_TARGET}")
        web_findings = run_web_scan(WEB_TARGET, include_brute_force=False)
        print_findings(web_findings, "No vulnerabilities found by the current checks.")

    if choice in ("2", "3"):
        print_section(f"PAYROLL FRAUD RISK ASSESSMENT — workbook: {PAYROLL_WORKBOOK_PATH}")
        try:
            payroll_findings = run_payroll_scan(PAYROLL_WORKBOOK_PATH)
            print_findings(payroll_findings, "No fraud indicators found by the current checks.")
        except (FileNotFoundError, ValueError) as e:
            print(f"\n[-] {e}\n")


if __name__ == "__main__":
    main()
