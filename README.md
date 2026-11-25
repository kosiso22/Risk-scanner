# Risk Scanner — Web Vulnerability + Payroll Fraud

A single Python script that runs two small, education-focused risk checks:

1. **Web application scan**: checks a target for a handful of classic
   OWASP Top 10 issues: reflected XSS, SQL injection, missing security
   headers, IDOR / broken access control, privilege escalation, weak
   passwords (optional brute-force check), and a basic indicator of
   unrestricted file upload / RCE risk.
2. **Payroll fraud scan**: reads one Excel workbook containing an
   employee sheet and a payments sheet, and flags duplicate employee
   records, bank accounts shared across employees, payments made before
   the recorded hire date, and mismatches between recorded tenure and
   actual payment history.

I built this as a self-contained way to practice both sides of risk work. I'm interested in  application security testing and the kind of fraud/control checks you would do on financial data in one small tool, rather than two unrelated scripts. The tool is a work-in-progress and is subject to updates.

## About the web target

The web scan was written and tested against OWASP Juice Shop, so the tests were conducted in a safe environment specifically designed to practice web security testing legally.

It's used here as a **stand-in for a real-world financial/payroll web application**. The checks (auth bypass, IDOR on another user's data,
privilege escalation to an admin endpoint, etc.) are the kind of things you wouldd want to test on a real payroll portal before it goes live, just run here against a safe practice target instead.

**Never point the web scan at a site you don't own or don't have explicit written permission to test.** Running these checks against systems you are not authorized to test is illegal.

## What's in this repo

```
risk_scanner.py             the scanner — run it directly
requirements.txt            Python dependencies
payroll_sample.xlsx       small, fully fictional sample payroll workbook
```

The sample workbook contains made-up employees and payments with a few deliberate issues baked in a shared bank account, a payment dated before a hire date, and so on so you can run the payroll scan immediately and see it catch something.

## Setup

```bash
git clone https://github.com/kosiso22/risk-scanner.git
cd risk-scanner
pip install -r requirements.txt
```

This runs Juice Shop locally at `http://localhost:3000`, which is the scanner's default target — no configuration needed.

## Running it

```bash
python3 risk_scanner.py
```

You'll get a simple menu:

```
1. Web application scan
2. Payroll fraud scan
3. Both
```

Each finding is printed with its severity, the evidence that triggered
it, the business impact, the likely root cause, a suggested fix, and
(for the web checks) the relevant ISO 27001 control and further reading.

## Using it on your own payroll data

Point `RISK_SCANNER_PAYROLL_PATH` at your own workbook. The scanner
doesn't care what the sheets are named, it looks at the **columns** to
work out which sheet is which:

 An **employee** sheet needs at least `employee_id` and `hire_date` 
 A `bank_account` column enables the duplicate-account check.
 A **payments** sheet needs `employee_id`, `payment_date`, and `amount`.

## A note on data protection

Don't commit real payroll data, real credentials, or a real wordlist to a public repository.

## Why this exists

Put together for practice combining application security testing with the kind of control checks used in financial risk and fraud detection which are two areas I'm trying to build skill in together rather than separately.
