"""Draft a National Cybercrime Reporting Portal (cybercrime.gov.in) complaint. Never submits anything."""

SUBCATEGORIES = {
    "upi": "UPI Related Frauds",
    "card": "Debit/Credit Card Fraud/Sim Swap Fraud",
    "netbanking": "Internet Banking Related Fraud",
    "investment": "Investment Scam/Trading Scam",
    "task": "Online Job Fraud",
    "digital_arrest": "Impersonation / Digital Arrest",
    "ewallet": "E-Wallet Related Fraud",
    "other": "Other Financial Fraud",
}


def draft_cybercrime_complaint(
    fraud_type: str,
    incident_summary: str,
    amount_lost_inr: str = "",
    payment_method: str = "",
    transaction_ids: list[str] | None = None,
    transaction_datetime: str = "",
    suspect_identifiers: list[str] | None = None,
    victim_bank: str = "",
) -> dict:
    sub = SUBCATEGORIES.get(fraud_type, SUBCATEGORIES["other"])
    tx = transaction_ids or []
    suspects = suspect_identifiers or []
    blank = "[FILL IN]"

    text = f"""NATIONAL CYBERCRIME REPORTING PORTAL: COMPLAINT DRAFT
(File at https://cybercrime.gov.in → "Report Cyber Crime" → "Financial Fraud". Call 1930 FIRST.)

Category: Online Financial Fraud
Sub-category: {sub}
Date & time of incident: {transaction_datetime or blank}
Amount lost (₹): {amount_lost_inr or blank}
Payment method: {payment_method or blank}
Victim's bank / wallet: {victim_bank or blank}
Transaction ID / UTR number(s): {", ".join(tx) if tx else blank + " (find it in your bank app / SMS; 12-digit UTR for UPI)"}

Suspect details (as known):
{chr(10).join("  - " + s for s in suspects) if suspects else "  - " + blank}

Description of incident:
{incident_summary}

Evidence to attach (screenshots, max 10 MB each):
  - The original message(s) and chat with the suspect
  - Payment confirmation / bank SMS showing debit and UTR
  - Bank statement page showing the transaction
  - Any website / app screenshots, links, phone numbers, UPI IDs used
"""
    return {
        "complaint_text": text,
        "urgent_steps": [
            "Call 1930 (National Cyber Crime Helpline) NOW. Reporting within the first hours ('golden hour') gives the best chance of freezing the money.",
            "Call your bank's official customer-care number (from the back of your card or the bank's website) and ask them to block the card/UPI/net banking and raise a fraud dispute.",
            "File the complaint on cybercrime.gov.in and note the acknowledgement number.",
            "If you installed any app the scammer asked for (AnyDesk, an APK, etc.), uninstall it, turn off mobile data, and change your banking passwords from another device.",
            "Do not pay anyone who contacts you claiming they can 'recover' your money. That is a second scam.",
        ],
        "missing_fields": [k for k, v in {
            "amount_lost_inr": amount_lost_inr, "transaction_ids": tx,
            "transaction_datetime": transaction_datetime, "victim_bank": victim_bank}.items() if not v],
    }
