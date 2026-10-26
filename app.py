from flask import Flask, render_template, request, session, redirect, url_for
import random
import re
import ssl
import socket
from urllib.parse import urlparse
from questions import quiz_questions

app = Flask(__name__)

# ---------------- Quiz Data ----------------
app.secret_key = "koi-bhi-lamba-random-text-likho"


@app.route("/quiz")
def quiz():
    count = min(5, len(quiz_questions))
    ids = random.sample(range(len(quiz_questions)), count)
    session["quiz_ids"] = ids
    questions = [quiz_questions[i] for i in ids]
    return render_template("quiz.html", questions=questions)


@app.route("/submit_quiz", methods=["POST"])
def submit_quiz():
    ids = session.get("quiz_ids")
    if not ids:
        return redirect(url_for("quiz"))

    score = 0
    for n, qid in enumerate(ids):
        if request.form.get(f"question{n}") == quiz_questions[qid]["answer"]:
            score += 1
    total = len(ids)

    return render_template("result.html", score=score, total=total)


# ---------------- Link Checker Data ----------------
SUSPICIOUS_TLDS = [".xyz", ".tk", ".ml", ".ga", ".cf", ".top", ".click", ".work", ".zip"]
SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy"]
KEYWORDS = ["verify", "login-secure", "update-account", "bank-alert",
            "confirm-identity", "free-prize", "win-lottery", "otp-verify",
            "kyc-update", "account-suspended"]
BRANDS = ["google", "paypal", "amazon", "facebook", "instagram", "whatsapp",
          "sbi", "hdfc", "icici", "paytm", "phonepe", "netflix", "microsoft"]


# ---------------- Link Checker Logic ----------------

# this function checks the SSL certificate of a given hostname
def check_ssl(hostname):
    """Connects to the server and checks whether the SSL certificate is valid."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True, "SSL certificate is valid"
    except ssl.SSLCertVerificationError:
        return False, "SSL certificate is INVALID"
    except Exception:
        return None, "SSL check could not be completed (server did not respond)"


# this checks http or https
def check_link(url):
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    full = url.lower()

    score = 0
    findings = []   # each item: (severity, message)

    def add(points, severity, message):
        nonlocal score
        score += points
        findings.append((severity, message))

    # 1. HTTPS
    if parsed.scheme != "https":
        add(20, "high", "Link does not use HTTPS, so the connection is not secure")

    # 2. IP address
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host):
        add(30, "high", "Link uses a raw IP address instead of a domain name")

    # 3. '@' trick
    if "@" in parsed.netloc:
        add(30, "high", "Link contains '@', a trick used to hide the real destination")

    # 4. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            add(20, "medium", f"Suspicious domain extension ({tld})")
            break

    # 5. Too many subdomains
    if host.count(".") >= 4:
        add(15, "medium", "Domain has too many subdomains")

    # 6. Punycode (lookalike unicode domain)
    if "xn--" in host:
        add(25, "high", "Punycode domain (looks like a real site but is different)")

    # 7. Keywords
    for word in KEYWORDS:
        if word in full:
            add(15, "medium", f"Suspicious keyword found: '{word}'")

    # 8. Hyphens
    if host.count("-") >= 3:
        add(10, "low", "Domain has an unusually high number of hyphens (-)")

    # 9. Very long URL
    if len(full) > 90:
        add(10, "low", "URL is unusually long")

    # 10. URL shortener
    for s in SHORTENERS:
        if host == s or host.endswith("." + s):
            add(20, "medium", f"URL shortener detected ({s}), the real destination is hidden")
            break

    # 11. Brand lookalike (e.g. paypa1, g00gle)
    normalized = host.replace("0", "o").replace("1", "l").replace("3", "e").replace("5", "s")
    for brand in BRANDS:
        if brand in normalized and not (host == f"{brand}.com" or host.endswith(f".{brand}.com")
                                        or host.endswith(f".{brand}.in") or host == f"{brand}.in"):
            add(25, "high", f"Domain appears to impersonate the brand '{brand}'")
            break

    # 12. Real SSL certificate check (https only)
    ssl_status = None
    if parsed.scheme == "https" and host:
        ssl_ok, ssl_msg = check_ssl(host)
        ssl_status = ssl_msg
        if ssl_ok is False:
            add(35, "high", ssl_msg)

    score = min(score, 100)

    if score >= 60:
        level, label = "high", "HIGH RISK - Very likely to be a fraudulent link"
    elif score >= 30:
        level, label = "medium", "MEDIUM RISK - Do not trust this link"
    elif score > 0:
        level, label = "low", "LOW RISK - Some suspicious signs were found"
    else:
        level, label = "safe", "SAFE - No suspicious patterns found"

    return {
        "url": url,
        "domain": host,
        "score": score,
        "level": level,
        "label": label,
        "findings": findings,
        "ssl_status": ssl_status,
    }


# ---------------- Message Checker ----------------
@app.route("/message-checker", methods=["GET", "POST"])
def message_checker():
    result = None
    if request.method == "POST":
        result = check_message(request.form["message_input"])
    return render_template("message_checker.html", result=result)


def check_message(text):
    original = text.strip()
    msg = original.lower()

    score = 0
    findings = []

    # 1. Urgency
    if "urgent" in msg or "immediately" in msg or "act now" in msg or "last chance" in msg or "within 24 hours" in msg:
        score = score + 15
        findings.append(("medium", "Urgency: the message tries to rush you"))

    # 2. Prize / lottery
    if "you have won" in msg or "lottery" in msg or "lucky draw" in msg or "claim your prize" in msg or "free gift" in msg:
        score = score + 30
        findings.append(("high", "Prize or lottery bait"))

    # 3. OTP / PIN / password
    if "otp" in msg or "your pin" in msg or "cvv" in msg or "password" in msg or "card number" in msg:
        score = score + 35
        findings.append(("high", "Asks for OTP, PIN, password or card details"))

    # 4. KYC / account block threat
    if "kyc" in msg or "account will be blocked" in msg or "account suspended" in msg or "verify your account" in msg:
        score = score + 25
        findings.append(("high", "Account threat or KYC scam"))

    # 5. Money / fee
    if "processing fee" in msg or "registration fee" in msg or "pay a small fee" in msg or "send money" in msg or "gift card" in msg:
        score = score + 30
        findings.append(("high", "Asks you to pay money or a fee"))

    # 6. Fake job / investment
    if "work from home" in msg or "earn per day" in msg or "double your money" in msg or "guaranteed returns" in msg:
        score = score + 20
        findings.append(("medium", "Fake job or investment offer"))

    # 7. Fake delivery
    if "delivery failed" in msg or "parcel on hold" in msg or "customs fee" in msg:
        score = score + 15
        findings.append(("medium", "Fake delivery or courier message"))

    # 8. Click here
    if "click here" in msg or "click the link" in msg or "tap the link" in msg:
        score = score + 10
        findings.append(("low", "Pushes you to click a link"))

    # 9. Links inside the message (checked with the link checker)
    for word in msg.split():
        if word.startswith("http") or word.startswith("www."):
            link = word.strip(".,!?)")
            link_result = check_link(link)
            if link_result["score"] >= 30:
                score = score + 30
                findings.append(("high", "Suspicious link inside the message: " + link_result["domain"]))
            elif link_result["score"] > 0:
                score = score + 10
                findings.append(("low", "Link looks slightly risky: " + link_result["domain"]))

    # 10. Fully CAPITAL letters
    if original.isupper():
        score = score + 10
        findings.append(("low", "Message is fully in CAPITAL LETTERS"))

    # 11. Too many exclamation marks
    if original.count("!") >= 3:
        score = score + 5
        findings.append(("low", "Too many exclamation marks (!!!)"))

    # Score 100 se zyada na ho
    if score > 100:
        score = 100

    # Score se risk level
    if score >= 60:
        level = "high"
        label = "HIGH RISK - This looks like a scam message"
    elif score >= 30:
        level = "medium"
        label = "MEDIUM RISK - Be careful, do not reply or click anything"
    elif score > 0:
        level = "low"
        label = "LOW RISK - A few suspicious signs were found"
    else:
        level = "safe"
        label = "SAFE - No common scam patterns found"

    return {
        "message": original,
        "score": score,
        "level": level,
        "label": label,
        "findings": findings,
    }


# ---------------- Routes ----------------
@app.route('/')
def home():
    return render_template('index.html')


@app.route("/link-checker", methods=["GET", "POST"])
def link_checker():
    result = None
    if request.method == "POST":
        result = check_link(request.form["url_input"])
    return render_template("link_checker.html", result=result)


# ---------------- Run Server ----------------
if __name__ == '__main__':
    app.run(debug=True)