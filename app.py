from flask import Flask, request, jsonify
import dns.resolver
import re

app = Flask(__name__)

@app.route("/check-mx", methods=["POST"])
def check_mx():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email is required"}), 400

    # Basic regex check
    regex = r'^[\w.-]+@[\w.-]+\.\w+$'
    if not re.match(regex, email):
        return jsonify({"valid_format": "False", "mx_exists": "True"})

    username = email.split('@')[0]

    # Gibberish or long username check
    if len(username) > 18 or re.search(r'[a-zA-Z]*\d{5,}[a-zA-Z\d]*', username):
        return jsonify({"valid_format": "False", "mx_exists": "False"})

    # MX record check
    try:
        domain = email.split("@")[1]
        records = dns.resolver.resolve(domain, "MX")
        return jsonify({
            "valid_format": "True",
            "mx_exists": "True" if records else "False"
        })
    except Exception:
        return jsonify({
            "valid_format": "True",
            "mx_exists": "False"
        })

if __name__ == "__main__":
    app.run(debug=True)
