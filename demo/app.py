"""Demo Flask application — intentionally vulnerable for CVE agent testing.

Patterns mirror real CVE weakness descriptions across PyPI ecosystem.
"""
from flask import Flask, request, jsonify, render_template_string

from db import get_user_by_id, search_users
from shell import run_diagnostic
from template import render_profile
from deserialize import load_config, import_session
from xml_parser import parse_feed

app = Flask(__name__)

# CVE-2018-1000656 pattern: hardcoded SECRET_KEY enables session forgery
app.config["SECRET_KEY"] = "super-secret-do-not-change-me"


# CVE-2019-15224 / SQLi pattern: user input flows into raw SQL string
@app.route("/user/<user_id>")
def user_route(user_id):
    return jsonify(get_user_by_id(user_id))


@app.route("/search")
def search_route():
    name = request.args.get("name", "")
    return jsonify(search_users(name))


# CVE-2017-1000219 pattern: user-controlled input reaches subprocess shell=True
@app.route("/diagnostic", methods=["POST"])
def diagnostic_route():
    host = request.json.get("host", "")
    return run_diagnostic(host)


# CVE-2019-10906 / SSTI pattern: user content rendered as Jinja2 template
@app.route("/profile/<username>")
def profile_route(username):
    bio = request.args.get("bio", "")
    return render_profile(username, bio)


# CVE-2020-14343 pattern: yaml.load() on untrusted input → RCE
@app.route("/config", methods=["POST"])
def config_route():
    cfg = load_config(request.data)
    return jsonify({"status": "ok", "config": cfg})


# CVE pattern (pickle): pickle.loads on untrusted bytes → RCE
@app.route("/session/import", methods=["POST"])
def import_session_route():
    session = import_session(request.data)
    return jsonify({"restored": str(session)})


# CVE-2021-28957 pattern: XML parsing with external entities enabled (XXE)
@app.route("/feed", methods=["POST"])
def feed_route():
    return jsonify(parse_feed(request.data))


# SSTI: render_template_string directly on user input
@app.route("/greet")
def greet_route():
    name = request.args.get("name", "guest")
    return render_template_string(f"<h1>Hello {name}</h1>")


if __name__ == "__main__":
    # CVE-2019-14806 pattern: debug=True exposes the Werkzeug debugger console (RCE)
    app.run(host="0.0.0.0", port=5000, debug=True)
