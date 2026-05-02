"""Mirrors CVE-2019-10906: Jinja2 sandbox escape + classic SSTI / XSS.

Weakness description: "Server-side template injection via user-controlled
template string" and "Cross-site scripting via unescaped output".
"""
from jinja2 import Environment, Template


# VULNERABLE: user `bio` is concatenated into the template SOURCE, not data —
# so {{ 7*7 }} or {{ config.items() }} executes server-side (SSTI).
def render_profile(username, bio):
    source = f"""
    <html>
      <body>
        <h1>Profile: {username}</h1>
        <div class="bio">{bio}</div>
      </body>
    </html>
    """
    return Template(source).render()


# VULNERABLE: autoescape disabled, raw user content rendered as HTML (XSS)
_env = Environment(autoescape=False)


def render_comment(author, comment):
    tmpl = _env.from_string("<div><strong>{{ author }}</strong>: {{ comment | safe }}</div>")
    return tmpl.render(author=author, comment=comment)


# SAFE reference (after fix):
# _env_safe = Environment(autoescape=True)
# def render_profile_safe(username, bio):
#     tmpl = _env_safe.from_string("<h1>Profile: {{ username }}</h1><div>{{ bio }}</div>")
#     return tmpl.render(username=username, bio=bio)
