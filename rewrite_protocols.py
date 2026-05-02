import re

with open("protocols.py", "r") as f:
    code = f.read()

# 1. Replace getattr(s, "UPPERCASE_KEY", default) with s.get("lowercase_key", default)
def replace_getattr(match):
    key = match.group(1).lower()
    default = match.group(2)
    return f's.get("{key}", {default})'

code = re.sub(r'getattr\(s,\s*"([A-Z0-9_]+)",\s*(.*?)\)', replace_getattr, code)
code = re.sub(r'getattr\(settings,\s*"([A-Z0-9_]+)",\s*(.*?)\)', lambda m: f'settings.get("{m.group(1).lower()}", {m.group(2)})', code)

# Write it back
with open("protocols.py", "w") as f:
    f.write(code)
print("protocols.py getattr replaced")
