# Change the admin password of index.html (Support tools + CMD commands).
# Usage:  python change_password.py index.html "OLD_PASSWORD" "NEW_PASSWORD"
# Needs:  pip install cryptography
import sys, re, os, json, base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def key(pw, salt, n):
    return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=n).derive(pw.encode("utf-8"))

def main(path, old, new):
    html = open(path, encoding="utf-8").read()
    m = re.search(r'(<script type="application/json" id="vault">)(.*?)(</script>)', html, re.S)
    if not m:
        sys.exit("vault block not found in " + path)
    j = json.loads(m.group(2)); d = base64.b64decode
    try:
        data = AESGCM(key(old, d(j["s"]), j["n"])).decrypt(d(j["i"]), d(j["c"]), None)
    except Exception:
        sys.exit("The old password is wrong.")
    n = 250000; salt = os.urandom(16); iv = os.urandom(12)
    ct = AESGCM(key(new, salt, n)).encrypt(iv, data, None)
    b = lambda x: base64.b64encode(x).decode()
    blob = json.dumps({"s": b(salt), "i": b(iv), "c": b(ct), "n": n})
    open(path, "w", encoding="utf-8").write(html[:m.start(2)] + blob + html[m.end(2):])
    print("Password changed.")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
