# passwords.py
import secrets, string

AMBIG = set("O0Il1|`'\"{}[]()<>;:,./\\")
SYMS  = "!@#$%^&*-_=+?"

def generate_password(length=16, upper=True, lower=True, digits=True, symbols=True, exclude_ambiguous=True) -> str:
    pools = []
    if upper: pools.append(string.ascii_uppercase)
    if lower: pools.append(string.ascii_lowercase)
    if digits: pools.append(string.digits)
    if symbols: pools.append(SYMS)
    alphabet = "".join(pools)
    if exclude_ambiguous:
        alphabet = "".join(ch for ch in alphabet if ch not in AMBIG)
    if not alphabet:
        raise ValueError("No character sets selected")
    req = []
    if upper:  req.append(secrets.choice("".join(c for c in string.ascii_uppercase if c not in AMBIG)))
    if lower:  req.append(secrets.choice("".join(c for c in string.ascii_lowercase if c not in AMBIG)))
    if digits: req.append(secrets.choice("".join(c for c in string.digits if c not in AMBIG)))
    if symbols:req.append(secrets.choice("".join(c for c in SYMS if c not in AMBIG)))
    pw = req + [secrets.choice(alphabet) for _ in range(max(0, length - len(req)))]
    secrets.SystemRandom().shuffle(pw)
    return "".join(pw)
