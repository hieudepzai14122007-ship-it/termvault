import datetime as dt
import time

from termvault.health import audit, strength
from termvault.models import Entry, new_card, new_login, new_note

STRONG = "x7#Kp2!qLm9@vR4z"
NOW = time.time()
TODAY = dt.date(2026, 10, 2)


def kinds(issues, entry):
    return {i.kind for i in issues if i.entry_id == entry.id}


def test_strength_scores():
    assert strength("password1").score == 0
    assert strength("password1").warning
    assert strength(STRONG).score == 4
    assert strength("").label == "Empty"


def test_audit_flags_each_problem():
    weak = new_login("Forum", password="password1")
    reused_a = new_login("Mail", password="Same-Strong-Pass-9241!")
    reused_b = new_login("Shop", password="Same-Strong-Pass-9241!")
    old = new_login("Old site", password=STRONG + "a")
    old.password_changed = NOW - 400 * 86400
    good = new_login("Good", password=STRONG + "b")
    expired = new_card("Old card", card_number="4111111111111111", card_expiry="01/25")
    expiring = new_card("Soon card", card_number="4111111111111111", card_expiry="11/26")
    note = new_note("Just a note")

    issues = audit([weak, reused_a, reused_b, old, good, expired, expiring, note], now=NOW, today=TODAY)

    assert kinds(issues, weak) == {"weak"}
    assert kinds(issues, reused_a) == {"reused"}
    assert "Shop" in next(i.detail for i in issues if i.entry_id == reused_a.id)
    assert kinds(issues, old) == {"old"}
    assert kinds(issues, good) == set()
    assert kinds(issues, expired) == {"expired"}
    assert kinds(issues, expiring) == {"expiring"}
    assert kinds(issues, note) == set()
    # Most severe first.
    assert issues[0].kind == "expired"


def test_audit_ignores_empty_passwords():
    assert audit([new_login("No pw"), new_login("No pw 2")], now=NOW) == []


def test_password_changed_backfilled_for_old_vaults():
    data = new_login("x").to_dict()
    del data["password_changed"]
    data["updated"] = 1000.0
    assert Entry.from_dict(data).password_changed == 1000.0
