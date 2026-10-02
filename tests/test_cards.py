import datetime as dt

import pytest

from termvault import cards

# Published test numbers from the card networks (not real cards).
VISA = "4111111111111111"
AMEX = "378282246310005"
MASTERCARD = "5555555555554444"
MASTERCARD_2 = "2223003122003222"
DISCOVER = "6011111111111117"


@pytest.mark.parametrize("number", [VISA, AMEX, MASTERCARD, MASTERCARD_2, DISCOVER, "4111 1111 1111 1111", "4111-1111-1111-1111"])
def test_luhn_valid(number):
    assert cards.luhn_valid(number)


@pytest.mark.parametrize("number", ["4111111111111112", "1234", "", "411111111111111111111", "abcd"])
def test_luhn_invalid(number):
    assert not cards.luhn_valid(number)


@pytest.mark.parametrize("number,brand", [
    (VISA, "Visa"), (AMEX, "Amex"), (MASTERCARD, "Mastercard"), (MASTERCARD_2, "Mastercard"),
    (DISCOVER, "Discover"), ("3530111333300000", "JCB"), ("", ""),
])
def test_brand(number, brand):
    assert cards.brand(number) == brand


def test_format_and_mask():
    assert cards.format_number(VISA) == "4111 1111 1111 1111"
    assert cards.format_number(AMEX) == "3782 822463 10005"
    assert cards.mask_number(VISA) == "•••• 1111"
    assert cards.mask_number(AMEX) == "•••• 0005"


@pytest.mark.parametrize("text,expected", [
    ("09/27", (9, 2027)), ("9/27", (9, 2027)), ("0927", (9, 2027)), ("09-2027", (9, 2027)), (" 12 / 30 ", (12, 2030)),
])
def test_parse_expiry(text, expected):
    assert cards.parse_expiry(text) == expected


@pytest.mark.parametrize("text", ["13/27", "00/27", "abc", "9/2", ""])
def test_parse_expiry_invalid(text):
    assert cards.parse_expiry(text) is None


def test_normalize_expiry():
    assert cards.normalize_expiry("9/2027") == "09/27"
    with pytest.raises(ValueError):
        cards.normalize_expiry("13/27")


def test_expiry_status():
    today = dt.date(2026, 10, 2)
    assert cards.expiry_status("09/26", today) == "expired"
    assert cards.expiry_status("10/26", today) == "soon"  # valid through Oct 31
    assert cards.expiry_status("11/26", today) == "soon"
    assert cards.expiry_status("12/26", today) == "ok"
    assert cards.expiry_status("12/26", dt.date(2027, 1, 1)) == "expired"
    assert cards.expiry_status("", today) == ""
