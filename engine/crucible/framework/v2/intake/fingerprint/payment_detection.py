"""payment_detection — identify visible payment processors / wallets."""

from __future__ import annotations

from typing import Iterable

from ..models import DetectionResult, HTTPExchange
from . import _common as c


SIGNATURES = (
    # Stripe
    c.body("stripe",        c.re_(r"js\.stripe\.com|api\.stripe\.com"),     0.95, "stripe.com asset / endpoint"),
    c.body("stripe",        c.re_(r"Stripe\.elements|stripe-pricing-table"), 0.9, "Stripe Elements widget"),

    # PayPal
    c.body("paypal",        c.re_(r"paypal\.com/sdk/js|www\.paypal\.com"),  0.9, "paypal.com SDK / endpoint"),
    c.body("paypal",        c.re_(r"PayPal\.Buttons"),                       0.9, "PayPal.Buttons script"),

    # Square
    c.body("square",        c.re_(r"squarecdn\.com|web\.squarecdn\.com"),    0.95, "Square CDN reference"),
    c.body("square",        c.re_(r"Square\.payments"),                      0.9, "Square.payments script"),

    # Cryptomus
    c.body("cryptomus",     c.re_(r"cryptomus\.com|api\.cryptomus\.com"),   0.95, "cryptomus.com endpoint"),
    c.path("cryptomus",     c.re_(r"/payment/cryptomus|/cryptomus/"),       0.85, "/cryptomus/ path"),

    # Coinbase Commerce
    c.body("coinbase-commerce", c.re_(r"commerce\.coinbase\.com"),          0.95, "commerce.coinbase.com reference"),
    c.path("coinbase-commerce", c.re_(r"/coinbase|/coinbase-commerce"),     0.7,  "/coinbase/ path"),

    # Payeer
    c.body("payeer",        c.re_(r"payeer\.com"),                          0.95, "payeer.com reference"),
    c.path("payeer",        c.re_(r"/payeer/"),                             0.7,  "/payeer/ path"),

    # Perfect Money
    c.body("perfect-money", c.re_(r"perfectmoney\.is|perfectmoney\.com"),  0.95, "perfectmoney.is reference"),
    c.path("perfect-money", c.re_(r"/perfectmoney|/pm/"),                  0.6,  "/perfectmoney/ path"),

    # BTCPay Server
    c.body("btcpay",        c.re_(r"btcpayserver|btcpay-frame"),            0.9,  "btcpayserver reference"),
    c.path("btcpay",        c.re_(r"/btcpay/"),                             0.7,  "/btcpay/ path"),

    # NowPayments
    c.body("nowpayments",   c.re_(r"nowpayments\.io|api\.nowpayments\.io"), 0.95, "nowpayments.io reference"),

    # Razorpay
    c.body("razorpay",      c.re_(r"razorpay\.com|checkout\.razorpay"),     0.95, "razorpay.com reference"),

    # Mollie
    c.body("mollie",        c.re_(r"mollie\.com"),                          0.9,  "mollie.com reference"),

    # Adyen
    c.body("adyen",         c.re_(r"adyen\.com|checkoutshopper-(live|test)"), 0.95, "adyen.com reference"),

    # Braintree
    c.body("braintree",     c.re_(r"braintreepayments\.com|js\.braintreegateway"), 0.95, "Braintree gateway reference"),

    # USDT / direct crypto manual confirm (panel pattern)
    c.body("manual-crypto", c.re_(r"USDT.*TRC20|paste your TX hash|tx hash:"), 0.7, "manual-crypto pattern"),
)


def detect(exchanges: Iterable[HTTPExchange]) -> DetectionResult:
    return c.run("payment_detection", SIGNATURES, exchanges, category="payment")
