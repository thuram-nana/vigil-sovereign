"""cms_detection — identify the CMS / off-the-shelf application."""

from __future__ import annotations

from typing import Iterable

from ..models import DetectionResult, HTTPExchange
from . import _common as c


SIGNATURES = (
    # WordPress
    c.body("wordpress",   c.re_(r"<meta name=\"generator\" content=\"WordPress"), 0.95, "<meta generator> WordPress"),
    c.path("wordpress",   c.re_(r"/wp-(content|includes|json)/"),    0.85, "/wp-* path"),
    c.path("wordpress",   c.re_(r"/wp-login\.php"),                  0.9,  "/wp-login.php path"),

    # Drupal
    c.body("drupal",      c.re_(r"<meta name=\"Generator\" content=\"Drupal"), 0.95, "<meta generator> Drupal"),
    c.body("drupal",      c.re_(r"Drupal\.settings|Drupal\.behaviors"), 0.9, "Drupal JS globals"),
    c.path("drupal",      c.re_(r"/sites/(default|all)/"),           0.7,  "/sites/default/ path"),

    # Joomla
    c.body("joomla",      c.re_(r"<meta name=\"generator\" content=\"Joomla"), 0.95, "<meta generator> Joomla"),
    c.path("joomla",      c.re_(r"/(components|modules|templates)/com_"), 0.8, "Joomla component path"),

    # Magento
    c.cookie("magento",   "frontend",                                0.7,  "magento `frontend` cookie"),
    c.body  ("magento",   c.re_(r"Magento_|Mage\.Cookies"),         0.85, "Magento JS namespace"),

    # TYPO3
    c.body("typo3",       c.re_(r"<meta name=\"generator\" content=\"TYPO3"), 0.95, "<meta generator> TYPO3"),
    c.path("typo3",       c.re_(r"/typo3conf/"),                    0.8,  "/typo3conf/ path"),

    # Ghost
    c.body("ghost",       c.re_(r"<meta name=\"generator\" content=\"Ghost"), 0.95, "<meta generator> Ghost"),

    # MediaWiki
    c.body("mediawiki",   c.re_(r"<meta name=\"generator\" content=\"MediaWiki"), 0.95, "<meta generator> MediaWiki"),

    # Shopify
    c.cookie("shopify",   "_shopify_y",                              0.9,  "_shopify_y cookie"),
    c.hdr   ("shopify",   "X-Shopify-Stage", "",                     0.95, "X-Shopify-Stage header"),
    c.body  ("shopify",   c.re_(r"cdn\.shopify\.com"),               0.6,  "cdn.shopify.com asset"),

    # WooCommerce (a WordPress plugin but identifies as a sub-archetype)
    c.body  ("woocommerce", c.re_(r"woocommerce|wc-add-to-cart"),     0.85, "woocommerce strings/classes"),
    c.cookie("woocommerce", "woocommerce_cart_hash",                  0.95, "woocommerce_cart_hash cookie"),

    # SMM panel family (Perfect Panel, JustAnotherPanel, SmartPanel forks)
    c.body  ("perfect-panel", c.re_(r"perfectcdn\.com|cdn\.glycon\.net"), 0.95, "Perfect Panel CDN signature"),
    c.body  ("perfect-panel", c.re_(r"/api/v2/.*action=add"),         0.85, "/api/v2/ action=add pattern"),
    c.body  ("smm-panel",     c.re_(r"reseller\s+panel|smm\s+panel|order\s+services"), 0.5, "SMM-panel marketing copy"),

    # phpMyAdmin (usually exposed accidentally)
    c.body  ("phpmyadmin", c.re_(r"phpMyAdmin"),                      0.9, "phpMyAdmin string in body"),
    c.path  ("phpmyadmin", c.re_(r"/phpmyadmin"),                     0.6, "/phpmyadmin path"),

    # cPanel / Plesk control planes
    c.body  ("cpanel",     c.re_(r"cpanel\.com|/cpsess"),             0.85, "cPanel UI markers"),
    c.body  ("plesk",      c.re_(r"plesk-page|plesk-statusbar"),      0.85, "Plesk UI markers"),
)


def detect(exchanges: Iterable[HTTPExchange]) -> DetectionResult:
    return c.run("cms_detection", SIGNATURES, exchanges, category="cms")
