<?php
/*
 * WordPress Login Honeypot Decoy
 * shlyahten.ru — Intercepts and mitigates automated bot attacks
 */
require_once __DIR__ . '/engine/modules/honeypot.php';
SiteHoneypot::handle('wp-login');
