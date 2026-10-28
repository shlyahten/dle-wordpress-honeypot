<?php
/*
 * WordPress Admin Decoy Handler
 * shlyahten.ru — Authentic redirect to login trap
 */
require_once __DIR__ . '/../engine/modules/honeypot.php';
SiteHoneypot::handle('wp-admin');
