<?php
/*
 * WordPress Admin Dashboard Decoy Index
 * Authentic 302 redirect to login trap
 */
require_once __DIR__ . '/../engine/modules/honeypot.php';
SiteHoneypot::handle('wp-admin');
