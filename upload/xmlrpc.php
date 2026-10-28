<?php
/*
 * WordPress XML-RPC Endpoint Decoy
 * Catches multicall brute-force attacks and DDoS reflection
 */
require_once __DIR__ . '/engine/modules/honeypot.php';
SiteHoneypot::handle('xmlrpc');
