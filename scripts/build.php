<?php
/**
 * Release Build Script for WordPress Honeypot DLE Plugin
 *
 * Usage: php scripts/build.php [version]
 */

$repoDir = dirname(__DIR__);
$xmlFile = $repoDir . '/honeypot-dle-plugin.xml';
$jsonFile = $repoDir . '/version.json';
$distDir = $repoDir . '/dist';
$zipFile = $distDir . '/dle-wordpress-honeypot.zip';

echo "=== Honeypot Plugin Release Builder ===\n\n";

// 1. Determine target version
$targetVersion = null;
if (!empty($argv[1])) {
    $targetVersion = ltrim(trim($argv[1]), 'v');
} else {
    // Read from XML
    if (file_exists($xmlFile)) {
        $xml = simplexml_load_file($xmlFile);
        if ($xml && isset($xml->version)) {
            $targetVersion = (string)$xml->version;
        }
    }
}

if (!$targetVersion || !preg_match('/^[0-9]+\.[0-9]+(\.[0-9]+)?(-[a-zA-Z0-9.]+)?$/', $targetVersion)) {
    fwrite(STDERR, "Error: Invalid version format '{$targetVersion}'. Expected semantic version like 1.0.0 or 1.0.1\n");
    exit(1);
}

echo "Target release version: {$targetVersion}\n";

// 2. Validate PHP files syntax
echo "Validating PHP files...\n";
$phpFiles = [];
$iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($repoDir . '/upload'));
foreach ($iterator as $file) {
    if ($file->isFile() && $file->getExtension() === 'php') {
        $phpFiles[] = $file->getPathname();
    }
}

foreach ($phpFiles as $file) {
    $rel = str_replace($repoDir . '/', '', $file);
    exec('php -l ' . escapeshellarg($file) . ' 2>&1', $out, $code);
    if ($code !== 0) {
        fwrite(STDERR, "Syntax error in {$rel}:\n" . implode("\n", $out) . "\n");
        exit(1);
    }
    echo "  [OK] {$rel}\n";
}

// 3. Validate XML manifest
echo "\nValidating XML manifest...\n";
$xml = @simplexml_load_file($xmlFile);
if (!$xml) {
    fwrite(STDERR, "Error: honeypot-dle-plugin.xml is not valid XML!\n");
    exit(1);
}
echo "  [OK] honeypot-dle-plugin.xml is valid\n";

// 4. Validate admin icon
$iconFile = $repoDir . '/upload/public/adminpanel/images/honeypot.png';
if (!file_exists($iconFile)) {
    fwrite(STDERR, "Error: Missing admin icon at {$iconFile}!\n");
    exit(1);
}
$imgInfo = @getimagesize($iconFile);
if (!$imgInfo || $imgInfo[2] !== IMAGETYPE_PNG) {
    fwrite(STDERR, "Error: Admin icon {$iconFile} is not a valid PNG image!\n");
    exit(1);
}
echo "  [OK] Admin icon validated ({$imgInfo[0]}x{$imgInfo[1]} PNG)\n";

// 5. Validate gzip bomb decoy
$bombFile = $repoDir . '/upload/wp-admin/admin.gzip';
if (!file_exists($bombFile) || filesize($bombFile) < 100000) {
    fwrite(STDERR, "Error: Missing or corrupt admin.gzip bomb decoy!\n");
    exit(1);
}
echo "  [OK] Gzip bomb decoy validated (" . round(filesize($bombFile) / 1024 / 1024, 2) . " MB)\n";

// 6. Synchronize version in XML
echo "\nSynchronizing version {$targetVersion}...\n";
$xmlContent = file_get_contents($xmlFile);
$xmlContent = preg_replace('/<version>[^<]+<\/version>/', "<version>{$targetVersion}</version>", $xmlContent, 1);
file_put_contents($xmlFile, $xmlContent);
echo "  [OK] Updated honeypot-dle-plugin.xml\n";

// 7. Synchronize version.json
$jsonContent = [
    'version' => $targetVersion,
    'url' => 'https://github.com/shlyahten/dle-wordpress-honeypot/releases/latest/download/honeypot-dle-plugin.xml',
    'description' => 'WordPress Honeypot & Threat Intelligence для DataLife Engine',
];
file_put_contents($jsonFile, json_encode($jsonContent, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n");
echo "  [OK] Updated version.json\n";

// 8. Prepare dist package
if (!is_dir($distDir)) {
    mkdir($distDir, 0755, true);
}
if (file_exists($zipFile)) {
    unlink($zipFile);
}

// Copy standalone XML to dist
copy($xmlFile, $distDir . '/honeypot-dle-plugin.xml');
echo "  [OK] Copied standalone honeypot-dle-plugin.xml to dist/\n";

// 9. Create ZIP archive
echo "\nBuilding ZIP distribution package...\n";
$tempBuild = sys_get_temp_dir() . '/honeypot-build-' . uniqid();
mkdir($tempBuild, 0755, true);

// Recursive copy helper
function copyDir($src, $dst) {
    $dir = opendir($src);
    @mkdir($dst, 0755, true);
    while (false !== ($file = readdir($dir))) {
        if ($file != '.' && $file != '..') {
            if (is_dir($src . '/' . $file)) {
                copyDir($src . '/' . $file, $dst . '/' . $file);
            } else {
                copy($src . '/' . $file, $dst . '/' . $file);
            }
        }
    }
    closedir($dir);
}

copyDir($repoDir . '/upload', $tempBuild . '/upload');
copy($xmlFile, $tempBuild . '/honeypot-dle-plugin.xml');
copy($repoDir . '/README.md', $tempBuild . '/README.md');
copy($repoDir . '/LICENSE', $tempBuild . '/LICENSE');
if (file_exists($repoDir . '/logo.png')) {
    copy($repoDir . '/logo.png', $tempBuild . '/logo.png');
}

$cmd = 'cd ' . escapeshellarg($tempBuild) . ' && zip -r -9 ' . escapeshellarg($zipFile) . ' .';
exec($cmd, $zipOut, $zipCode);

// Cleanup temp build
exec('rm -rf ' . escapeshellarg($tempBuild));

if ($zipCode !== 0 || !file_exists($zipFile)) {
    fwrite(STDERR, "Error building ZIP archive!\n");
    exit(1);
}

$zipSize = filesize($zipFile);
echo "  [OK] Archive created: dist/dle-wordpress-honeypot.zip (" . round($zipSize / 1024, 1) . " KB)\n";

// 10. Verify zip archive contents
$zip = new ZipArchive();
if ($zip->open($zipFile) !== true) {
    fwrite(STDERR, "Error: Cannot open created zip archive!\n");
    exit(1);
}

$requiredEntries = [
    'upload/engine/modules/honeypot.php',
    'upload/engine/inc/honeypot.php',
    'upload/public/adminpanel/images/honeypot.png',
    'upload/wp-login.php',
    'upload/wp-admin/index.php',
    'upload/wp-admin/admin.php',
    'upload/wp-admin/admin.gzip',
    'upload/xmlrpc.php',
    'upload/admin.php.sample',
    'honeypot-dle-plugin.xml',
    'README.md',
    'LICENSE',
    'logo.png',
];

foreach ($requiredEntries as $entry) {
    if ($zip->locateName($entry) === false) {
        fwrite(STDERR, "Error: Missing {$entry} in zip package!\n");
        $zip->close();
        exit(1);
    }
}
$zip->close();
echo "  [OK] Verified all required package entries inside ZIP archive\n";

echo "\n============================================\n";
echo "BUILD SUCCESSFUL! Version {$targetVersion}\n";
echo "Archive: dist/dle-wordpress-honeypot.zip\n";
echo "Plugin XML: dist/honeypot-dle-plugin.xml\n";
echo "============================================\n";
