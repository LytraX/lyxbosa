# Builds php-ziparchive-backup.zip: a site backup as PHP's ZipArchive writes one on Windows.
#
# Run it on Windows, with a Windows build of PHP on PATH. The backup is written the way backup
# plugins and the usual recipe write one: a RecursiveDirectoryIterator walk, the root's prefix
# stripped from each path to make it relative, and addFile(). On Windows the walk spells every
# path with backslashes, and PHP's bundled libzip stores each entry under host byte 3 (Unix), as
# it does on every platform - so no field of the result but the names says a Windows host wrote
# it. PHP 8.5.3 with libzip 1.11.2 wrote the committed file.
#
# The tree is the one make-compress-archive-backup.ps1 builds, file for file, so the two
# fixtures differ only in their writer. Every file is synthetic: an ordinary site, with ordinary
# names that carry an apostrophe or an ampersand, and five hostile names planted in final
# components. None of the five carries a character FN002 reads.
#
#   x$(id)-a.mdb        FN001
#   y`id`-b.mdb         FN001
#   -rf-c.htaccess      FN004
#   f..<U+FF0F>g.php    FN005
#   d.php%00-e.mdb      FN006
#
# Usage: pwsh -NoProfile -File make-php-ziparchive-backup.ps1 OUTDIR
param([Parameter(Mandatory = $true)][string]$OutDir)
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'run this on Windows: the walk has to spell the paths' }

$work = Join-Path $OutDir 'backup-tree'
Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
$fullwidthSolidus = [string][char]0xFF0F
$files = [ordered]@{
    'site\index.php'                                           = "<?php require __DIR__ . '/wp-blog-header.php';"
    'site\wp-blog-header.php'                                  = '<?php // loads the theme'
    'site\wp-includes\version.php'                             = "<?php `$wp_version = '6.6';"
    'site\wp-includes\js\jquery\jquery.min.js'                 = '/* minified */'
    'site\wp-content\themes\twentytwenty\style.css'            = 'body { margin: 0; }'
    'site\wp-content\themes\twentytwenty\functions.php'        = '<?php // theme setup'
    'site\wp-content\plugins\contact-form\contact-form.php'    = '<?php // plugin'
    "site\wp-content\uploads\2024\05\O'Brien & Sons Invoice.pdf" = 'pdf'
    'site\wp-content\uploads\2024\05\Q&A with Marks & Spencer.docx' = 'docx'
    "site\wp-content\uploads\2024\06\Dave's Deli menu.jpg"      = 'jpg'
    'site\wp-content\uploads\2024\05\x$(id)-a.mdb'             = 'db'
    'site\wp-content\uploads\2024\06\y`id`-b.mdb'              = 'db'
    'site\wp-content\uploads\-rf-c.htaccess'                   = 'deny from all'
    ('site\wp-content\uploads\f..' + $fullwidthSolidus + 'g.php') = '<?php echo 1;'
    'site\wp-content\uploads\d.php%00-e.mdb'                   = 'db'
}
foreach ($entry in $files.GetEnumerator()) {
    $path = Join-Path $work $entry.Key
    New-Item -ItemType Directory -Force -Path (Split-Path -LiteralPath $path) | Out-Null
    [IO.File]::WriteAllText($path, $entry.Value + "`n")
}

$script = Join-Path $OutDir 'backup-recipe.php'
@'
<?php
$rootPath = realpath($argv[1]);
$zip = new ZipArchive();
if ($zip->open($argv[2], ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
    fwrite(STDERR, "cannot create $argv[2]\n");
    exit(1);
}
$files = new RecursiveIteratorIterator(
    new RecursiveDirectoryIterator($rootPath, FilesystemIterator::SKIP_DOTS),
    RecursiveIteratorIterator::LEAVES_ONLY
);
foreach ($files as $file) {
    if ($file->isDir()) {
        continue;
    }
    $filePath = $file->getRealPath();
    $zip->addFile($filePath, substr($filePath, strlen($rootPath) + 1));
}
$zip->close();
printf("PHP %s, libzip %s, %s\n", PHP_VERSION, ZipArchive::LIBZIP_VERSION, PHP_OS_FAMILY);
'@ | Set-Content -LiteralPath $script -Encoding ascii

$zip = Join-Path $OutDir 'php-ziparchive-backup.zip'
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
php $script $work $zip
if ($LASTEXITCODE -ne 0) { throw "php exited $LASTEXITCODE" }
Remove-Item -LiteralPath $script -Force
Remove-Item -LiteralPath $work -Recurse -Force
Get-Item -LiteralPath $zip | Select-Object Name, Length
