# Builds compress-archive-backup.zip: a site backup as Windows PowerShell 5.1 writes one.
#
# Run it on Windows, in Windows PowerShell 5.1 (`powershell`, not `pwsh`): its in-box
# Microsoft.PowerShell.Archive 1.0.1.0 stores every path with backslash separators and marks
# every entry as written by MS-DOS (host byte 0), which is what the member-name tests need to
# read. pwsh 7 writes forward slashes and would not be the same fixture.
#
# Every file is synthetic. The tree is an ordinary site, with ordinary names that carry an
# apostrophe or an ampersand, and five hostile names planted in final components. None of the
# five carries a character FN002 reads, so a scan of the backup that raises FN002 at all has
# read a separator as part of a name.
#
#   x$(id)-a.mdb        FN001
#   y`id`-b.mdb         FN001
#   -rf-c.htaccess      FN004
#   f..<U+FF0F>g.php    FN005
#   d.php%00-e.mdb      FN006
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File make-compress-archive-backup.ps1 OUTDIR
param([Parameter(Mandatory = $true)][string]$OutDir)
$ErrorActionPreference = 'Stop'
if ($PSVersionTable.PSVersion.Major -ne 5) { throw "run this in Windows PowerShell 5.1, not $($PSVersionTable.PSVersion)" }

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

$zip = Join-Path $OutDir 'compress-archive-backup.zip'
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
# Stored rather than deflated, so the names and the bytes can be read in the file as it is.
Compress-Archive -Path (Join-Path $work 'site') -DestinationPath $zip -CompressionLevel NoCompression
Remove-Item -LiteralPath $work -Recurse -Force
Get-Item -LiteralPath $zip | Select-Object Name, Length
