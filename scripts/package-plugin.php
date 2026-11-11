<?php
/** Create a timestamp-normalised release archive from the plugin directory. */

// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fwrite, WordPress.WP.AlternativeFunctions.file_system_operations_mkdir -- This CLI creates and reports a repository artifact outside WordPress.

declare(strict_types=1);

$root   = dirname( __DIR__ );
$source = $root . '/site-security-auditor';
$target = $root . '/artifacts/site-security-auditor.zip';

$required = array(
	'site-security-auditor.php',
	'uninstall.php',
	'readme.txt',
	'LICENSE',
	'build/index.js',
	'build/index.asset.php',
	'build/style-index.css',
);
foreach ( $required as $file ) {
	if ( ! is_file( $source . '/' . $file ) ) {
		fwrite( STDERR, "Missing release file: {$file}\n" );
		exit( 1 );
	}
}

if ( ! class_exists( ZipArchive::class ) ) {
	fwrite( STDERR, "Enable PHP's zip extension to create the archive.\n" );
	exit( 1 );
}

if ( ! is_dir( dirname( $target ) ) ) {
	mkdir( dirname( $target ), 0777, true );
}

$zip = new ZipArchive();
if ( $zip->open( $target, ZipArchive::CREATE | ZipArchive::OVERWRITE ) !== true ) {
	fwrite( STDERR, "Could not create release archive.\n" );
	exit( 1 );
}

$files = array();

foreach ( array( 'site-security-auditor.php', 'uninstall.php', 'readme.txt', 'LICENSE' ) as $file ) {
	$files[ 'site-security-auditor/' . $file ] = $source . '/' . $file;
}

foreach ( array( 'includes', 'build', 'languages' ) as $directory ) {
	$scan_dir = $source . '/' . $directory;
	if ( ! is_dir( $scan_dir ) ) {
		continue;
	}

	$iterator = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $scan_dir, FilesystemIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::LEAVES_ONLY
	);
	foreach ( $iterator as $file ) {
		if ( ! $file->isFile() || $file->isLink() || ! preg_match( '/\.(?:php|js|css|mo)$/i', $file->getFilename() ) ) {
			continue;
		}
		$relative = substr( $file->getPathname(), strlen( $source ) + 1 );
		$files[ 'site-security-auditor/' . str_replace( '\\', '/', $relative ) ] = $file->getPathname();
	}
}

ksort( $files, SORT_STRING );
foreach ( $files as $entry => $file_path ) {
	if ( ! $zip->addFile( $file_path, $entry ) || ! $zip->setMtimeName( $entry, 315532800 ) ) { // ZIP's minimum supported timestamp: 1980-01-01.
		fwrite( STDERR, "Could not add release file: {$entry}\n" );
		exit( 1 );
	}
}

if ( ! $zip->close() ) {
	fwrite( STDERR, "Could not finish release archive.\n" );
	exit( 1 );
}
fwrite( STDOUT, "Created artifacts/site-security-auditor.zip\n" );
