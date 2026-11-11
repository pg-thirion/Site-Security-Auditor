<?php
/** Exercise packaging failures without replacing the release archive. */
$runner  = <<<'PHP'
if ( class_exists( 'ZipArchive' ) ) {
    exit(77);
}
if ( ! class_exists( 'ZipArchive' ) ) {
class ZipArchive {
    const CREATE = 1;
    const OVERWRITE = 8;
    public function open($path, $flags) { return true; }
    public function addFile($path, $entry) { return $GLOBALS['argv'][1] !== 'add'; }
    public function setMtimeName($entry, $timestamp) { return $GLOBALS['argv'][1] !== 'mtime'; }
    public function close() { return $GLOBALS['argv'][1] !== 'close'; }
}
}
PHP;
$fixture = sys_get_temp_dir() . '/ssa-package-' . bin2hex( random_bytes( 8 ) );
$files   = array( 'site-security-auditor.php', 'uninstall.php', 'readme.txt', 'LICENSE', 'build/index.js', 'build/index.asset.php', 'build/style-index.css' );
mkdir( $fixture . '/scripts', 0777, true );
mkdir( $fixture . '/site-security-auditor/build', 0777, true );
copy( dirname( __DIR__, 2 ) . '/scripts/package-plugin.php', $fixture . '/scripts/package-plugin.php' );
foreach ( $files as $file ) {
	file_put_contents( $fixture . '/site-security-auditor/' . $file, 'fixture' );
}
$runner .= "\nrequire " . var_export( $fixture . '/scripts/package-plugin.php', true ) . ';';
try {
	foreach ( array( 'add', 'mtime', 'close', 'success' ) as $mode ) {
		$process = proc_open(
			array( PHP_BINARY, '-n', '-r', $runner, $mode ),
			array(
				1 => array( 'pipe', 'w' ),
				2 => array( 'pipe', 'w' ),
			),
			$pipes
		);
		if ( ! is_resource( $process ) ) {
			throw new RuntimeException( 'Could not run isolated package check.' );
		}
		$output = stream_get_contents( $pipes[1] );
		$error  = stream_get_contents( $pipes[2] );
		fclose( $pipes[1] );
		fclose( $pipes[2] );
		$exit = proc_close( $process );
		if ( 77 === $exit ) {
			echo "package: skipped, ZipArchive is compiled into this PHP binary\n";
			return;
		}
		$success = 'success' === $mode;
		if ( ( $success ? 0 !== $exit : 0 === $exit ) || $success !== str_contains( $output, 'Created artifacts/site-security-auditor.zip' ) || ( ! $success && '' === $error ) ) {
			throw new RuntimeException( 'Packaging did not report ' . $mode . ' correctly: ' . $output . $error );
		}
	}
	echo "package: add, timestamp and close failures return errors; success is reported only after close\n";
} finally {
	foreach ( $files as $file ) {
		unlink( $fixture . '/site-security-auditor/' . $file );
	}
	unlink( $fixture . '/scripts/package-plugin.php' );
	foreach ( array( '/site-security-auditor/build', '/site-security-auditor', '/scripts', '/artifacts', '' ) as $directory ) {
		if ( is_dir( $fixture . $directory ) ) {
			rmdir( $fixture . $directory );
		}
	}
}
