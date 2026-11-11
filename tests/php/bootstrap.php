<?php
/** PHPUnit bootstrap for unit and WordPress integration tests. */

declare(strict_types=1);

$autoload = dirname( __DIR__, 2 ) . '/vendor/autoload.php';
if ( file_exists( $autoload ) ) {
	require_once $autoload;
}

if ( getenv( 'WP_TESTS_DIR' ) && file_exists( getenv( 'WP_TESTS_DIR' ) . '/includes/functions.php' ) ) {
	require_once getenv( 'WP_TESTS_DIR' ) . '/includes/functions.php';
	tests_add_filter(
		'muplugins_loaded',
		static function (): void {
			$active = (array) get_option( 'active_plugins', array() );
			if ( ! defined( 'SSA_FILE' ) && ! in_array( 'site-security-auditor/site-security-auditor.php', $active, true ) ) {
				require_once dirname( __DIR__, 2 ) . '/site-security-auditor/site-security-auditor.php';
			}
		}
	);
	require getenv( 'WP_TESTS_DIR' ) . '/includes/bootstrap.php';
}
