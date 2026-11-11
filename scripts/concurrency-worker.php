<?php
/** Local-only subprocess worker for concurrency-smoke.py, invoked through WP-CLI. */

use SiteSecurityAuditor\Persistence\ScanRepository;
use SiteSecurityAuditor\Services\ScanRunner;

if ( 'local' !== wp_get_environment_type() ) {
	throw new RuntimeException( 'Concurrency smoke requires a disposable local WordPress site.' );
}
$operation = $args[0] ?? '';
$scan_id   = (int) ( $args[1] ?? 0 );
if ( 'start' === $operation ) {
	$result = ScanRunner::start( 0 );
} elseif ( 'advance' === $operation || 'slow-advance' === $operation ) {
	if ( 'slow-advance' === $operation ) {
		// Hold real worker execution inside its acquired lock, without changing production code.
		add_filter(
			'query',
			static function ( $query ) {
				if ( str_starts_with( $query, 'UPDATE' ) && str_contains( $query, 'ssa_scans' ) && str_contains( $query, 'running' ) ) {
					usleep( 2000000 );
				}
				return $query;
			}
		);
	}
	$result = ScanRunner::advance( $scan_id );
} elseif ( 'cancel' === $operation ) {
	( new ScanRepository() )->cancel( $scan_id );
	$result = ( new ScanRepository() )->get( $scan_id );
} else {
	throw new RuntimeException( 'Unknown concurrency worker operation.' );
}
if ( is_wp_error( $result ) ) {
	$result = array( 'error' => $result->get_error_code() );
}
echo 'SSA_RESULT:' . wp_json_encode( $result ) . PHP_EOL;
