<?php
namespace SiteSecurityAuditor\Audit;

use SiteSecurityAuditor\Audit\Checks\LocalChecks;
use SiteSecurityAuditor\Audit\Checks\ProviderChecks;

final class AuditRegistry {

	public static function ids(): array {
		return array_map( static fn( $n ) => sprintf( 'SSA-%03d', $n ), range( 1, 16 ) );
	}

	public static function run( string $id, array $context = array() ): array {
		$start = microtime( true );
		$check = (int) substr( $id, 4 );
		if ( ! in_array( $id, self::ids(), true ) ) {
			return self::result( $id, 'unknown', 'Check is not registered.', array(), 0, $start );
		}
		try {
			$data = ( $check >= 4 && $check <= 6 ) || 12 === $check
				? ProviderChecks::run( $check, $context )
				: LocalChecks::run( $check, $context );
		} catch ( \Throwable $e ) {
			$data = array(
				'status'         => 'unknown',
				'reason'         => 'Check could not be completed.',
				'findings'       => array(),
				'affected_count' => 0,
			);
		}
		$findings = $data['findings'] ?? array();
		foreach ( $findings as &$finding ) {
			$finding['check_id'] = $id;
		}
		unset( $finding );
		return self::result( $id, $data['status'] ?? 'unknown', $data['reason'] ?? 'Check could not be completed.', $findings, $data['affected_count'] ?? 0, $start, $data['cursor'] ?? null, ! empty( $data['has_unknown'] ) );
	}

	private static function result( string $id, string $status, string $reason, array $findings, int $count, float $start, $cursor = null, bool $has_unknown = false ): array {
		$out = array(
			'check_id'       => $id,
			'status'         => in_array( $status, array( 'pass', 'fail', 'unknown', 'not_applicable' ), true ) ? $status : 'unknown',
			'reason'         => substr( $reason, 0, 300 ),
			'checked_at'     => gmdate( 'c' ),
			'duration'       => round( microtime( true ) - $start, 3 ),
			'affected_count' => max( 0, $count ),
			'findings'       => $findings,
			'has_unknown'    => $has_unknown,
		);
		if ( null !== $cursor ) {
			$out['cursor'] = $cursor;
		}
		return $out;
	}
}
