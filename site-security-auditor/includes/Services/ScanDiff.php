<?php
namespace SiteSecurityAuditor\Services;

use SiteSecurityAuditor\Persistence\FindingRepository;

final class ScanDiff {
	public static function compare( array $previous, array $current, array $checks ): array {
		$before = array();
		$after  = array();
		foreach ( $previous as $finding ) {
			$before[ FindingRepository::identity( $finding ) ] = $finding;
		}
		foreach ( $current as $finding ) {
			$after[ FindingRepository::identity( $finding ) ] = $finding;
		}
		$out = array();
		foreach ( $after + $before as $identity => $finding ) {
			$status   = $checks[ $finding['check_id'] ]['status'] ?? 'unknown';
			$assessed = in_array( $status, array( 'pass', 'fail' ), true );
			$label    = isset( $after[ $identity ] ) && $assessed ? ( isset( $before[ $identity ] ) ? 'Still present' : 'New' ) : ( $assessed && empty( $checks[ $finding['check_id'] ]['has_unknown'] ) ? 'Resolved' : 'Not evaluated' );
			$out[]    = array(
				'identity_hash' => $identity,
				'title'         => $finding['title'],
				'check_id'      => $finding['check_id'],
				'state'         => $label,
			);
		}
		return $out;
	}
}
