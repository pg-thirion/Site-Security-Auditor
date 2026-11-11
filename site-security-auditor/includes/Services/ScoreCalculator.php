<?php
namespace SiteSecurityAuditor\Services;

final class ScoreCalculator {
	public static function calculate( array $checks, array $findings ): array {
		$penalties  = array(
			'critical' => 25,
			'high'     => 12,
			'medium'   => 6,
			'low'      => 2,
			'info'     => 0,
			'unrated'  => 0,
		);
		$eligible   = 0;
		$assessed   = 0;
		$deductions = array();
		foreach ( $checks as $key => $check ) {
			$id = $check['check_id'] ?? $key;
			if ( in_array( $id, array( 'SSA-015', 'SSA-016' ), true ) || 'not_applicable' === $check['status'] ) {
				continue;
			}
			++$eligible;
			if ( in_array( $check['status'], array( 'pass', 'fail' ), true ) ) {
				++$assessed;
			}
			if ( 'fail' === $check['status'] ) {
				foreach ( $findings as $finding ) {
					if ( $finding['check_id'] === $id ) {
						$deductions[ $id ] = max( $deductions[ $id ] ?? 0, $penalties[ $finding['severity'] ] ?? 0 );
					}
				}
			}
		}
		$coverage = $eligible ? round( 100 * $assessed / $eligible, 2 ) : 0;
		return array(
			'score_version' => '1',
			'score'         => $coverage >= 70 ? max( 0, 100 - array_sum( $deductions ) ) : null,
			'coverage'      => $coverage,
			'assessed'      => $assessed,
			'eligible'      => $eligible,
		);
	}
}
