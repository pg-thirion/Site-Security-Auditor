<?php
namespace SiteSecurityAuditor\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SiteSecurityAuditor\Services\ScoreCalculator;

final class ScoreCalculatorTest extends TestCase {
	public function test_exactly_seventy_percent_coverage_keeps_score(): void {
		$checks = array();
		foreach ( range( 1, 10 ) as $index ) {
			$checks[ sprintf( 'SSA-%03d', $index ) ] = array( 'status' => $index <= 7 ? 'pass' : 'unknown' );
		}
		$result = ScoreCalculator::calculate( $checks, array() );
		$this->assertSame( 70.0, $result['coverage'] );
		$this->assertSame( 100, $result['score'] );
		$this->assertSame( '1', $result['score_version'] );
	}
	public function test_penalties_floor_at_zero_without_counting_unrated_findings(): void {
		$checks   = array();
		$findings = array();
		foreach ( range( 1, 6 ) as $index ) {
			$id            = sprintf( 'SSA-%03d', $index );
			$checks[ $id ] = array( 'status' => 'fail' );
			$findings[]    = array(
				'check_id' => $id,
				'severity' => $index <= 5 ? 'critical' : 'unrated',
			);
		}
		$this->assertSame( 0, ScoreCalculator::calculate( $checks, $findings )['score'] );
		$this->assertSame( 100, ScoreCalculator::calculate( array( 'SSA-006' => $checks['SSA-006'] ), array( end( $findings ) ) )['score'] );
	}
	public function test_penalises_only_the_highest_finding_per_failed_check(): void {
		$result = ScoreCalculator::calculate(
			array(
				'SSA-001' => array( 'status' => 'fail' ),
				'SSA-002' => array( 'status' => 'pass' ),
				'SSA-003' => array( 'status' => 'not_applicable' ),
			),
			array(
				array(
					'check_id' => 'SSA-001',
					'severity' => 'high',
				),
				array(
					'check_id' => 'SSA-001',
					'severity' => 'low',
				),
			)
		);

		$this->assertSame( 88, $result['score'] );
		$this->assertSame( 100.0, $result['coverage'] );
		$this->assertSame( 2, $result['eligible'] );
	}

	public function test_unknown_checks_reduce_coverage_and_hide_low_coverage_score(): void {
		$result = ScoreCalculator::calculate(
			array(
				'SSA-001' => array( 'status' => 'pass' ),
				'SSA-002' => array( 'status' => 'unknown' ),
				'SSA-003' => array( 'status' => 'unknown' ),
			),
			array()
		);

		$this->assertNull( $result['score'] );
		$this->assertSame( 33.33, $result['coverage'] );
	}

	public function test_informational_checks_do_not_change_score_or_coverage(): void {
		$result = ScoreCalculator::calculate(
			array(
				'SSA-001' => array( 'status' => 'pass' ),
				'SSA-015' => array( 'status' => 'fail' ),
				'SSA-016' => array( 'status' => 'unknown' ),
			),
			array(
				array(
					'check_id' => 'SSA-015',
					'severity' => 'critical',
				),
			)
		);

		$this->assertSame( 100, $result['score'] );
		$this->assertSame( 100.0, $result['coverage'] );
	}
}
