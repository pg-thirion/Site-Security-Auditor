<?php
namespace SiteSecurityAuditor\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SiteSecurityAuditor\Persistence\ScanRepository;

final class StoredScanTest extends TestCase {
	public function test_corrupt_stored_results_cannot_display_a_passing_score(): void {
		$decode = new \ReflectionMethod( ScanRepository::class, 'decode' );
		$decode->setAccessible( true );
		$row    = array(
			'id'            => '1',
			'status'        => 'completed',
			'checks_json'   => '{broken',
			'progress_json' => '{}',
			'coverage'      => '100',
			'assessed'      => '14',
			'score'         => '100',
		);
		$result = $decode->invoke( new ScanRepository(), $row );
		$this->assertSame( 'failed', $result['status'] );
		$this->assertSame( 'stored_result_invalid', $result['diagnostic'] );
		$this->assertNull( $result['score'] );
		$this->assertSame( 0.0, $result['coverage'] );
	}
	public function test_valid_versioned_history_is_preserved(): void {
		$checks = array();
		foreach ( range( 1, 16 ) as $index ) {
			$id            = sprintf( 'SSA-%03d', $index );
			$checks[ $id ] = array(
				'check_id' => $id,
				'status'   => 'pass',
			);
		}
		$row    = array(
			'id'            => '1',
			'status'        => 'completed',
			'checks_json'   => json_encode( $checks ), // phpcs:ignore WordPress.WP.AlternativeFunctions.json_encode_json_encode -- This isolated unit test does not bootstrap WordPress.
			'progress_json' => '{}',
			'coverage'      => '100',
			'assessed'      => '14',
			'score'         => '88',
			'score_version' => '1',
		);
		$decode = new \ReflectionMethod( ScanRepository::class, 'decode' );
		$decode->setAccessible( true );
		$result = $decode->invoke( new ScanRepository(), $row );
		$this->assertSame( 88, $result['score'] );
		$this->assertSame( '1', $result['score_version'] );
		$this->assertCount( 16, $result['checks'] );
	}
}
