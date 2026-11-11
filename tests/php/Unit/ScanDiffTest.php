<?php
namespace SiteSecurityAuditor\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SiteSecurityAuditor\Services\ScanDiff;

final class ScanDiffTest extends TestCase {
	public function test_partial_component_assessment_does_not_resolve_missing_issue(): void {
		$previous                    = array( $this->finding( 'Unavailable component' ) );
		$current                     = array( $this->finding( 'Confirmed issue' ) );
		$current[0]['component_key'] = 'different-component';
		$checks                      = array(
			'SSA-007' => array(
				'status'      => 'fail',
				'has_unknown' => true,
			),
		);
		$states                      = array_column( ScanDiff::compare( $previous, $current, $checks ), 'state', 'title' );
		$this->assertSame( 'Not evaluated', $states['Unavailable component'] );
		$this->assertSame( 'New', $states['Confirmed issue'] );
	}
	private function finding( string $title ): array {
		return array(
			'check_id'       => 'SSA-007',
			'component_type' => 'site',
			'component_key'  => 'https',
			'advisory_id'    => '',
			'title'          => $title,
		);
	}

	public function test_reports_new_still_present_resolved_and_not_evaluated(): void {
		$previous                     = array( $this->finding( 'Still' ), $this->finding( 'Resolved' ), $this->finding( 'Unknown' ) );
		$previous[1]['component_key'] = 'resolved';
		$previous[2]['component_key'] = 'unknown';
		$previous[1]['check_id']      = 'SSA-008';
		$previous[2]['check_id']      = 'SSA-009';
		$current                      = array( $this->finding( 'Still' ), $this->finding( 'New' ) );
		$current[1]['component_key']  = 'new';
		$checks                       = array(
			'SSA-007' => array( 'status' => 'fail' ),
			'SSA-008' => array( 'status' => 'pass' ),
			'SSA-009' => array( 'status' => 'unknown' ),
		);

		$states = array_column( ScanDiff::compare( $previous, $current, $checks ), 'state', 'title' );

		$this->assertSame( 'Still present', $states['Still'] );
		$this->assertSame( 'New', $states['New'] );
		$this->assertSame( 'Resolved', $states['Resolved'] );
		$this->assertSame( 'Not evaluated', $states['Unknown'] );
	}
}
