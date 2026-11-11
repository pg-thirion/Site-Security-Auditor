<?php

// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite, WordPress.WP.AlternativeFunctions.file_system_operations_fclose -- Parse CSV through an in-memory stream to verify quoting and row boundaries.

namespace SiteSecurityAuditor\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SiteSecurityAuditor\Services\ExportService;

final class ExportServiceTest extends TestCase {
	/** Formula prefixes remain inert even behind whitespace. */
	public function test_formula_prefixes_are_neutralised(): void {
		foreach ( array( '=SUM(1,2)', '+1', '-1', '@SUM(A1)', "\tvalue", " \t=1", "\n=1" ) as $input ) {
			$this->assertSame( "'" . $input, ExportService::csv_cell( $input ) );
		}
		$this->assertSame( 'A normal value', ExportService::csv_cell( 'A normal value' ) );
	}
	/** Stored unknown checks are represented even when no finding exists. */
	public function test_csv_preserves_unknown_checks_and_quoted_unicode(): void {
		$scan   = array(
			'checks' => array(
				array(
					'check_id'   => 'SSA-004',
					'status'     => 'unknown',
					'reason'     => 'Provider disabled',
					'checked_at' => '2026-11-10T00:00:00Z',
				),
			),
		);
		$csv    = ExportService::csv(
			$scan,
			array(
				array(
					'check_id' => 'SSA-007',
					'title'    => "Caf\xc3\xa9, \"quoted\"\nsecond line",
					'evidence' => '=1+1',
				),
			)
		);
		$stream = fopen( 'php://temp', 'r+' );
		fwrite( $stream, $csv );
		rewind( $stream );
		$header  = fgetcsv( $stream, 0, ',', '"', '' );
		$finding = array_combine( $header, fgetcsv( $stream, 0, ',', '"', '' ) );
		$check   = array_combine( $header, fgetcsv( $stream, 0, ',', '"', '' ) );
		fclose( $stream );
		$this->assertSame( "Caf\xc3\xa9, \"quoted\"\nsecond line", $finding['title'] );
		$this->assertSame( "'=1+1", $finding['evidence'] );
		$this->assertSame( 'unknown', $check['status'] );
		$this->assertSame( 'Provider disabled', $check['evidence'] );
	}
}
