<?php
namespace SiteSecurityAuditor\Tests\Unit;

use PHPUnit\Framework\TestCase;
use SiteSecurityAuditor\Persistence\FindingRepository;
use SiteSecurityAuditor\Persistence\ScanRepository;
use SiteSecurityAuditor\Services\RetentionService;

final class StorageFailureTest extends TestCase {
	public static function setUpBeforeClass(): void {
		if ( ! defined( 'ARRAY_A' ) ) {
			define( 'ARRAY_A', 'ARRAY_A' );
		}
	}
	public function test_failed_finding_read_throws_instead_of_returning_an_empty_report(): void {
		global $wpdb;
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Use a controlled database result for this unit test.
		$wpdb = new class() {
			public string $prefix     = 'wp_';
			public string $last_error = 'Simulated SELECT failure';
			public function prepare( string $query, int $scan_id ): string {
				return $query;
			}
			public function get_col( string $query ): array {
				return array();
			}
		};

		$this->expectException( \RuntimeException::class );
		$this->expectExceptionMessage( 'storage_failed' );
		( new FindingRepository() )->all( 7 );
	}
	public function test_failed_scan_reads_do_not_look_like_missing_scans_or_empty_history(): void {
		global $wpdb;
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Use a controlled database result for this unit test.
		$wpdb       = new class() {
			public string $prefix     = 'wp_';
			public string $last_error = 'Simulated SELECT failure';
			public function prepare( string $query, ...$arguments ): string {
				return $query;
			}
			public function get_row( string $query, ...$arguments ): ?array {
				return null;
			}
			public function get_results( string $query, ...$arguments ): array {
				return array();
			}
			public function get_var( string $query, ...$arguments ) {
				return null;
			}
		};
		$repository = new ScanRepository();
		$reads      = array(
			'get'     => static fn() => $repository->get( 7 ),
			'active'  => static fn() => $repository->active(),
			'listing' => static fn() => $repository->listing(),
		);

		foreach ( $reads as $name => $read ) {
			try {
				$read();
				$this->fail( "A failed scan {$name} query must throw." );
			} catch ( \RuntimeException $error ) {
				$this->assertSame( 'storage_failed', $error->getMessage() );
			}
		}
	}
	public function test_failed_finding_count_and_list_reads_do_not_look_empty(): void {
		global $wpdb;
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Use a controlled database result for this unit test.
		$wpdb       = new class() {
			public string $prefix     = 'wp_';
			public string $last_error = 'Simulated SELECT failure';
			public function prepare( string $query, ...$arguments ): string {
				return $query;
			}
			public function get_var( string $query, ...$arguments ) {
				return null;
			}
			public function get_col( string $query, ...$arguments ): array {
				return array();
			}
		};
		$repository = new FindingRepository();
		$reads      = array(
			'count'  => static fn() => $repository->count( 7 ),
			'list'   => static fn() => $repository->listing( 7, 1, 20 ),
			'search' => static fn() => $repository->listing( 7, 1, 20, array(), 'needle' ),
		);

		foreach ( $reads as $name => $read ) {
			try {
				$read();
				$this->fail( "A failed finding {$name} query must throw." );
			} catch ( \RuntimeException $error ) {
				$this->assertSame( 'storage_failed', $error->getMessage() );
			}
		}
	}
	public function test_failed_atomic_retention_delete_keeps_scans_and_findings(): void {
		global $wpdb;
		if ( ! defined( 'DAY_IN_SECONDS' ) ) {
			define( 'DAY_IN_SECONDS', 86400 );
		}
		// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited -- Use a controlled database result for this unit test.
		$wpdb = new class() {
			public string $prefix  = 'wp_';
			public array $queries  = array();
			public array $scans    = array( 7 );
			public array $findings = array( 7 );
			public function prepare( string $query, ...$arguments ): string {
				return $query;
			}
			public function get_col( string $query ): array {
				return str_contains( $query, 'OFFSET 20' ) ? array() : array( 7 );
			}
			public function query( string $query ) {
				$this->queries[] = $query;
				return false;
			}
		};

		RetentionService::prune();

		$this->assertSame( 1, count( $wpdb->queries ) );
		$this->assertStringContainsString( 'DELETE scans, findings', $wpdb->queries[0] );
		$this->assertStringContainsString( 'LEFT JOIN wp_ssa_findings findings', $wpdb->queries[0] );
		$this->assertSame( array( 7 ), $wpdb->scans );
		$this->assertSame( array( 7 ), $wpdb->findings );
	}
}
