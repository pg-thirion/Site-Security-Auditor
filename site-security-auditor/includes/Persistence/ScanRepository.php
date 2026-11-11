<?php
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Private custom tables and atomic locks require direct, fresh, parameterised queries.
namespace SiteSecurityAuditor\Persistence;

final class ScanRepository {
	public function create( int $user ): int {
		global $wpdb;
		$now = gmdate( 'Y-m-d H:i:s' );
		$ok  = $wpdb->insert(
			$wpdb->prefix . 'ssa_scans',
			array(
				'started_by'    => $user ? $user : null,
				'status'        => 'queued',
				'checks_json'   => '{}',
				'progress_json' => '{"index":0}',
				'started_at'    => $now,
				'updated_at'    => $now,
			)
		);
		return $ok ? (int) $wpdb->insert_id : 0;
	}
	public function get( int $id ): ?array {
		global $wpdb;
		$row = $wpdb->get_row( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}ssa_scans WHERE id = %d", $id ), ARRAY_A );
		if ( $wpdb->last_error ) {
			throw new \RuntimeException( 'storage_failed' );
		}
		return $row ? $this->decode( $row ) : null;
	}
	public function latest(): ?array {
		$rows = $this->listing( 1, 1 );
		return $rows['items'][0] ?? null;
	}
	public function active(): ?array {
		global $wpdb;
		$row = $wpdb->get_row( "SELECT * FROM {$wpdb->prefix}ssa_scans WHERE status IN ('queued','running') ORDER BY id DESC LIMIT 1", ARRAY_A );
		if ( $wpdb->last_error ) {
			throw new \RuntimeException( 'storage_failed' );
		}
		return $row ? $this->decode( $row ) : null;
	}
	public function listing( int $page = 1, int $limit = 20 ): array {
		global $wpdb;
		$rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM {$wpdb->prefix}ssa_scans ORDER BY id DESC LIMIT %d OFFSET %d", $limit, ( $page - 1 ) * $limit ), ARRAY_A );
		if ( $wpdb->last_error ) {
			throw new \RuntimeException( 'storage_failed' );
		}
		$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}ssa_scans" );
		if ( $wpdb->last_error ) {
			throw new \RuntimeException( 'storage_failed' );
		}
		return array(
			'items' => array_map( array( $this, 'decode' ), $rows ),
			'total' => $total,
		);
	}
	public function save( int $id, array $values ): bool {
		global $wpdb;
		foreach ( array( 'checks', 'progress' ) as $field ) {
			if ( isset( $values[ $field ] ) ) {
				$values[ $field . '_json' ] = wp_json_encode( $values[ $field ] );
				unset( $values[ $field ] );
			}
		}
		$values['updated_at'] = gmdate( 'Y-m-d H:i:s' );
		// Cancellation is terminal even if a previously started worker finishes later.
		return false !== $wpdb->update(
			$wpdb->prefix . 'ssa_scans',
			$values,
			array(
				'id'     => $id,
				'status' => 'running',
			)
		);
	}
	public function running( int $id ): void {
		global $wpdb;
		$wpdb->update(
			$wpdb->prefix . 'ssa_scans',
			array( 'status' => 'running' ),
			array(
				'id'     => $id,
				'status' => 'queued',
			)
		);
	}
	public function fail_if_owner( int $id, string $token, string $diagnostic ) {
		global $wpdb;
		// Only for rejected storage engines: normal failure writes take the option lock first.
		$now = gmdate( 'Y-m-d H:i:s' );
		return $wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->prefix}ssa_scans SET status='failed', diagnostic=%s, completed_at=%s, updated_at=%s WHERE id=%d AND status IN ('queued','running') AND EXISTS (SELECT 1 FROM {$wpdb->options} WHERE option_name=%s AND option_value=%s FOR UPDATE)", $diagnostic, $now, $now, $id, 'ssa_worker_' . $id, $token ) );
	}
	public function cancel( int $id ): void {
		global $wpdb;
		$wpdb->query( $wpdb->prepare( "UPDATE {$wpdb->prefix}ssa_scans SET status='cancelled', completed_at=%s WHERE id=%d AND status IN ('queued','running')", gmdate( 'Y-m-d H:i:s' ), $id ) );
		wp_clear_scheduled_hook( 'ssa_batch', array( $id ) );
	}
	private function decode( array $row ): array {
		$row['id']       = (int) $row['id'];
		$row['checks']   = (array) json_decode( $row['checks_json'], true );
		$row['progress'] = (array) json_decode( $row['progress_json'], true );
		$row['coverage'] = (float) $row['coverage'];
		$row['assessed'] = (int) $row['assessed'];
		$row['score']    = null === $row['score'] ? null : (int) $row['score'];
		$valid           = count( $row['checks'] ) <= 16;
		foreach ( $row['checks'] as $id => $check ) {
			if ( ! is_array( $check ) || ! preg_match( '/^SSA-(?:00[1-9]|01[0-6])$/D', (string) $id ) || ( $check['check_id'] ?? null ) !== $id || ! in_array( $check['status'] ?? '', array( 'pass', 'fail', 'unknown', 'not_applicable' ), true ) ) {
				$valid = false;
				break;
			}
		}
		if ( in_array( $row['status'], array( 'completed', 'partial' ), true ) && 16 !== count( $row['checks'] ) ) {
			$valid = false;
		}
		if ( ! $valid ) {
			$row['status']     = 'failed';
			$row['diagnostic'] = 'stored_result_invalid';
			$row['checks']     = array();
			$row['score']      = null;
			$row['coverage']   = 0.0;
			$row['assessed']   = 0;
		}
		unset( $row['checks_json'], $row['progress_json'], $row['started_by'] );
		return $row;
	}
}
