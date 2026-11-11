<?php
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Private custom tables and atomic locks require direct, fresh, parameterised queries.
namespace SiteSecurityAuditor\Persistence;

use SiteSecurityAuditor\Support\SafeOutput;

final class FindingRepository {
	public function count( int $scan_id ): int {
		global $wpdb;
		$count = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}ssa_findings WHERE scan_id=%d", $scan_id ) );
		if ( $wpdb->last_error ) {
			throw new \RuntimeException( 'storage_failed' );
		}
		return (int) $count;
	}
	public static function identity( array $finding ): string {
		return hash( 'sha256', implode( '|', array( $finding['check_id'], $finding['component_type'] ?? '', $finding['component_key'] ?? '', $finding['advisory_id'] ?? '' ) ) );
	}
	public function store( int $scan_id, array $finding ): void {
		global $wpdb;
		$finding                  = SafeOutput::finding( $finding );
		$finding['scan_id']       = $scan_id;
		$finding['identity_hash'] = self::identity( $finding );
		$finding['id']            = hash( 'sha256', $scan_id . ':' . $finding['identity_hash'] );
		$ok                       = $wpdb->replace(
			$wpdb->prefix . 'ssa_findings',
			array(
				'scan_id'       => $scan_id,
				'identity_hash' => $finding['identity_hash'],
				'check_id'      => $finding['check_id'],
				'status'        => $finding['status'],
				'severity'      => $finding['severity'],
				'kind'          => $finding['kind'],
				'component_key' => $finding['component_key'],
				'payload_json'  => wp_json_encode( $finding ),
				'created_at'    => gmdate( 'Y-m-d H:i:s' ),
			)
		);
		if ( false === $ok ) {
			throw new \RuntimeException( 'storage_failed' );
		}
	}
	public function store_batch( int $scan_id, array $findings ): void {
		global $wpdb;
		$identities = array();
		foreach ( $findings as $finding ) {
			$identities[ self::identity( SafeOutput::finding( $finding ) ) ] = true;
		}
		$existing = $wpdb->get_col( $wpdb->prepare( "SELECT identity_hash FROM {$wpdb->prefix}ssa_findings WHERE scan_id=%d", $scan_id ) );
		if ( null === $existing || $wpdb->last_error ) {
			throw new \RuntimeException( 'storage_failed' );
		}
		if ( count( $existing ) + count( array_diff_key( $identities, array_fill_keys( $existing, true ) ) ) > 5000 ) {
			throw new \RuntimeException( 'finding_limit' );
		}
		foreach ( $findings as $finding ) {
			$this->store( $scan_id, $finding );
		}
	}
	public function all( int $scan_id ): array {
		global $wpdb;
		$rows = $wpdb->get_col( $wpdb->prepare( "SELECT payload_json FROM {$wpdb->prefix}ssa_findings WHERE scan_id=%d ORDER BY FIELD(severity,'critical','high','medium','low','unrated','info'), id DESC", $scan_id ) );
		if ( $wpdb->last_error ) {
			throw new \RuntimeException( 'storage_failed' );
		}
		return array_map( static fn( $json ) => json_decode( $json, true ), $rows );
	}
	public function listing( int $scan_id, int $page, int $limit, array $filters = array(), string $search = '' ): array {
		global $wpdb;
		$where = 'scan_id=%d';
		$args  = array( $scan_id );
		foreach ( array( 'severity', 'status', 'kind' ) as $field ) {
			if ( isset( $filters[ $field ] ) ) {
				$where .= " AND {$field}=%s";
				$args[] = $filters[ $field ];
			}
		}
		$order  = " ORDER BY FIELD(severity,'critical','high','medium','low','unrated','info'), id DESC";
		$offset = ( $page - 1 ) * $limit;
		if ( '' !== $search ) {
			// shortcut: search JSON in PHP within the 5,000-finding cap; add search columns if larger scans are supported.
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders -- Clauses contain only fixed SQL and placeholders; all values are prepared.
			$rows = $wpdb->get_col( $wpdb->prepare( "SELECT payload_json FROM {$wpdb->prefix}ssa_findings WHERE {$where}{$order} LIMIT 5000", $args ) );
			if ( $wpdb->last_error ) {
				throw new \RuntimeException( 'storage_failed' );
			}
			$items = array_filter( array_map( static fn( $json ) => json_decode( $json, true ), $rows ), static fn( $item ) => false !== stripos( $item['title'] . ' ' . $item['component_name'], $search ) );
			return array(
				'items' => array_slice( array_values( $items ), $offset, $limit ),
				'total' => count( $items ),
			);
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders -- Clauses contain only fixed SQL and placeholders; all values are prepared.
		$total = (int) $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM {$wpdb->prefix}ssa_findings WHERE {$where}", $args ) );
		if ( $wpdb->last_error ) {
			throw new \RuntimeException( 'storage_failed' );
		}
		// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared,WordPress.DB.PreparedSQLPlaceholders -- Clauses contain only fixed SQL and placeholders; all values are prepared.
		$rows = $wpdb->get_col( $wpdb->prepare( "SELECT payload_json FROM {$wpdb->prefix}ssa_findings WHERE {$where}{$order} LIMIT %d OFFSET %d", array_merge( $args, array( $limit, $offset ) ) ) );
		if ( $wpdb->last_error ) {
			throw new \RuntimeException( 'storage_failed' );
		}
		return array(
			'items' => array_map( static fn( $json ) => json_decode( $json, true ), $rows ),
			'total' => $total,
		);
	}
}
