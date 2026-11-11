<?php
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Private custom tables and atomic locks require direct, fresh, parameterised queries.
namespace SiteSecurityAuditor\Services;

final class RetentionService {
	public static function prune(): void {
		global $wpdb;
		$cutoff = gmdate( 'Y-m-d H:i:s', time() - 90 * DAY_IN_SECONDS );
		$ids    = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM {$wpdb->prefix}ssa_scans WHERE status NOT IN ('queued','running') AND started_at < %s LIMIT 1000", $cutoff ) );
		$older  = $wpdb->get_col( $wpdb->prepare( "SELECT id FROM {$wpdb->prefix}ssa_scans WHERE status NOT IN ('queued','running') AND started_at >= %s ORDER BY started_at DESC, id DESC LIMIT 1000 OFFSET 20", $cutoff ) );
		$remove = array_values( array_unique( array_map( 'intval', array_merge( $ids, $older ) ) ) );
		if ( $remove ) {
			$placeholders = implode( ',', array_fill( 0, count( $remove ), '%d' ) );
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare -- Tables are fixed plugin-owned names; only generated %d placeholders are interpolated and every ID is prepared.
			$wpdb->query( $wpdb->prepare( "DELETE scans, findings FROM {$wpdb->prefix}ssa_scans scans LEFT JOIN {$wpdb->prefix}ssa_findings findings ON findings.scan_id = scans.id WHERE scans.id IN ($placeholders)", ...$remove ) );
		}
		if ( count( $ids ) >= 1000 || count( $older ) >= 1000 ) {
			$next = wp_next_scheduled( 'ssa_retention' );
			if ( ! $next || $next > time() + 600 ) {
				wp_schedule_single_event( time() + 60, 'ssa_retention' );
			}
		}
	}
}
