<?php
namespace SiteSecurityAuditor\Persistence;

final class Schema {
	public const VERSION = '1';
	public static function has_innodb_engine( string $table ): ?bool {
		global $wpdb;
		// WordPress's SQLite drop-in can report InnoDB through its MySQL compatibility layer.
		if ( is_a( $wpdb, 'WP_SQLite_DB' ) ) {
			return false;
		}
		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery,WordPress.DB.DirectDatabaseQuery.NoCaching -- Check the actual table engine before relying on transactions.
		$status = $wpdb->get_row( $wpdb->prepare( 'SHOW TABLE STATUS LIKE %s', $wpdb->esc_like( $table ) ), ARRAY_A );
		return $wpdb->last_error ? null : 'innodb' === strtolower( $status['Engine'] ?? '' );
	}
	public static function install(): void {
		global $wpdb;
		require_once ABSPATH . 'wp-admin/includes/upgrade.php';
		$charset = $wpdb->get_charset_collate();
		dbDelta(
			"CREATE TABLE {$wpdb->prefix}ssa_scans (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		started_by bigint(20) unsigned DEFAULT NULL,
		status varchar(20) NOT NULL,
		score_version varchar(32) NOT NULL DEFAULT '1',
		checks_json longtext NOT NULL,
		progress_json longtext NOT NULL,
		score smallint(6) DEFAULT NULL,
		assessed smallint(6) NOT NULL DEFAULT 0,
		coverage decimal(5,2) NOT NULL DEFAULT 0,
		diagnostic varchar(64) NOT NULL DEFAULT '',
		started_at datetime NOT NULL,
		updated_at datetime NOT NULL,
		completed_at datetime DEFAULT NULL,
		PRIMARY KEY  (id),
		KEY status (status),
		KEY started_at (started_at)
		) ENGINE=InnoDB $charset;"
		);
		dbDelta(
			"CREATE TABLE {$wpdb->prefix}ssa_findings (
		id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
		scan_id bigint(20) unsigned NOT NULL,
		identity_hash char(64) NOT NULL,
		check_id varchar(16) NOT NULL,
		status varchar(20) NOT NULL,
		severity varchar(20) NOT NULL,
		kind varchar(40) NOT NULL,
		component_key varchar(255) NOT NULL,
		payload_json longtext NOT NULL,
		created_at datetime NOT NULL,
		PRIMARY KEY  (id),
		UNIQUE KEY scan_identity (scan_id,identity_hash),
		KEY scan_id (scan_id),
		KEY identity_hash (identity_hash),
		KEY severity (severity)
		) ENGINE=InnoDB $charset;"
		);
		foreach ( array( $wpdb->prefix . 'ssa_scans', $wpdb->prefix . 'ssa_findings' ) as $table ) {
			if ( true !== self::has_innodb_engine( $table ) ) {
				return;
			}
		}
		update_option( 'ssa_schema_version', self::VERSION, false );
	}
}
