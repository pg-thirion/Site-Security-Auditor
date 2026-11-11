<?php
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Explicit WordPress uninstall removes only plugin-owned tables and options.
/** Remove only plugin-owned data when WordPress explicitly uninstalls this plugin. */
defined( 'WP_UNINSTALL_PLUGIN' ) || exit;
global $wpdb;
wp_unschedule_hook( 'ssa_batch' );
wp_clear_scheduled_hook( 'ssa_weekly' );
wp_clear_scheduled_hook( 'ssa_retention' );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}ssa_findings" );
$wpdb->query( "DROP TABLE IF EXISTS {$wpdb->prefix}ssa_scans" );
delete_option( 'ssa_settings' );
delete_option( 'ssa_schema_version' );
delete_option( 'ssa_start_lock' );
$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s", $wpdb->esc_like( 'ssa_worker_' ) . '%', $wpdb->esc_like( '_transient_ssa_' ) . '%', $wpdb->esc_like( '_transient_timeout_ssa_' ) . '%' ) );
