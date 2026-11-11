<?php
namespace SiteSecurityAuditor;

use SiteSecurityAuditor\Persistence\Schema;
use SiteSecurityAuditor\Services\ScanRunner;

final class Plugin {
	public static function activate( bool $network_wide = false ): void {
		if ( $network_wide || is_multisite() ) {
			wp_die( esc_html__( 'Site Security Auditor currently supports single-site WordPress only.', 'site-security-auditor' ) );
		}
		Schema::install();
		add_option(
			'ssa_settings',
			array(
				'vulnerability_intelligence' => false,
				'core_integrity'             => false,
				'weekly_schedule'            => false,
			),
			'',
			false
		);
		$settings = get_option( 'ssa_settings', array() );
		if ( ! empty( $settings['weekly_schedule'] ) && ! wp_next_scheduled( 'ssa_weekly' ) ) {
			wp_schedule_event( time() + WEEK_IN_SECONDS, 'weekly', 'ssa_weekly' );
		}
		if ( ! wp_next_scheduled( 'ssa_retention' ) ) {
			wp_schedule_event( time() + DAY_IN_SECONDS, 'daily', 'ssa_retention' );
		}
	}
	public static function deactivate(): void {
		wp_unschedule_hook( 'ssa_batch' );
		wp_clear_scheduled_hook( 'ssa_weekly' );
		wp_clear_scheduled_hook( 'ssa_retention' );
	}
	public static function boot(): void {
		if ( is_multisite() ) {
			add_action(
				'network_admin_notices',
				static function () {
					echo '<div class="notice notice-warning"><p>' . esc_html__( 'Site Security Auditor does not support multisite audits.', 'site-security-auditor' ) . '</p></div>';
				}
			);
			return;
		}
		if ( get_option( 'ssa_schema_version' ) !== Schema::VERSION ) {
			Schema::install();
		}
		( new Admin\AdminPage() )->register();
		add_action( 'rest_api_init', array( new Api\Routes(), 'register' ) );
		add_action( 'ssa_batch', array( ScanRunner::class, 'advance' ) );
		add_action( 'ssa_retention', array( Services\RetentionService::class, 'prune' ) );
		add_action(
			'ssa_weekly',
			static function () {
				$settings = get_option( 'ssa_settings', array() );
				if ( ! empty( $settings['weekly_schedule'] ) ) {
					ScanRunner::start( 0 );
				}
			}
		);
	}
}
