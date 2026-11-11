<?php
/**
 * Plugin Name: Site Security Auditor
 * Description: Read-only, local-first WordPress security posture audits with explicit external-service consent.
 * Version: 0.1.0
 * Requires at least: 6.6
 * Requires PHP: 8.2
 * License: GPL-2.0-or-later
 * Text Domain: site-security-auditor
 */

defined( 'ABSPATH' ) || exit;
define( 'SSA_VERSION', '0.1.0' );
define( 'SSA_FILE', __FILE__ );
spl_autoload_register(
	static function ( $class_name ) {
		$prefix = 'SiteSecurityAuditor\\';
		if ( ! str_starts_with( $class_name, $prefix ) ) {
			return;
		}
		$relative = substr( $class_name, strlen( $prefix ) );
		if ( ! preg_match( '/^[A-Za-z0-9_\\\\]+$/D', $relative ) ) {
			return;
		}
		$file = __DIR__ . '/includes/' . str_replace( '\\', '/', $relative ) . '.php';
		if ( is_file( $file ) ) {
			require_once $file;
		}
	}
);
register_activation_hook( __FILE__, array( SiteSecurityAuditor\Plugin::class, 'activate' ) );
register_deactivation_hook( __FILE__, array( SiteSecurityAuditor\Plugin::class, 'deactivate' ) );
add_action( 'plugins_loaded', array( SiteSecurityAuditor\Plugin::class, 'boot' ) );
