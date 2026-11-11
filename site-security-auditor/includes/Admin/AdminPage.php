<?php
namespace SiteSecurityAuditor\Admin;

final class AdminPage {
	private string $hook = '';
	public function register(): void {
		add_action( 'admin_menu', array( $this, 'menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue' ) );
	}
	public function menu(): void {
		$this->hook = add_menu_page( __( 'Security Audit', 'site-security-auditor' ), __( 'Security Audit', 'site-security-auditor' ), 'manage_options', 'site-security-auditor', array( $this, 'render' ), 'dashicons-shield' );
	}
	public function render(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You cannot access security audits.', 'site-security-auditor' ), '', array( 'response' => 403 ) );
		}
		echo '<div class="wrap"><div id="ssa-root"></div></div>';
	}
	public function enqueue( string $hook ): void {
		if ( $hook !== $this->hook || ! current_user_can( 'manage_options' ) ) {
			return;
		}
		$build = dirname( SSA_FILE ) . '/build/';
		if ( ! is_file( $build . 'index.asset.php' ) ) {
			return;
		}
		$asset = require $build . 'index.asset.php';
		wp_enqueue_script( 'ssa-admin', plugins_url( 'build/index.js', SSA_FILE ), $asset['dependencies'], $asset['version'], true );
		wp_enqueue_style( 'ssa-admin', plugins_url( 'build/style-index.css', SSA_FILE ), array( 'wp-components' ), $asset['version'] );
		wp_add_inline_script(
			'ssa-admin',
			'window.ssaSettings = ' . wp_json_encode(
				array(
					'nonce'    => wp_create_nonce( 'wp_rest' ),
					'root'     => esc_url_raw( rest_url() ),
					'siteName' => get_bloginfo( 'name' ),
					'hostname' => wp_parse_url( home_url(), PHP_URL_HOST ),
				)
			) . ';',
			'before'
		);
		wp_set_script_translations( 'ssa-admin', 'site-security-auditor' );
	}
}
