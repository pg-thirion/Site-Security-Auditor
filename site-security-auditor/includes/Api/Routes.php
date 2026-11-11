<?php
namespace SiteSecurityAuditor\Api;

use SiteSecurityAuditor\Persistence\ScanRepository;
use SiteSecurityAuditor\Persistence\FindingRepository;
use SiteSecurityAuditor\Services\ScanRunner;
use SiteSecurityAuditor\Services\ExportService;
use SiteSecurityAuditor\Services\ScanDiff;
use SiteSecurityAuditor\Support\Lock;

final class Routes {
	public const NS = 'site-security-auditor/v1';
	public function register(): void {
		foreach ( array(
			'/overview'                           => 'GET',
			'/scans'                              => 'GET,POST',
			'/scans/(?P<id>[1-9][0-9]*)'          => 'GET',
			'/scans/(?P<id>[1-9][0-9]*)/findings' => 'GET',
			'/scans/(?P<id>[1-9][0-9]*)/advance'  => 'POST',
			'/scans/(?P<id>[1-9][0-9]*)/cancel'   => 'POST',
			'/scans/(?P<id>[1-9][0-9]*)/export'   => 'GET',
			'/settings'                           => 'GET,POST',
		) as $path => $methods ) {
			register_rest_route(
				self::NS,
				$path,
				array(
					'methods'             => $methods,
					'permission_callback' => array( $this, 'permission' ),
					'callback'            => array( $this, 'dispatch' ),
				)
			);
		}
		add_filter( 'rest_pre_serve_request', array( $this, 'serve_export' ), 10, 4 );
	}
	public function permission( \WP_REST_Request $request ) {
		if ( ! current_user_can( 'manage_options' ) ) {
			return new \WP_Error( 'ssa_forbidden', __( 'Administrator access required.', 'site-security-auditor' ), array( 'status' => 403 ) );
		}
		if ( 'POST' === $request->get_method() && ! wp_verify_nonce( $request->get_header( 'X-WP-Nonce' ), 'wp_rest' ) ) {
			return new \WP_Error( 'ssa_nonce', __( 'Reload this page to renew your session.', 'site-security-auditor' ), array( 'status' => 403 ) );
		}
		return true;
	}
	private function error( string $code, int $status = 400 ): \WP_Error {
		return new \WP_Error( 'ssa_' . $code, __( 'The audit request could not be processed.', 'site-security-auditor' ), array( 'status' => $status ) );
	}
	public function dispatch( \WP_REST_Request $request ) {
		try {
			$data = $this->handle( $request );
			if ( is_wp_error( $data ) ) {
				return $data;
			}
			if ( is_array( $data ) ) {
				$data = $this->public_data( $data );
			}
			$response = rest_ensure_response( $data );
			$response->header( 'Cache-Control', 'no-store, private, max-age=0' );
			$response->header( 'X-Robots-Tag', 'noindex, nofollow' );
			$response->header( 'X-Content-Type-Options', 'nosniff' );
			return $response;
		} catch ( \Throwable $error ) {
			return $this->error( 'internal', 500 );
		}
	}
	private function public_data( array $data ): array {
		if ( isset( $data['progress'] ) ) {
			unset( $data['progress']['cursor'] );
		}
		foreach ( $data as $key => $value ) {
			if ( is_array( $value ) ) {
				$data[ $key ] = $this->public_data( $value );
			}
		}
		return $data;
	}
	private function handle( \WP_REST_Request $request ) {
		$repo     = new ScanRepository();
		$findings = new FindingRepository();
		$path     = $request->get_route();
		$post     = 'POST' === $request->get_method();
		if ( str_ends_with( $path, '/settings' ) ) {
			$settings = get_option(
				'ssa_settings',
				array(
					'vulnerability_intelligence' => false,
					'core_integrity'             => false,
					'weekly_schedule'            => false,
				)
			);
			if ( $post ) {
				$input = $request->get_json_params();
				if ( ! is_array( $input ) || array_diff( array_keys( $input ), array_keys( $settings ) ) ) {
					return $this->error( 'settings' );
				}
				foreach ( $input as $key => $value ) {
					if ( ! is_bool( $value ) ) {
						return $this->error( 'settings' );
					}
					$settings[ $key ] = $value;
				}
				update_option( 'ssa_settings', $settings, false );
				if ( get_option( 'ssa_settings' ) !== $settings ) {
					return $this->error( 'settings_save', 500 );
				}
				wp_clear_scheduled_hook( 'ssa_weekly' );
				if ( $settings['weekly_schedule'] ) {
					wp_schedule_event( time() + WEEK_IN_SECONDS, 'weekly', 'ssa_weekly' );
				}
			}
			return $settings;
		}
		if ( str_ends_with( $path, '/overview' ) ) {
			$latest = $repo->latest();
			return array(
				'latest' => $latest,
			);
		}
		if ( preg_match( '~/scans$~', $path ) ) {
			if ( $post ) {
				return ScanRunner::start( get_current_user_id() );
			}
			$page  = $request->get_param( 'page' ) ?? 1;
			$limit = $request->get_param( 'per_page' ) ?? 20;
			if ( ! $this->positive( $page, 1000 ) || ! $this->positive( $limit, 100 ) ) {
				return $this->error( 'pagination' );
			}
			return $repo->listing( (int) $page, (int) $limit );
		}
		$id = $request->get_param( 'id' );
		if ( ! $this->positive( $id, PHP_INT_MAX ) ) {
			return $this->error( 'id' );
		}
		$scan = $repo->get( (int) $id );
		if ( ! $scan ) {
			return $this->error( 'missing', 404 );
		}
		if ( str_ends_with( $path, '/advance' ) ) {
			return ScanRunner::advance( (int) $id );
		}
		if ( str_ends_with( $path, '/cancel' ) ) {
			$token = Lock::acquire( 'ssa_worker_' . (int) $id );
			if ( ! $token ) {
				return new \WP_Error( 'ssa_batch_active', __( 'A batch is finishing. Try cancelling again shortly.', 'site-security-auditor' ), array( 'status' => 409 ) );
			}
			try {
				$repo->cancel( (int) $id );
			} finally {
				Lock::release( 'ssa_worker_' . (int) $id, $token );
			}
			return $repo->get( (int) $id );
		}
		if ( str_ends_with( $path, '/export' ) ) {
			$items  = $findings->all( (int) $id );
			$format = $request->get_param( 'format' ) ?? 'json';
			if ( ! in_array( $format, array( 'json', 'csv' ), true ) ) {
				return $this->error( 'format' );
			}
			unset( $scan['progress'] );
			$body = 'csv' === $format ? ExportService::csv( $scan, $items ) : wp_json_encode(
				array(
					'schema_version' => 1,
					'scan'           => $scan,
					'findings'       => $items,
				),
				JSON_PRETTY_PRINT
			);
			return new \WP_REST_Response(
				$body,
				200,
				array(
					'Content-Type'        => 'csv' === $format ? 'text/csv; charset=utf-8' : 'application/json; charset=utf-8',
					'Content-Disposition' => 'attachment; filename="site-security-audit-' . (int) $id . '.' . $format . '"',
				)
			);
		}
		if ( str_ends_with( $path, '/findings' ) ) {
			$filters = array();
			foreach ( array(
				'severity' => array( 'critical', 'high', 'medium', 'low', 'unrated', 'info' ),
				'status'   => array( 'pass', 'fail', 'unknown', 'not_applicable' ),
				'category' => array( 'confirmed_vulnerability', 'configuration_risk', 'hardening', 'integrity_difference', 'informational', 'unverified' ),
			) as $field => $allowed ) {
				$value = $request->get_param( $field );
				if ( null !== $value && '' !== $value ) {
					if ( ! in_array( $value, $allowed, true ) ) {
						return $this->error( 'filter' );
					}
					$filters[ 'category' === $field ? 'kind' : $field ] = $value;
				}
			}
			$search = $request->get_param( 'search' ) ?? '';
			if ( ! is_string( $search ) || strlen( $search ) > 200 ) {
				return $this->error( 'search' );
			}
			$page  = $request->get_param( 'page' ) ?? 1;
			$limit = $request->get_param( 'per_page' ) ?? 50;
			if ( ! $this->positive( $page, 1000 ) || ! $this->positive( $limit, 100 ) ) {
				return $this->error( 'pagination' );
			}
			return $findings->listing( (int) $id, (int) $page, (int) $limit, $filters, $search );
		}
		$items              = $findings->all( (int) $id );
		$previous           = array_filter( $repo->listing( 1, 20 )['items'], static fn( $item ) => $item['id'] < (int) $id && in_array( $item['status'], array( 'completed', 'partial' ), true ) );
		$previous           = reset( $previous );
		$scan['comparison'] = $previous ? ScanDiff::compare( $findings->all( $previous['id'] ), $items, $scan['checks'] ) : null;
		return $scan;
	}
	private function positive( $value, int $max ): bool {
		return ( is_int( $value ) || is_string( $value ) ) && preg_match( '/^[1-9][0-9]*$/D', (string) $value ) && false !== filter_var(
			$value,
			FILTER_VALIDATE_INT,
			array(
				'options' => array(
					'min_range' => 1,
					'max_range' => $max,
				),
			)
		);
	}
	public function serve_export( bool $served, $response, $request ): bool {
		if ( str_starts_with( $request->get_route(), '/' . self::NS . '/' ) && str_ends_with( $request->get_route(), '/export' ) && 200 === $response->get_status() && is_string( $response->get_data() ) ) {
			echo $response->get_data(); // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- Generated CSV/JSON attachment; HTML escaping corrupts the report.
			return true;
		}
		return $served;
	}
}
