<?php
namespace SiteSecurityAuditor\Tests\Integration;

use SiteSecurityAuditor\Api\Routes;
use WP_Error;
use WP_REST_Request;
use WP_UnitTestCase;

final class RouteAccessTest extends WP_UnitTestCase {
	public function test_anonymous_and_subscriber_users_are_forbidden(): void {
		$routes  = new Routes();
		$request = new WP_REST_Request( 'GET' );

		wp_set_current_user( 0 );
		$this->assertWPError( $routes->permission( $request ) );

		$user_id = self::factory()->user->create( array( 'role' => 'subscriber' ) );
		wp_set_current_user( $user_id );
		$this->assertWPError( $routes->permission( $request ) );
	}

	public function test_admin_can_read_but_post_requires_a_valid_rest_nonce(): void {
		wp_set_current_user( self::factory()->user->create( array( 'role' => 'administrator' ) ) );
		$routes = new Routes();
		$this->assertTrue( $routes->permission( new WP_REST_Request( 'GET' ) ) );

		$post = new WP_REST_Request( 'POST' );
		$this->assertWPError( $routes->permission( $post ) );
		$post->add_header( 'X-WP-Nonce', wp_create_nonce( 'wp_rest' ) );
		$this->assertTrue( $routes->permission( $post ) );
	}
}
