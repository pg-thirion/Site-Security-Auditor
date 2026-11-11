<?php
namespace SiteSecurityAuditor\Tests\Integration;

use SiteSecurityAuditor\Support\SafeOutput;
use WP_UnitTestCase;

final class SafeOutputTest extends WP_UnitTestCase {
	public function test_untrusted_finding_text_and_references_are_scrubbed(): void {
		$result = SafeOutput::finding(
			array(
				'check_id'       => 'SSA-001',
				'component_type' => 'plugin',
				'component_key'  => 'example/example.php',
				'title'          => '<script>alert(1)</script> exposed',
				'summary'        => 'Found /etc/passwd and C:\\Users\\operator\\private.txt',
				'status'         => 'fail',
				'severity'       => 'high',
				'kind'           => 'configuration_risk',
				'remediation'    => array( '<img src=x onerror=alert(1)> Review settings' ),
				'references'     => array(
					'javascript:alert(1)',
					'https://user:secret@wordpress.org/support/article/',
					'https://wordpress.org:8443/support/article/',
					'https://wordpress.org/support/article/hardening-wordpress/',
				),
			)
		);

		$this->assertStringNotContainsString( '<script>', $result['title'] );
		$this->assertStringNotContainsString( '/etc/passwd', $result['summary'] );
		$this->assertStringNotContainsString( 'operator', $result['summary'] );
		$this->assertStringNotContainsString( '<img', $result['remediation'][0] );
		$this->assertSame( array( 'https://wordpress.org/support/article/hardening-wordpress/' ), $result['references'] );
	}
}
