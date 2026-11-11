<?php
namespace SiteSecurityAuditor\Services;

use SiteSecurityAuditor\Audit\AuditRegistry;
use SiteSecurityAuditor\Persistence\ScanRepository;
use SiteSecurityAuditor\Persistence\FindingRepository;
use SiteSecurityAuditor\Support\Lock;
use SiteSecurityAuditor\Support\SafeOutput;

final class ScanRunner {
	public static function start( int $user ) {
		global $wpdb;
		$token = Lock::acquire( 'ssa_start_lock' );
		if ( ! $token ) {
			return new \WP_Error( 'ssa_busy', __( 'Another scan is starting.', 'site-security-auditor' ), array( 'status' => 409 ) );
		}
		try {
			$repo = new ScanRepository();
			try {
				$tables = array( $wpdb->prefix . 'ssa_scans', $wpdb->prefix . 'ssa_findings' );
				Lock::require_transactional_storage( $tables );
			} catch ( \RuntimeException $error ) {
				return new \WP_Error( 'ssa_storage_engine', __( 'Safe scan writes require available InnoDB options and audit tables.', 'site-security-auditor' ), array( 'status' => 500 ) );
			}
			$active = false;
			$id     = 0;
			try {
				$owned = Lock::with_owner(
					'ssa_start_lock',
					$token,
					$tables,
					static function () use ( $repo, $user, &$active, &$id ) {
						$active = (bool) $repo->active();
						if ( ! $active ) {
							$id = $repo->create( $user );
						}
					}
				);
			} catch ( \RuntimeException $error ) {
				return new \WP_Error( 'ssa_storage', __( 'Could not save the scan.', 'site-security-auditor' ), array( 'status' => 500 ) );
			}
			if ( ! $owned ) {
				return new \WP_Error( 'ssa_busy', __( 'Another scan is starting.', 'site-security-auditor' ), array( 'status' => 409 ) );
			}
			if ( $active ) {
				return new \WP_Error( 'ssa_busy', __( 'A scan is already active.', 'site-security-auditor' ), array( 'status' => 409 ) );
			}
			if ( ! $id ) {
				return new \WP_Error( 'ssa_storage', __( 'Could not save the scan.', 'site-security-auditor' ), array( 'status' => 500 ) );
			}
			wp_schedule_single_event( time() + 5, 'ssa_batch', array( $id ) );
			return $repo->get( $id );
		} finally {
			Lock::release( 'ssa_start_lock', $token );
		}
	}
	public static function advance( int $id ): array|\WP_Error|null {
		global $wpdb;
		$repo   = new ScanRepository();
		$name   = 'ssa_worker_' . $id;
		$token  = Lock::acquire( $name );
		$tables = array( $wpdb->prefix . 'ssa_scans', $wpdb->prefix . 'ssa_findings' );
		if ( ! $token ) {
			return $repo->get( $id );
		}
		try {
			$scan = $repo->get( $id );
			if ( ! $scan || ! in_array( $scan['status'], array( 'queued', 'running' ), true ) ) {
				return $scan;
			}
			Lock::require_transactional_storage( $tables );
			$repo->running( $id );
			$ids      = array( 'SSA-001', 'SSA-002', 'SSA-003', 'SSA-007', 'SSA-008', 'SSA-009', 'SSA-010', 'SSA-011', 'SSA-013', 'SSA-014', 'SSA-015', 'SSA-016', 'SSA-004', 'SSA-005', 'SSA-006', 'SSA-012' );
			$index    = (int) ( $scan['progress']['index'] ?? 0 );
			$checks   = $scan['checks'];
			$progress = $scan['progress'];
			$findings = new FindingRepository();
			$result   = null;
			if ( isset( $ids[ $index ] ) ) {
				$result = AuditRegistry::run(
					$ids[ $index ],
					array(
						'cursor'         => $progress['cursor'] ?? null,
						'request_budget' => 5,
						'hash_budget'    => 250,
					)
				);
				if ( count( $result['findings'] ?? array() ) > 500 ) {
					throw new \RuntimeException( 'batch_finding_limit' );
				}
			}
			$persisted = Lock::with_owner(
				$name,
				$token,
				$tables,
				static function () use ( $repo, $id, $result, $findings, $ids, $index, $checks, $progress ) {
					$current = $repo->get( $id );
					if ( ! $current || 'running' !== $current['status'] ) {
						return;
					}
					if ( null !== $result ) {
						// Deterministic identities make retries replace rows without consuming capacity twice.
						$findings->store_batch( $id, $result['findings'] ?? array() );
						unset( $result['findings'] );
						$cursor = $result['cursor'] ?? null;
						unset( $result['cursor'] );
						$result['reason']         = SafeOutput::text( $result['reason'] ?? '' );
						$checks[ $ids[ $index ] ] = $result;
						$progress                 = array(
							'index'  => $cursor ? $index : $index + 1,
							'cursor' => $cursor,
							'stage'  => $index < 3 ? 'inventory' : ( $index < 12 ? 'local_checks' : ( $index < 15 ? 'vulnerability_lookup' : 'checksum_lookup' ) ),
						);
					}
					$values = array(
						'checks'   => $checks,
						'progress' => $progress,
					);
					if ( $progress['index'] >= count( $ids ) ) {
						$score = ScoreCalculator::calculate( $checks, $findings->all( $id ) );
						unset( $score['eligible'] );
						$unknown = count( array_filter( $checks, static fn( $check ) => 'unknown' === $check['status'] || ! empty( $check['has_unknown'] ) ) );
						$values += $score + array(
							'status'       => $unknown ? 'partial' : 'completed',
							'completed_at' => gmdate( 'Y-m-d H:i:s' ),
						);
					}
					if ( ! $repo->save( $id, $values ) ) {
						throw new \RuntimeException( 'storage_failed' );
					}
				}
			);
			$scan      = $repo->get( $id );
			if ( ! $persisted ) {
				return $scan;
			}
			if ( $scan && in_array( $scan['status'], array( 'completed', 'partial' ), true ) ) {
				RetentionService::prune();
			}
			if ( $scan && 'running' === $scan['status'] && ! wp_next_scheduled( 'ssa_batch', array( $id ) ) ) {
				wp_schedule_single_event( time() + 10, 'ssa_batch', array( $id ) );
			}
			return $scan;
		} catch ( \Throwable $error ) {
			$diagnostic = in_array( $error->getMessage(), array( 'batch_finding_limit', 'finding_limit', 'storage_failed', 'transactional_storage_required' ), true ) ? $error->getMessage() : 'batch_failed';
			if ( 'transactional_storage_required' === $diagnostic ) {
				if ( false === $repo->fail_if_owner( $id, $token, $diagnostic ) ) {
					return new \WP_Error( 'ssa_storage', __( 'The scan could not be saved. Try again after checking database availability.', 'site-security-auditor' ), array( 'status' => 500 ) );
				}
				return new \WP_Error( 'ssa_storage_engine', __( 'Safe scan writes require InnoDB for WordPress options and audit tables.', 'site-security-auditor' ), array( 'status' => 500 ) );
			}
			try {
				Lock::with_owner(
					$name,
					$token,
					$tables,
					static function () use ( $repo, $id, $diagnostic ) {
						if ( ! $repo->save(
							$id,
							array(
								'status'       => 'failed',
								'diagnostic'   => $diagnostic,
								'completed_at' => gmdate( 'Y-m-d H:i:s' ),
							)
						) ) {
							throw new \RuntimeException( 'storage_failed' );
						}
					}
				);
			} catch ( \Throwable $failure ) {
				return new \WP_Error( 'ssa_storage', __( 'The scan could not be saved. Try again after checking database availability.', 'site-security-auditor' ), array( 'status' => 500 ) );
			}
			return $repo->get( $id );
		} finally {
			Lock::release( $name, $token );
		}
	}
}
