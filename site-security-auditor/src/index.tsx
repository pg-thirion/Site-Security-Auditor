import apiFetch from '@wordpress/api-fetch';
import { Button, Modal } from '@wordpress/components';
import { createRoot } from '@wordpress/element';
import { __, sprintf } from '@wordpress/i18n';
import { useCallback, useEffect, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import './style.css';
declare global {
	interface Window {
		ssaSettings: {
			nonce: string;
			root: string;
			siteName: string;
			hostname: string;
		};
	}
}
type Scan = {
	id: number;
	status: string;
	checks: Record<
		string,
		{
			check_id: string;
			status: string;
			reason?: string;
			has_unknown?: boolean;
		}
	>;
	score: number | null;
	coverage: number;
	started_at: string;
	completed_at: string | null;
	updated_at?: string;
	progress?: {
		index: number;
		stage: string;
	};
	comparison?:
		| {
				title: string;
				check_id: string;
				state: string;
		  }[]
		| null;
};
type Finding = {
	id?: string;
	identity_hash?: string;
	scan_id: number;
	check_id: string;
	component_type: string;
	component_key: string;
	component_name: string;
	component_version: string;
	status: string;
	severity: string;
	kind: string;
	title: string;
	summary: string;
	evidence: string;
	remediation: string[];
	references: string[];
	checked_at: string;
	source: string;
	source_updated_at: string | null;
};
type Settings = {
	vulnerability_intelligence: boolean;
	core_integrity: boolean;
	weekly_schedule: boolean;
};
type View = 'overview' | 'findings' | 'history' | 'report' | 'settings';
const severityOrder: Record< string, number > = {
	critical: 0,
	high: 1,
	medium: 2,
	low: 3,
	unrated: 4,
	info: 5,
};
const viewLabels: Record< View, string > = {
	overview: __( 'Overview', 'site-security-auditor' ),
	findings: __( 'Findings', 'site-security-auditor' ),
	history: __( 'History', 'site-security-auditor' ),
	settings: __( 'Settings', 'site-security-auditor' ),
	report: __( 'Report', 'site-security-auditor' ),
};
const severityLabels: Record< string, string > = {
	critical: __( 'Critical', 'site-security-auditor' ),
	high: __( 'High', 'site-security-auditor' ),
	medium: __( 'Medium', 'site-security-auditor' ),
	low: __( 'Low', 'site-security-auditor' ),
	info: __( 'Info', 'site-security-auditor' ),
	unrated: __( 'Unrated', 'site-security-auditor' ),
};
const kindLabels: Record< string, string > = {
	confirmed_vulnerability: __(
		'Known vulnerability',
		'site-security-auditor'
	),
	configuration_risk: __( 'Configuration risk', 'site-security-auditor' ),
	hardening: __( 'Hardening advice', 'site-security-auditor' ),
	integrity_difference: __( 'Integrity difference', 'site-security-auditor' ),
	informational: __( 'Informational', 'site-security-auditor' ),
	unverified: __( 'Unverified', 'site-security-auditor' ),
};
const api = < T, >(
	path: string,
	options?: {
		method?: string;
		data?: unknown;
	}
) =>
	apiFetch< T >( {
		path: `/site-security-auditor/v1${ path }`,
		...options,
	} );
const date = ( value?: string | null ) =>
	value
		? sprintf(
				/* translators: %1$s is a localised date and time. */
				__( '%1$s (local)', 'site-security-auditor' ),
				new Date(
					/[zZ]|[+-]\d\d:\d\d$/.test( value )
						? value
						: `${ value.replace( ' ', 'T' ) }Z`
				).toLocaleString()
			)
		: __( 'Not available', 'site-security-auditor' );
const statusLabel = ( status: string ) =>
	( {
		completed: __( 'Completed', 'site-security-auditor' ),
		partial: __( 'Partial audit', 'site-security-auditor' ),
		failed: __( 'Audit failed', 'site-security-auditor' ),
		running: __( 'Running', 'site-security-auditor' ),
		queued: __( 'Queued', 'site-security-auditor' ),
		cancelled: __( 'Cancelled', 'site-security-auditor' ),
		pass: __( 'Passed', 'site-security-auditor' ),
		fail: __( 'Action needed', 'site-security-auditor' ),
		unknown: __( 'Not verified', 'site-security-auditor' ),
		not_applicable: __( 'Not applicable', 'site-security-auditor' ),
	} )[ status ] || status;
function scoreLabel( scan: Scan ) {
	if ( ! [ 'completed', 'partial' ].includes( scan.status ) ) {
		return __( 'Not available', 'site-security-auditor' );
	}
	if ( scan.coverage < 70 ) {
		return __( 'Insufficient coverage', 'site-security-auditor' );
	}
	if ( scan.score === null ) {
		return __( 'Not evaluated', 'site-security-auditor' );
	}
	return `${ scan.score }/100`;
}
function coverageLabel( scan: Scan ) {
	return [ 'completed', 'partial' ].includes( scan.status )
		? `${ scan.coverage }%`
		: __( 'Not available', 'site-security-auditor' );
}
function errorMessage( error: unknown, fallback: string ) {
	if ( error && typeof error === 'object' ) {
		const response = error as {
			code?: unknown;
			message?: unknown;
		};
		if (
			response.code === 'rest_cookie_invalid_nonce' ||
			response.code === 'ssa_nonce'
		) {
			return __(
				'Your session has expired. Reload this page and try again.',
				'site-security-auditor'
			);
		}
		if ( typeof response.message === 'string' ) {
			return response.message;
		}
	}
	return error instanceof Error ? error.message : fallback;
}
function App() {
	const params = new URLSearchParams( window.location.search );
	const [ view, setView ] = useState< View >(
		( [ 'overview', 'findings', 'history', 'report', 'settings' ].includes(
			params.get( 'view' ) || ''
		)
			? params.get( 'view' )
			: 'overview' ) as View
	);
	const [ overview, setOverview ] = useState< {
		latest: Scan | null;
	} | null >( null );
	const [ reportScan, setReportScan ] = useState< Scan | null >( null );
	const [ scans, setScans ] = useState< Scan[] >( [] );
	const [ historyLoaded, setHistoryLoaded ] = useState( false );
	const [ historyLoadFailed, setHistoryLoadFailed ] = useState( false );
	const [ settingsLoadFailed, setSettingsLoadFailed ] = useState( false );
	const [ comparison, setComparison ] =
		useState< Scan[ 'comparison' ] >( null );
	const [ findings, setFindings ] = useState< Finding[] >( [] );
	const [ findingsScanId, setFindingsScanId ] = useState< number | null >(
		null
	);
	const [ settings, setSettings ] = useState< Settings | null >( null );
	const [ selected, setSelected ] = useState< Finding | null >( null );
	const detailKey = useRef< string | null >( null );
	const detailHeading = useRef< HTMLHeadingElement >( null );
	const findingsHeading = useRef< HTMLHeadingElement >( null );
	const settingsLoaded = useRef( false );
	const loadInFlight = useRef< Promise< void > | null >( null );
	const pollInFlight = useRef( false );
	const [ pollError, setPollError ] = useState( '' );
	const [ query, setQuery ] = useState( '' );
	const [ severity, setSeverity ] = useState( '' );
	const [ findingStatus, setFindingStatus ] = useState( '' );
	const [ category, setCategory ] = useState( '' );
	const [ notice, setNotice ] = useState( '' );
	const [ error, setError ] = useState( '' );
	const [ busy, setBusy ] = useState( false );
	const [ confirmCancel, setConfirmCancel ] = useState( false );
	const scanId = Number( params.get( 'scan' ) ) || overview?.latest?.id;
	const reportScanData: Scan | null =
		reportScan &&
		reportScan.id === scanId &&
		[ 'completed', 'partial' ].includes( reportScan.status )
			? reportScan
			: null;
	const reportReady = Boolean( reportScanData );
	const load = useCallback( async () => {
		while ( loadInFlight.current ) {
			await loadInFlight.current;
		}
		let finishLoad!: () => void;
		loadInFlight.current = new Promise< void >( ( resolve ) => {
			finishLoad = resolve;
		} );
		setError( '' );
		setPollError( '' );
		setHistoryLoadFailed( false );
		setHistoryLoaded( false );
		setSettingsLoadFailed( false );
		try {
			const result = await api< {
				latest: Scan | null;
			} >( '/overview' );
			setOverview( result );
			const ancillaryReads = Promise.allSettled( [
				api< {
					items: Scan[];
					total: number;
				} >( '/scans' ),
				api< Settings >( '/settings' ),
			] );
			const id =
				Number(
					new URLSearchParams( window.location.search ).get( 'scan' )
				) || result.latest?.id;
			let selectedScanFailed = false;
			if ( id ) {
				try {
					const detail = await api< Scan >( `/scans/${ id }` );
					const allFindings: Finding[] = [];
					let total = 0;
					for (
						let page = 1;
						page === 1 || allFindings.length < total;
						page += 1
					) {
						const findingPage = await api< {
							items: Finding[];
							total: number;
						} >(
							`/scans/${ id }/findings?page=${ page }&per_page=100`
						);
						allFindings.push( ...findingPage.items );
						total = findingPage.total;
						if ( findingPage.items.length === 0 ) {
							break;
						}
					}
					setFindings( allFindings );
					setFindingsScanId( id );
					const findingKey = new URLSearchParams(
						window.location.search
					).get( 'finding' );
					if ( findingKey ) {
						const match = allFindings.find(
							( item ) =>
								( item.id || item.identity_hash ) === findingKey
						);
						if ( match ) {
							detailKey.current = findingKey;
							setSelected( ( current ) =>
								current?.id === match.id &&
								current?.identity_hash === match.identity_hash
									? current
									: match
							);
						}
					}
					setReportScan( detail );
				} catch ( e ) {
					selectedScanFailed = true;
					setError(
						errorMessage(
							e,
							__(
								'Could not load audit data.',
								'site-security-auditor'
							)
						)
					);
				}
			} else {
				setFindings( [] );
				setFindingsScanId( null );
				setReportScan( null );
			}
			const [ historyResult, prefsResult ] = await ancillaryReads;
			if ( historyResult.status === 'fulfilled' ) {
				setScans( historyResult.value.items );
				setHistoryLoaded( true );
				if ( view === 'history' ) {
					setComparison( null );
				}
			} else {
				setScans( [] );
				setComparison( null );
				setHistoryLoadFailed( true );
				if ( ! selectedScanFailed ) {
					setError(
						errorMessage(
							historyResult.reason,
							__(
								'Could not load audit history.',
								'site-security-auditor'
							)
						)
					);
				}
			}
			if (
				view === 'history' &&
				historyResult.status === 'fulfilled' &&
				historyResult.value.items.length
			) {
				setComparison( null );
				try {
					const detail = await api< Scan >(
						`/scans/${ historyResult.value.items[ 0 ].id }`
					);
					setComparison( detail.comparison || null );
				} catch ( e ) {
					if ( ! selectedScanFailed ) {
						setError(
							errorMessage(
								e,
								__(
									'Could not load audit comparison.',
									'site-security-auditor'
								)
							)
						);
					}
				}
			}
			if ( ! settingsLoaded.current ) {
				if ( prefsResult.status === 'fulfilled' ) {
					setSettings( prefsResult.value );
					settingsLoaded.current = true;
				} else {
					setSettingsLoadFailed( true );
					if (
						! selectedScanFailed &&
						historyResult.status === 'fulfilled'
					) {
						setError(
							errorMessage(
								prefsResult.reason,
								__(
									'Could not load settings.',
									'site-security-auditor'
								)
							)
						);
					}
				}
			}
		} catch ( e ) {
			setError(
				errorMessage(
					e,
					__( 'Could not load audit data.', 'site-security-auditor' )
				)
			);
		} finally {
			loadInFlight.current = null;
			finishLoad();
		}
	}, [ view ] );
	useEffect( () => {
		apiFetch.use(
			apiFetch.createNonceMiddleware( window.ssaSettings.nonce )
		);
	}, [] );
	useEffect( () => {
		void load();
	}, [ load ] );
	useEffect( () => {
		const activeScan = overview?.latest;
		if (
			! activeScan ||
			! [ 'queued', 'running' ].includes( activeScan.status )
		) {
			return;
		}
		let mounted = true;
		const timer = window.setInterval( async () => {
			if ( pollInFlight.current || loadInFlight.current ) {
				return;
			}
			pollInFlight.current = true;
			let pollSucceeded = false;
			try {
				const snapshot = await api< {
					latest: Scan | null;
				} >( '/overview' );
				if (
					! snapshot.latest ||
					snapshot.latest.id !== activeScan.id ||
					! [ 'queued', 'running' ].includes( snapshot.latest.status )
				) {
					void load();
					return;
				}
				const detail = await api< Scan >( `/scans/${ activeScan.id }` );
				pollSucceeded = true;
				if ( mounted ) {
					if ( ! [ 'queued', 'running' ].includes( detail.status ) ) {
						void load();
					} else {
						setOverview( {
							latest: detail,
						} );
					}
				}
			} catch ( e ) {
				if ( mounted ) {
					setPollError(
						errorMessage(
							e,
							__(
								'Could not refresh audit progress.',
								'site-security-auditor'
							)
						)
					);
				}
			} finally {
				if ( mounted && pollSucceeded && ! loadInFlight.current ) {
					setPollError( '' );
				}
				pollInFlight.current = false;
			}
		}, 5000 );
		return () => {
			mounted = false;
			window.clearInterval( timer );
		};
	}, [ overview?.latest, load ] );
	const closeDetails = useCallback( () => {
		setSelected( null );
		const url = new URL( window.location.href );
		url.searchParams.delete( 'finding' );
		window.history.replaceState( {}, '', url );
		window.setTimeout( () => {
			const trigger = Array.from(
				document.querySelectorAll< HTMLButtonElement >(
					'[data-finding-key]'
				)
			).find(
				( button ) => button.dataset.findingKey === detailKey.current
			);
			( trigger || findingsHeading.current )?.focus();
		}, 0 );
	}, [] );
	const openFinding = ( finding: Finding ) => {
		detailKey.current = finding.id || finding.identity_hash || null;
		setSelected( finding );
		const url = new URL( window.location.href );
		url.searchParams.set(
			'finding',
			finding.id || finding.identity_hash || ''
		);
		window.history.replaceState( {}, '', url );
	};
	const selectedIdentity = selected?.id || selected?.identity_hash;
	useEffect( () => {
		if ( ! selectedIdentity ) {
			return;
		}
		detailHeading.current?.focus();
		const onKeyDown = ( event: KeyboardEvent ) => {
			if ( event.key === 'Escape' ) {
				closeDetails();
			}
		};
		window.addEventListener( 'keydown', onKeyDown );
		return () => window.removeEventListener( 'keydown', onKeyDown );
	}, [ selectedIdentity, closeDetails ] );
	const navigate = ( next: View, id?: number ) => {
		setView( next );
		if ( next === 'overview' ) {
			setFindings( [] );
			setFindingsScanId( null );
		}
		if ( next === 'report' ) {
			setReportScan( null );
			setFindings( [] );
		}
		const url = new URL( window.location.href );
		if ( next === 'overview' ) {
			url.searchParams.delete( 'view' );
		} else {
			url.searchParams.set( 'view', next );
		}
		if ( next !== 'findings' ) {
			setSelected( null );
			url.searchParams.delete( 'finding' );
		}
		if ( id ) {
			url.searchParams.set( 'scan', String( id ) );
		} else {
			url.searchParams.delete( 'scan' );
		}
		window.history.replaceState( {}, '', url );
	};
	const action = async (
		path: string,
		method = 'POST',
		data?: unknown,
		success?: string
	) => {
		setBusy( true );
		setError( '' );
		setNotice( '' );
		try {
			await api( path, {
				method,
				data,
			} );
			if ( success ) {
				setNotice( success );
			}
			await load();
		} catch ( e ) {
			setError(
				errorMessage(
					e,
					__( 'The request failed.', 'site-security-auditor' )
				)
			);
			if ( path === '/settings' ) {
				try {
					setSettings( await api< Settings >( '/settings' ) );
				} catch {
					// Keep the original save error visible if settings cannot be reloaded.
				}
			}
		} finally {
			setBusy( false );
		}
	};
	const latest = overview?.latest;
	const findingsDisplayScanId = view === 'overview' ? latest?.id : scanId;
	const findingsLoadedForDisplay =
		findingsDisplayScanId !== undefined &&
		findingsScanId === findingsDisplayScanId;
	const currentFindings = findingsLoadedForDisplay ? findings : [];
	const active = Boolean(
		latest && [ 'queued', 'running' ].includes( latest.status )
	);
	const resultsAvailable = Boolean(
		latest && [ 'completed', 'partial' ].includes( latest.status )
	);
	const findingCount = ( countSeverity: string ) => {
		if ( ! resultsAvailable || ! findingsLoadedForDisplay ) {
			return __( 'Not available', 'site-security-auditor' );
		}
		return String(
			currentFindings.filter(
				( finding ) =>
					finding.severity === countSeverity &&
					finding.status === 'fail'
			).length
		);
	};
	const filtered = currentFindings.filter(
		( f ) =>
			`${ f.title } ${ f.component_name }`
				.toLowerCase()
				.includes( query.toLowerCase() ) &&
			( ! severity || f.severity === severity ) &&
			( ! findingStatus || f.status === findingStatus ) &&
			( ! category || f.kind === category )
	);
	const priorityFindings = [ ...currentFindings ]
		.filter( ( f ) => f.status === 'fail' )
		.sort(
			( a, b ) =>
				( severityOrder[ a.severity ] ?? 6 ) -
					( severityOrder[ b.severity ] ?? 6 ) ||
				Date.parse( b.checked_at ) - Date.parse( a.checked_at )
		);
	const exportReport = async ( format: 'csv' | 'json' ) => {
		if ( ! reportScan || reportScan.id !== scanId ) {
			return;
		}
		setBusy( true );
		setError( '' );
		try {
			const response = await apiFetch< Response >( {
				path: `/site-security-auditor/v1/scans/${ reportScan.id }/export?format=${ format }`,
				parse: false,
			} as never );
			const link = document.createElement( 'a' );
			link.href = URL.createObjectURL( await response.blob() );
			link.download = `site-security-audit-${ reportScan.id }.${ format }`;
			link.click();
			URL.revokeObjectURL( link.href );
		} catch ( e ) {
			setError(
				errorMessage(
					e,
					__(
						'Could not export this report.',
						'site-security-auditor'
					)
				)
			);
		} finally {
			setBusy( false );
		}
	};
	let runLabel: string = __( 'Run audit', 'site-security-auditor' );
	if ( latest ) {
		runLabel = __( 'Run another audit', 'site-security-auditor' );
	}
	if ( busy ) {
		runLabel = __( 'Starting…', 'site-security-auditor' );
	}
	return (
		<main className="ssa-app">
			<header className="ssa-header">
				<div>
					<p className="ssa-eyebrow">
						{ __(
							'SITE SECURITY AUDITOR',
							'site-security-auditor'
						) }
					</p>
					<h1>{ __( 'Security Audit', 'site-security-auditor' ) }</h1>
					<p>
						{ __(
							'Know what was checked, why it matters and what to do.',
							'site-security-auditor'
						) }
					</p>
				</div>
				{ ! active && latest && (
					<button
						className="ssa-primary"
						disabled={ busy }
						onClick={ () =>
							void action(
								'/scans',
								'POST',
								undefined,
								'Audit started.'
							)
						}
					>
						{ runLabel }
					</button>
				) }
			</header>
			<nav
				className="ssa-tabs"
				aria-label={ __(
					'Security audit views',
					'site-security-auditor'
				) }
			>
				{ (
					[ 'overview', 'findings', 'history', 'settings' ] as View[]
				 ).map( ( tab ) => (
					<button
						key={ tab }
						aria-current={ view === tab ? 'page' : undefined }
						onClick={ () => navigate( tab ) }
					>
						{ viewLabels[ tab ] }
					</button>
				) ) }
				{ view === 'report' && (
					<button aria-current="page">
						{ __( 'Report', 'site-security-auditor' ) }
					</button>
				) }
			</nav>
			{ ( error || pollError ) && (
				<p role="alert" className="ssa-alert">
					{ error || pollError }
				</p>
			) }
			{ notice && (
				<p role="status" className="ssa-notice">
					{ notice }
				</p>
			) }
			{ view === 'overview' && (
				<>
					{ ! latest ? (
						<section className="ssa-empty">
							<h2>
								{ __(
									'No audits yet',
									'site-security-auditor'
								) }
							</h2>
							<p>
								{ __(
									'Run a read-only audit of selected WordPress settings, installed components and enabled integrity checks.',
									'site-security-auditor'
								) }
							</p>
							<button
								className="ssa-primary"
								disabled={ busy }
								onClick={ () =>
									void action(
										'/scans',
										'POST',
										undefined,
										'Audit started.'
									)
								}
							>
								{ __( 'Run audit', 'site-security-auditor' ) }
							</button>
							<button
								className="ssa-link"
								onClick={ () => navigate( 'settings' ) }
							>
								{ __(
									'Review optional checks and consent',
									'site-security-auditor'
								) }
							</button>
						</section>
					) : (
						<>
							<section
								className="ssa-metrics"
								aria-label={ __(
									'Latest audit summary',
									'site-security-auditor'
								) }
							>
								<Metric
									label={ __(
										'Posture',
										'site-security-auditor'
									) }
									value={ scoreLabel( latest ) }
									detail={ statusLabel( latest.status ) }
								/>
								<Metric
									label={ __(
										'Coverage',
										'site-security-auditor'
									) }
									value={ coverageLabel( latest ) }
									detail={ __(
										'Eligible checks assessed',
										'site-security-auditor'
									) }
								/>
								<Metric
									label={ __(
										'Critical',
										'site-security-auditor'
									) }
									value={ findingCount( 'critical' ) }
									detail={ __(
										'Open findings',
										'site-security-auditor'
									) }
								/>
								<Metric
									label={ __(
										'High',
										'site-security-auditor'
									) }
									value={ findingCount( 'high' ) }
									detail={ __(
										'Open findings',
										'site-security-auditor'
									) }
								/>
							</section>
							{ active && (
								<section className="ssa-panel">
									<h2>
										{ __(
											'Audit in progress',
											'site-security-auditor'
										) }
									</h2>
									<p aria-live="polite">
										{ statusLabel( latest.status ) }{ ' ' }
										{ __(
											'\xB7 Started',
											'site-security-auditor'
										) }{ ' ' }
										{ date( latest.started_at ) }
									</p>
									<p>
										{
											Object.keys( latest.checks || {} )
												.length
										}{ ' ' }
										{ __(
											'of 16 checks have results;',
											'site-security-auditor'
										) }{ ' ' }
										{ Math.max(
											16 -
												Object.keys(
													latest.checks || {}
												).length,
											0
										) }{ ' ' }
										{ __(
											'remain.',
											'site-security-auditor'
										) }
									</p>
									<p>
										{ __(
											'Current stage:',
											'site-security-auditor'
										) }{ ' ' }
										{ latest.progress?.stage?.replaceAll(
											'_',
											' '
										) ||
											__(
												'Not reported',
												'site-security-auditor'
											) }{ ' ' }
										{ __(
											'\xB7 Updated',
											'site-security-auditor'
										) }{ ' ' }
										{ date(
											latest.updated_at ||
												latest.started_at
										) }
									</p>
									<p>
										{ __(
											'Continue checks a small group of remaining items. Repeat this if the audit is still active.',
											'site-security-auditor'
										) }
									</p>
									<button
										disabled={ busy }
										onClick={ () =>
											void action(
												`/scans/${ latest.id }/advance`,
												'POST',
												undefined,
												'Audit progress requested.'
											)
										}
									>
										{ __(
											'Continue scan',
											'site-security-auditor'
										) }
									</button>
									<button
										disabled={ busy }
										onClick={ () =>
											setConfirmCancel( true )
										}
									>
										{ __(
											'Cancel audit',
											'site-security-auditor'
										) }
									</button>
								</section>
							) }
							{ confirmCancel && latest && (
								<Modal
									title={ __(
										'Cancel audit?',
										'site-security-auditor'
									) }
									onRequestClose={ () =>
										setConfirmCancel( false )
									}
								>
									<p>
										{ __(
											'Completed checks will remain in this audit record.',
											'site-security-auditor'
										) }
									</p>
									<Button
										onClick={ () =>
											setConfirmCancel( false )
										}
									>
										{ __(
											'Keep scanning',
											'site-security-auditor'
										) }
									</Button>
									<Button
										variant="primary"
										disabled={ busy }
										onClick={ () => {
											setConfirmCancel( false );
											void action(
												`/scans/${ latest.id }/cancel`,
												'POST',
												undefined,
												'Audit cancelled.'
											);
										} }
									>
										{ __(
											'Cancel audit',
											'site-security-auditor'
										) }
									</Button>
								</Modal>
							) }
							<div className="ssa-grid">
								<section className="ssa-panel">
									<div className="ssa-panel-heading">
										<h2>
											{ __(
												'Prioritised findings',
												'site-security-auditor'
											) }
										</h2>
										<button
											className="ssa-link"
											onClick={ () =>
												navigate( 'findings' )
											}
										>
											{ __(
												'View all findings',
												'site-security-auditor'
											) }
										</button>
									</div>
									{ priorityFindings
										.slice( 0, 5 )
										.map( ( f ) => (
											<button
												className="ssa-finding-row"
												key={ f.id || f.identity_hash }
												onClick={ () => {
													navigate( 'findings' );
													openFinding( f );
												} }
												data-finding-key={
													f.id || f.identity_hash
												}
											>
												<span
													className={ `ssa-severity ${
														severityLabels[
															f.severity
														] || f.severity
													}` }
												>
													{ severityLabels[
														f.severity
													] || f.severity }
												</span>
												<span>{ f.title }</span>
												<span aria-hidden="true">
													{ __(
														'\u203A',
														'site-security-auditor'
													) }
												</span>
											</button>
										) ) }
									{ ! findingsLoadedForDisplay ? (
										<p>
											{ __(
												'Findings are not available for this audit.',
												'site-security-auditor'
											) }
										</p>
									) : (
										! priorityFindings.length && (
											<p>
												{ __(
													'No failing findings were returned for this audit.',
													'site-security-auditor'
												) }
											</p>
										)
									) }
								</section>
								<section className="ssa-panel">
									<h2>
										{ __(
											'Latest audit',
											'site-security-auditor'
										) }
									</h2>
									<p>
										{ date(
											latest.completed_at ||
												latest.started_at
										) }
									</p>
									<p>
										{ __(
											'Status:',
											'site-security-auditor'
										) }{ ' ' }
										<Status value={ latest.status } />
									</p>
									<p>
										{ __(
											'Checks:',
											'site-security-auditor'
										) }{ ' ' }
										{
											Object.values(
												latest.checks || {}
											).filter( ( c ) =>
												[ 'pass', 'fail' ].includes(
													c.status
												)
											).length
										}{ ' ' }
										{ __(
											'assessed',
											'site-security-auditor'
										) }
									</p>
									<button
										onClick={ () =>
											navigate( 'report', latest.id )
										}
									>
										{ __(
											'Open report',
											'site-security-auditor'
										) }
									</button>
								</section>
							</div>
							<section className="ssa-panel">
								<h2>
									{ __(
										'Unknown checks',
										'site-security-auditor'
									) }
								</h2>
								{ Object.values( latest.checks || {} )
									.filter(
										( c ) =>
											c.status === 'unknown' ||
											c.has_unknown
									)
									.map( ( c ) => (
										<p key={ c.check_id }>
											<strong>{ c.check_id }</strong>
											{ __(
												':',
												'site-security-auditor'
											) }{ ' ' }
											{ c.reason ||
												__(
													'Reason not provided',
													'site-security-auditor'
												) }
											{ __(
												'.',
												'site-security-auditor'
											) }
										</p>
									) ) }
								{ ! Object.values( latest.checks || {} ).some(
									( c ) =>
										c.status === 'unknown' || c.has_unknown
								) && (
									<p>
										{ __(
											'No unknown checks reported.',
											'site-security-auditor'
										) }
									</p>
								) }
							</section>
							<section className="ssa-panel">
								<h2>
									{ __(
										'Coverage and confidence',
										'site-security-auditor'
									) }
								</h2>
								<p>
									{ __(
										'Local checks assessed:',
										'site-security-auditor'
									) }{ ' ' }
									{
										Object.values(
											latest.checks || {}
										).filter(
											( c ) =>
												! [
													'SSA-004',
													'SSA-005',
													'SSA-006',
													'SSA-012',
													'SSA-015',
													'SSA-016',
												].includes( c.check_id ) &&
												[ 'pass', 'fail' ].includes(
													c.status
												)
										).length
									}
									{ __(
										'; unknown:',
										'site-security-auditor'
									) }{ ' ' }
									{
										Object.values(
											latest.checks || {}
										).filter(
											( c ) =>
												! [
													'SSA-004',
													'SSA-005',
													'SSA-006',
													'SSA-012',
													'SSA-015',
													'SSA-016',
												].includes( c.check_id ) &&
												( c.status === 'unknown' ||
													c.has_unknown )
										).length
									}
									{ __( '.', 'site-security-auditor' ) }
								</p>
								<p>
									{ __(
										'Vulnerability intelligence:',
										'site-security-auditor'
									) }{ ' ' }
									{ [ 'SSA-004', 'SSA-005', 'SSA-006' ]
										.map(
											( id ) =>
												`${ id } ${ statusLabel(
													latest.checks?.[ id ]
														?.status || 'unknown'
												) }`
										)
										.join( ' · ' ) }
									{ __( '.', 'site-security-auditor' ) }
								</p>
								<p>
									{ __(
										'Core integrity:',
										'site-security-auditor'
									) }{ ' ' }
									{ statusLabel(
										latest.checks?.[ 'SSA-012' ]?.status ||
											'unknown'
									) }
									{ __( '.', 'site-security-auditor' ) }
								</p>
								{ latest.coverage < 70 && (
									<p role="note">
										{ __(
											'Coverage is below 70%; the score is suppressed because too few eligible checks were assessed.',
											'site-security-auditor'
										) }
									</p>
								) }
							</section>
							<p className="ssa-footnote">
								{ __(
									'This is a limited security posture audit, not a malware scan. A passing check does not establish that the site is secure.',
									'site-security-auditor'
								) }
							</p>
						</>
					) }
				</>
			) }
			{ view === 'findings' && (
				<section className="ssa-panel">
					<h2 ref={ findingsHeading } tabIndex={ -1 }>
						{ __( 'Findings', 'site-security-auditor' ) }
					</h2>
					{ ! Boolean( selected ) && (
						<>
							<div className="ssa-filters">
								<label htmlFor="ssa-search">
									{ __(
										'Search findings',
										'site-security-auditor'
									) }
									<input
										id="ssa-search"
										value={ query }
										onChange={ ( e ) =>
											setQuery( e.target.value )
										}
										placeholder={ __(
											'Title or component',
											'site-security-auditor'
										) }
									/>
								</label>
								<label htmlFor="ssa-severity">
									{ __(
										'Severity',
										'site-security-auditor'
									) }
									<select
										id="ssa-severity"
										value={ severity }
										onChange={ ( e ) =>
											setSeverity( e.target.value )
										}
									>
										<option value="">
											{ __(
												'All severities',
												'site-security-auditor'
											) }
										</option>
										{ [
											'critical',
											'high',
											'medium',
											'low',
											'info',
											'unrated',
										].map( ( s ) => (
											<option key={ s }>{ s }</option>
										) ) }
									</select>
								</label>
								<label htmlFor="ssa-status">
									{ __( 'Status', 'site-security-auditor' ) }
									<select
										id="ssa-status"
										value={ findingStatus }
										onChange={ ( e ) =>
											setFindingStatus( e.target.value )
										}
									>
										<option value="">
											{ __(
												'All statuses',
												'site-security-auditor'
											) }
										</option>
										{ [
											'fail',
											'unknown',
											'pass',
											'not_applicable',
										].map( ( s ) => (
											<option key={ s } value={ s }>
												{ statusLabel( s ) }
											</option>
										) ) }
									</select>
								</label>
								<label htmlFor="ssa-category">
									{ __(
										'Category',
										'site-security-auditor'
									) }
									<select
										id="ssa-category"
										value={ category }
										onChange={ ( e ) =>
											setCategory( e.target.value )
										}
									>
										<option value="">
											{ __(
												'All categories',
												'site-security-auditor'
											) }
										</option>
										{ [
											'confirmed_vulnerability',
											'configuration_risk',
											'hardening',
											'integrity_difference',
											'informational',
											'unverified',
										].map( ( s ) => (
											<option key={ s } value={ s }>
												{ kindLabels[ s ] || s }
											</option>
										) ) }
									</select>
								</label>
								<span>
									{ filtered.length }{ ' ' }
									{ __( 'results', 'site-security-auditor' ) }
								</span>
								<button
									onClick={ () => {
										setQuery( '' );
										setSeverity( '' );
										setFindingStatus( '' );
										setCategory( '' );
									} }
								>
									{ __(
										'Reset filters',
										'site-security-auditor'
									) }
								</button>
							</div>

							<div
								className="ssa-table-wrap"
								role="region"
								aria-label={ __(
									'Audit findings',
									'site-security-auditor'
								) }
								tabIndex={ 0 }
							>
								<table>
									<thead>
										<tr>
											<th>
												{ __(
													'Severity',
													'site-security-auditor'
												) }
											</th>
											<th>
												{ __(
													'Finding / check',
													'site-security-auditor'
												) }
											</th>
											<th>
												{ __(
													'Component',
													'site-security-auditor'
												) }
											</th>
											<th>
												{ __(
													'State',
													'site-security-auditor'
												) }
											</th>
											<th>
												{ __(
													'Verified',
													'site-security-auditor'
												) }
											</th>
											<th>
												{ __(
													'Details',
													'site-security-auditor'
												) }
											</th>
										</tr>
									</thead>
									<tbody>
										{ filtered.map( ( f ) => (
											<tr key={ f.id || f.identity_hash }>
												<td>
													<span
														className={ `ssa-severity ${
															severityLabels[
																f.severity
															] || f.severity
														}` }
													>
														{ severityLabels[
															f.severity
														] || f.severity }
													</span>
												</td>
												<td>
													{ f.title }
													<small>
														{ f.check_id }
													</small>
												</td>
												<td>
													{ f.component_name ||
														f.component_type ||
														__(
															'Site',
															'site-security-auditor'
														) }
												</td>
												<td>
													<Status
														value={ f.status }
													/>
												</td>
												<td>
													{ date( f.checked_at ) }
												</td>
												<td>
													<button
														onClick={ () => {
															openFinding( f );
														} }
														data-finding-key={
															f.id ||
															f.identity_hash
														}
													>
														{ __(
															'View details',
															'site-security-auditor'
														) }
													</button>
												</td>
											</tr>
										) ) }
									</tbody>
								</table>
							</div>
							<div className="ssa-mobile-list">
								{ filtered.map( ( f ) => (
									<article
										className="ssa-mobile-card"
										key={ f.id || f.identity_hash }
									>
										<p>
											<span
												className={ `ssa-severity ${
													severityLabels[
														f.severity
													] || f.severity
												}` }
											>
												{ severityLabels[
													f.severity
												] || f.severity }
											</span>{ ' ' }
											{ __(
												'\xB7',
												'site-security-auditor'
											) }{ ' ' }
											<Status value={ f.status } />
										</p>
										<h3>{ f.title }</h3>
										<p>
											{ f.component_name ||
												f.component_type ||
												__(
													'Site',
													'site-security-auditor'
												) }{ ' ' }
											{ __(
												'\xB7',
												'site-security-auditor'
											) }{ ' ' }
											{ f.check_id }
										</p>
										<p>
											{ __(
												'Verified:',
												'site-security-auditor'
											) }{ ' ' }
											{ date( f.checked_at ) }
										</p>
										<button
											onClick={ () => {
												openFinding( f );
											} }
											data-finding-key={
												f.id || f.identity_hash
											}
										>
											{ __(
												'View details',
												'site-security-auditor'
											) }
										</button>
									</article>
								) ) }
							</div>
							{ filtered.length === 0 && (
								<p>
									{ __(
										'No findings match these filters.',
										'site-security-auditor'
									) }
								</p>
							) }
						</>
					) }
					{ selected && (
						<article className="ssa-detail">
							<button
								className="ssa-close"
								onClick={ closeDetails }
							>
								{ __(
									'Close details',
									'site-security-auditor'
								) }
							</button>
							<p
								className={ `ssa-severity ${ selected.severity }` }
							>
								{ selected.severity }{ ' ' }
								{ __( '\xB7', 'site-security-auditor' ) }{ ' ' }
								{ kindLabels[ selected.kind ] || selected.kind }
							</p>
							<h3 ref={ detailHeading } tabIndex={ -1 }>
								{ selected.title }
							</h3>
							<p>{ selected.summary }</p>
							<h4>
								{ __( 'Evidence', 'site-security-auditor' ) }
							</h4>
							{ selected.evidence &&
							selected.evidence.length > 400 ? (
								<details>
									<summary>
										{ selected.evidence.slice( 0, 400 ) }
										{ __(
											'\u2026 Show full evidence',
											'site-security-auditor'
										) }
									</summary>
									<p>{ selected.evidence }</p>
								</details>
							) : (
								<p>
									{ selected.evidence ||
										'No evidence supplied.' }
								</p>
							) }
							<h4>
								{ __(
									'How to address it',
									'site-security-auditor'
								) }
							</h4>
							<ol>
								{ selected.remediation?.map( ( step ) => (
									<li key={ step }>{ step }</li>
								) ) }
							</ol>
							<h4>
								{ __(
									'Verification',
									'site-security-auditor'
								) }
							</h4>
							<p>
								{ selected.check_id }{ ' ' }
								{ __( '\xB7', 'site-security-auditor' ) }{ ' ' }
								{ selected.source || 'Source not supplied' }{ ' ' }
								{ __(
									'\xB7 Checked',
									'site-security-auditor'
								) }{ ' ' }
								{ date( selected.checked_at ) }
								{ selected.source_updated_at
									? ` · Source updated ${ date(
											selected.source_updated_at
										) }`
									: '' }
							</p>
							{ selected.kind === 'integrity_difference' && (
								<p>
									{ __(
										'A checksum difference identifies an integrity difference; it does not prove infection.',
										'site-security-auditor'
									) }
								</p>
							) }
							{ selected.check_id === 'SSA-008' && (
								<p>
									{ __(
										'This check reports the FORCE_SSL_ADMIN setting; it does not verify how all administrator requests travel.',
										'site-security-auditor'
									) }
								</p>
							) }
							{ selected.references
								?.filter( ( href ) => {
									try {
										return (
											new URL( href ).protocol ===
											'https:'
										);
									} catch {
										return false;
									}
								} )
								.map( ( href ) => (
									<p key={ href }>
										<a
											href={ href }
											target="_blank"
											rel="noreferrer"
										>
											{ __(
												'Reference',
												'site-security-auditor'
											) }
										</a>
									</p>
								) ) }
						</article>
					) }
				</section>
			) }
			{ view === 'history' && (
				<>
					<section className="ssa-panel">
						<h2>
							{ __( 'Audit history', 'site-security-auditor' ) }
						</h2>
						{ historyLoadFailed && (
							<p>
								{ __(
									'Audit history could not be loaded.',
									'site-security-auditor'
								) }
							</p>
						) }
						{ ! historyLoadFailed && ! historyLoaded && (
							<p>
								{ __(
									'Loading audit history…',
									'site-security-auditor'
								) }
							</p>
						) }

						{ ! historyLoadFailed &&
							historyLoaded &&
							scans.length > 0 && (
								<div className="ssa-table-wrap">
									<table>
										<thead>
											<tr>
												<th>
													{ __(
														'Date',
														'site-security-auditor'
													) }
												</th>
												<th>
													{ __(
														'State',
														'site-security-auditor'
													) }
												</th>
												<th>
													{ __(
														'Posture',
														'site-security-auditor'
													) }
												</th>
												<th>
													{ __(
														'Coverage',
														'site-security-auditor'
													) }
												</th>
												<th>
													{ __(
														'Report',
														'site-security-auditor'
													) }
												</th>
											</tr>
										</thead>
										<tbody>
											{ scans.map( ( s ) => (
												<tr key={ s.id }>
													<td>
														{ date(
															s.completed_at ||
																s.started_at
														) }
													</td>
													<td>
														<Status
															value={ s.status }
														/>
													</td>
													<td>{ scoreLabel( s ) }</td>
													<td>
														{ coverageLabel( s ) }
													</td>
													<td>
														<button
															disabled={
																! [
																	'completed',
																	'partial',
																].includes(
																	s.status
																)
															}
															onClick={ () =>
																navigate(
																	'report',
																	s.id
																)
															}
														>
															{ __(
																'Open report',
																'site-security-auditor'
															) }
														</button>
													</td>
												</tr>
											) ) }
										</tbody>
									</table>
								</div>
							) }
						{ ! historyLoadFailed &&
							historyLoaded &&
							scans.length === 0 && (
								<p>
									{ __(
										'No audit history is available.',
										'site-security-auditor'
									) }
								</p>
							) }
					</section>
					<section className="ssa-panel">
						<h2>
							{ __(
								'Latest comparison',
								'site-security-auditor'
							) }
						</h2>
						{ comparison?.length ? (
							comparison.map( ( item, index ) => (
								<p key={ `${ item.check_id }-${ index }` }>
									<strong>{ item.state }</strong>{ ' ' }
									{ __( '\xB7', 'site-security-auditor' ) }{ ' ' }
									{ item.check_id }{ ' ' }
									{ __( '\xB7', 'site-security-auditor' ) }{ ' ' }
									{ item.title }
								</p>
							) )
						) : (
							<p>
								{ __(
									'No comparable scan data was returned. Unknown checks are not treated as resolved.',
									'site-security-auditor'
								) }
							</p>
						) }
					</section>
				</>
			) }
			{ view === 'report' && (
				<section className="ssa-panel ssa-report">
					<div className="ssa-actions">
						{ reportScanData && (
							<Button onClick={ () => window.print() }>
								{ __(
									'Print / Save as PDF',
									'site-security-auditor'
								) }
							</Button>
						) }
						{ reportScanData && (
							<>
								<Button
									onClick={ () => void exportReport( 'csv' ) }
									disabled={ busy }
								>
									{ __(
										'Download CSV',
										'site-security-auditor'
									) }
								</Button>
								<Button
									onClick={ () =>
										void exportReport( 'json' )
									}
									disabled={ busy }
								>
									{ __(
										'Download JSON',
										'site-security-auditor'
									) }
								</Button>
							</>
						) }
					</div>
					<p className="ssa-eyebrow">
						{ __( 'SITE SECURITY AUDIT', 'site-security-auditor' ) }
					</p>
					<h2>
						{ window.ssaSettings.siteName }{ ' ' }
						{ __( '(', 'site-security-auditor' ) }
						{ window.ssaSettings.hostname }
						{ __( ')', 'site-security-auditor' ) }
					</h2>
					{ ! error &&
						! pollError &&
						( ! reportScan || reportScan.id !== scanId ) && (
							<p>
								{ __(
									'Loading the selected audit\u2026',
									'site-security-auditor'
								) }
							</p>
						) }
					{ reportScan &&
						reportScan.id === scanId &&
						! reportReady && (
							<p>
								{ __(
									'A report is available after the audit completes or becomes partial.',
									'site-security-auditor'
								) }
							</p>
						) }
					{ reportScanData && (
						<>
							<p>
								{ __( 'Audit:', 'site-security-auditor' ) }{ ' ' }
								{ date(
									reportScanData.completed_at ||
										reportScanData.started_at
								) }{ ' ' }
								{ __(
									'\xB7 Status:',
									'site-security-auditor'
								) }{ ' ' }
								{ statusLabel( reportScanData.status ) }
							</p>
							<p>
								{ __( 'Coverage:', 'site-security-auditor' ) }{ ' ' }
								{ coverageLabel( reportScanData ) }{ ' ' }
								{ __(
									'\xB7 Posture:',
									'site-security-auditor'
								) }{ ' ' }
								{ scoreLabel( reportScanData ) }
							</p>
							<h3>
								{ __(
									'Check status',
									'site-security-auditor'
								) }
							</h3>
							{ Object.values( reportScanData.checks || {} ).map(
								( check ) => (
									<p key={ check.check_id }>
										{ check.check_id }{ ' ' }
										{ __(
											'\xB7',
											'site-security-auditor'
										) }{ ' ' }
										{ statusLabel( check.status ) }
										{ check.reason
											? ` · ${ check.reason }`
											: '' }
									</p>
								)
							) }
						</>
					) }
					{ reportScanData && (
						<>
							{ currentFindings.map( ( f ) => (
								<article key={ f.id || f.identity_hash }>
									<h3>{ f.title }</h3>
									<p>
										{ severityLabels[ f.severity ] ||
											f.severity }{ ' ' }
										{ __(
											'\xB7',
											'site-security-auditor'
										) }{ ' ' }
										{ f.component_name }{ ' ' }
										{ __(
											'\xB7',
											'site-security-auditor'
										) }{ ' ' }
										{ f.check_id }
									</p>
									<p>{ f.summary }</p>
									<p>
										<strong>
											{ __(
												'Evidence:',
												'site-security-auditor'
											) }
										</strong>{ ' ' }
										{ f.evidence }
									</p>
									{ f.remediation?.map( ( step ) => (
										<p key={ step }>
											{ __(
												'\u2022',
												'site-security-auditor'
											) }{ ' ' }
											{ step }
										</p>
									) ) }
									<p>
										{ __(
											'Source:',
											'site-security-auditor'
										) }{ ' ' }
										{ f.source ||
											__(
												'Not supplied',
												'site-security-auditor'
											) }{ ' ' }
										{ __(
											'\xB7 Checked',
											'site-security-auditor'
										) }{ ' ' }
										{ date( f.checked_at ) }
										{ f.source_updated_at
											? ` · Source updated ${ date(
													f.source_updated_at
												) }`
											: '' }
									</p>
									{ f.references
										?.filter( ( href ) => {
											try {
												return (
													new URL( href ).protocol ===
													'https:'
												);
											} catch {
												return false;
											}
										} )
										.map( ( href ) => (
											<p key={ href }>
												<a
													href={ href }
													target="_blank"
													rel="noreferrer"
												>
													{ __(
														'Reference',
														'site-security-auditor'
													) }
												</a>
											</p>
										) ) }
								</article>
							) ) }
							<h3>
								{ __(
									'Method and limitations',
									'site-security-auditor'
								) }
							</h3>
							<p>
								{ __(
									'Score version 1 applies the documented fixed severity weights once per failed check. Coverage counts assessed eligible checks over eligible checks; unknown checks stay in the denominator, while not-applicable and informational checks are excluded. Scores below 70 percent coverage are suppressed. Severity is contextual and is not a CVSS calculation. Optional external checks are only performed when enabled in Settings.',
									'site-security-auditor'
								) }
							</p>
							<p className="ssa-footnote">
								{ __(
									'This audit checks selected WordPress configuration and vulnerability indicators. It does not establish that the site is secure or free from compromise.',
									'site-security-auditor'
								) }
							</p>
						</>
					) }
				</section>
			) }
			{ view === 'settings' && (
				<section className="ssa-panel">
					<h2>
						{ __(
							'Settings and consent',
							'site-security-auditor'
						) }
					</h2>
					{ settings ? (
						<form
							onSubmit={ ( e ) => {
								e.preventDefault();
								void action(
									'/settings',
									'POST',
									settings,
									'Settings saved.'
								);
							} }
						>
							<Consent
								label="Vulnerability intelligence"
								checked={ settings.vulnerability_intelligence }
								onChange={ ( v ) =>
									setSettings( {
										...settings,
										vulnerability_intelligence: v,
									} )
								}
							>
								{ __(
									'When enabled, plugin and theme slugs and the WordPress core version are sent to WPVulnerability to check for published advisories. Installed plugin and theme versions are compared locally. The provider may see the requesting server IP. No user lists, secrets or full site URL are sent.',
									'site-security-auditor'
								) }
							</Consent>
							<p>
								<a
									href="https://docs.wpvulnerability.com/"
									target="_blank"
									rel="noreferrer"
								>
									{ __(
										'WPVulnerability documentation',
										'site-security-auditor'
									) }
								</a>
							</p>
							<Consent
								label="Core integrity verification"
								checked={ settings.core_integrity }
								onChange={ ( v ) =>
									setSettings( {
										...settings,
										core_integrity: v,
									} )
								}
							>
								{ __(
									'When enabled, official checksums are requested from WordPress.org using the WordPress version and locale, then compared against core files.',
									'site-security-auditor'
								) }
							</Consent>
							<Consent
								label="Weekly scheduled audit"
								checked={ settings.weekly_schedule }
								onChange={ ( v ) =>
									setSettings( {
										...settings,
										weekly_schedule: v,
									} )
								}
							>
								{ __(
									'Scheduled tasks depend on site traffic or server cron. Optional network checks only run when enabled above.',
									'site-security-auditor'
								) }
							</Consent>
							<p>
								{ __(
									'History is limited to the latest 20 audits and 90 days. Deactivation retains history; deleting the plugin removes its tables, options, cached provider responses and scheduled work.',
									'site-security-auditor'
								) }
							</p>
							<button className="ssa-primary" disabled={ busy }>
								{ __(
									'Save settings',
									'site-security-auditor'
								) }
							</button>
						</form>
					) : (
						<p>
							{ settingsLoadFailed
								? __(
										'Settings could not be loaded.',
										'site-security-auditor'
									)
								: __(
										'Loading settings\u2026',
										'site-security-auditor'
									) }
						</p>
					) }
				</section>
			) }
		</main>
	);
}
function Metric( {
	label,
	value,
	detail,
}: {
	label: string;
	value: string;
	detail: string;
} ) {
	return (
		<section className="ssa-panel ssa-metric">
			<span>{ label }</span>
			<strong>{ value }</strong>
			<small>{ detail }</small>
		</section>
	);
}
function Status( { value }: { value: string } ) {
	return (
		<span className={ `ssa-status ${ value }` }>
			{ statusLabel( value ) }
		</span>
	);
}
function Consent( {
	label,
	checked,
	onChange,
	children,
}: {
	label: string;
	checked: boolean;
	onChange: ( value: boolean ) => void;
	children: ReactNode;
} ) {
	const inputId = `ssa-setting-${ label
		.toLowerCase()
		.replaceAll( ' ', '-' ) }`;
	return (
		<label className="ssa-consent" htmlFor={ inputId } aria-label={ label }>
			<input
				type="checkbox"
				id={ inputId }
				checked={ checked }
				onChange={ ( e ) => onChange( e.target.checked ) }
			/>
			<span>
				<strong>{ label }</strong>
				<small>{ children }</small>
			</span>
		</label>
	);
}
const target = document.getElementById( 'ssa-root' );
if ( target ) {
	createRoot( target ).render( <App /> );
}
