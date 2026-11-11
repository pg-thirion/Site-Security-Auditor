import { expect, test } from '@playwright/test';
import axe from 'axe-core';

const api = '/wp-json/site-security-auditor/v1';
test( 'overview hides historical findings if current findings fail to load', async ( {
	page,
} ) => {
	await logIn( page );
	await page.route( `**${ api }/**`, async ( route ) => {
		const path = new URL( route.request().url() ).pathname.slice(
			api.length
		);
		const scan = ( id: number ) => ( {
			id,
			status: 'completed',
			checks: {},
			score: 100,
			coverage: 100,
			started_at: '2026-11-10 08:00:00',
			completed_at: '2026-11-10 08:01:00',
		} );
		if ( path === '/overview' ) {
			await route.fulfill( { json: { latest: scan( 900002 ) } } );
		} else if ( path === '/scans' ) {
			await route.fulfill( { json: { items: [], total: 0 } } );
		} else if ( path === '/settings' ) {
			await route.fulfill( { json: {} } );
		} else if ( path === '/scans/900001' ) {
			await route.fulfill( { json: scan( 900001 ) } );
		} else if ( path === '/scans/900001/findings' ) {
			await route.fulfill( {
				json: {
					items: [
						{
							id: 'old-critical',
							scan_id: 900001,
							check_id: 'old',
							component_type: 'plugin',
							component_key: 'old',
							component_name: 'Old finding',
							component_version: '1.0',
							status: 'fail',
							severity: 'critical',
							kind: 'security',
							title: 'Historical critical finding',
							summary: 'Historical',
							evidence: 'Historical',
							remediation: [],
							references: [],
							checked_at: '2026-11-09 08:00:00',
							source: 'test',
							source_updated_at: null,
						},
					],
					total: 1,
				},
			} );
		} else if ( path === '/scans/900002' ) {
			await route.fulfill( { json: scan( 900002 ) } );
		} else if ( path === '/scans/900002/findings' ) {
			await route.fulfill( { status: 500, body: 'Unavailable' } );
		} else {
			await route.continue();
		}
	} );
	await page.goto(
		'/wp-admin/admin.php?page=site-security-auditor&view=findings&scan=900001'
	);
	await expect(
		page
			.getByRole( 'row' )
			.filter( { hasText: 'Historical critical finding' } )
	).toBeVisible();
	const currentFindingsResponse = page.waitForResponse( ( response ) =>
		response.url().includes( '/scans/900002/findings' )
	);
	await page.getByRole( 'button', { name: 'Overview', exact: true } ).click();
	expect( ( await currentFindingsResponse ).status() ).toBe( 500 );
	await expect( page.getByRole( 'alert' ) ).toBeVisible();
	await expect(
		page
			.locator( '.ssa-metric' )
			.filter( { hasText: 'Posture' } )
			.locator( 'strong' )
	).toHaveText( '100/100' );
	await expect(
		page
			.locator( '.ssa-metric' )
			.filter( { hasText: 'Critical' } )
			.locator( 'strong' )
	).toHaveText( 'Not available' );
	await expect(
		page.getByText( 'Findings are not available for this audit.', {
			exact: true,
		} )
	).toBeVisible();
	await expect(
		page
			.getByRole( 'row' )
			.filter( { hasText: 'Historical critical finding' } )
	).toHaveCount( 0 );
	await page.screenshot( {
		path: '../artifacts/screenshots/audit-fixes-overview.png',
	} );
} );

test( 'history failure does not block selected report or imply no history', async ( {
	page,
} ) => {
	await logIn( page );
	const scan = {
		id: 900010,
		status: 'completed',
		checks: {},
		score: 100,
		coverage: 100,
		started_at: '2026-11-10 08:00:00',
		completed_at: '2026-11-10 08:01:00',
	};
	let releaseAncillary!: () => void;
	const ancillaryPending = new Promise< void >( ( resolve ) => {
		releaseAncillary = resolve;
	} );
	let signalAncillaryStarted!: () => void;
	const ancillaryStarted = new Promise< void >( ( resolve ) => {
		signalAncillaryStarted = resolve;
	} );
	let ancillaryRequestCount = 0;
	await page.route( `**${ api }/**`, async ( route ) => {
		const path = new URL( route.request().url() ).pathname.slice(
			api.length
		);
		if ( path === '/overview' ) {
			await route.fulfill( { json: { latest: scan } } );
		} else if ( path === '/scans' || path === '/settings' ) {
			ancillaryRequestCount++;
			if ( ancillaryRequestCount === 2 ) {
				signalAncillaryStarted();
			}
			await ancillaryPending;
			await route.fulfill( {
				status: 503,
				contentType: 'application/json',
				body: JSON.stringify( {
					code: 'fixture',
					message:
						path === '/scans'
							? 'History temporarily unavailable'
							: 'Settings temporarily unavailable',
				} ),
			} );
		} else if ( path === '/scans/900010' ) {
			await route.fulfill( { json: scan } );
		} else if ( path === '/scans/900010/findings' ) {
			await route.fulfill( { json: { items: [], total: 0 } } );
		} else {
			await route.continue();
		}
	} );

	const historyFailed = page.waitForResponse(
		( response ) =>
			new URL( response.url() ).pathname === `${ api }/scans` &&
			response.request().method() === 'GET'
	);
	const scanLoaded = page.waitForResponse(
		( response ) =>
			new URL( response.url() ).pathname === `${ api }/scans/900010`
	);
	await page.goto(
		'/wp-admin/admin.php?page=site-security-auditor&view=report&scan=900010'
	);
	await ancillaryStarted;
	await expect( page.locator( '.ssa-report' ) ).toContainText( '100/100' );
	await expect( page.getByRole( 'alert' ) ).toHaveCount( 0 );
	releaseAncillary();
	expect( ( await historyFailed ).status() ).toBe( 503 );
	expect( ( await scanLoaded ).status() ).toBe( 200 );
	await expect( page.getByRole( 'alert' ) ).toContainText(
		'History temporarily unavailable'
	);
	const reportText = await page.locator( '.ssa-report' ).innerText();
	expect( reportText ).toMatch( /Coverage:\s*100%\s*· Posture:\s*100\/100/ );
	expect( reportText ).not.toContain( 'Coverage: 100%%' );

	const historyFailedAgain = page.waitForResponse(
		( response ) =>
			new URL( response.url() ).pathname === `${ api }/scans` &&
			response.request().method() === 'GET'
	);
	await page.getByRole( 'button', { name: 'History', exact: true } ).click();
	expect( ( await historyFailedAgain ).status() ).toBe( 503 );
	await expect(
		page.getByText( 'Audit history could not be loaded.', { exact: true } )
	).toBeVisible();
	await expect(
		page.getByText( 'No audit history is available.', { exact: true } )
	).toHaveCount( 0 );
	await page.getByRole( 'button', { name: 'Settings', exact: true } ).click();
	await expect(
		page.getByText( 'Settings could not be loaded.', { exact: true } )
	).toBeVisible();
} );

test( 'empty history and unavailable assessments never imply a passing audit', async ( {
	page,
} ) => {
	await logIn( page );
	let scan: Record< string, unknown > | null = null;
	await page.route( `**${ api }/**`, async ( route ) => {
		const path = new URL( route.request().url() ).pathname.slice(
			api.length
		);
		if ( path === '/overview' ) {
			await route.fulfill( { json: { latest: scan } } );
		} else if ( path === '/scans' ) {
			await route.fulfill( {
				json: { items: scan ? [ scan ] : [], total: scan ? 1 : 0 },
			} );
		} else if ( path === '/scans/900001' ) {
			await route.fulfill( { json: scan } );
		} else if ( path === '/scans/900001/findings' ) {
			await route.fulfill( { json: { items: [], total: 0 } } );
		} else if ( path === '/scans/900002' ) {
			await route.fulfill( {
				status: 404,
				json: {
					code: 'ssa_not_found',
					message: 'Audit not found.',
					data: { status: 404 },
				},
			} );
		} else {
			await route.continue();
		}
	} );
	await page.goto( '/wp-admin/admin.php?page=site-security-auditor' );
	await expect(
		page.getByRole( 'heading', { name: 'No audits yet', exact: true } )
	).toBeVisible();
	await page.getByRole( 'button', { name: 'History', exact: true } ).click();
	await expect(
		page.getByText( 'No audit history is available.', { exact: true } )
	).toBeVisible();
	scan = {
		id: 900001,
		status: 'failed',
		checks: {},
		score: null,
		coverage: 0,
		started_at: '2026-11-10 08:00:00',
		completed_at: '2026-11-10 08:01:00',
	};
	await page.reload();
	await expect(
		page.getByRole( 'button', { name: 'Open report', exact: true } )
	).toBeDisabled();
	await page.getByRole( 'button', { name: 'Overview', exact: true } ).click();
	await expect(
		page
			.getByRole( 'region', { name: 'Latest audit summary' } )
			.getByText( 'Audit failed', { exact: true } )
	).toBeVisible();
	await expect(
		page.getByText( 'Not available', { exact: true } ).first()
	).toBeVisible();
	scan = {
		...scan,
		status: 'partial',
		checks: {
			'SSA-004': {
				check_id: 'SSA-004',
				status: 'unknown',
				reason: 'Provider unavailable.',
			},
		},
		coverage: 0,
	};
	await page.reload();
	await expect(
		page.getByText( 'Insufficient coverage', { exact: true } )
	).toBeVisible();
	await expect( page.getByText( /SSA-004 Not verified/ ) ).toBeVisible();
	await expect( page.getByRole( 'note' ) ).toContainText(
		'score is suppressed'
	);
	await page.goto(
		'/wp-admin/admin.php?page=site-security-auditor&view=report&scan=900002'
	);
	await expect( page.getByRole( 'alert' ) ).toHaveText( 'Audit not found.' );
	await expect(
		page.getByText( 'Loading the selected audit…', { exact: true } )
	).toHaveCount( 0 );
	await expect(
		page.getByRole( 'button', { name: 'Download JSON', exact: true } )
	).toHaveCount( 0 );
	await expect(
		page.getByRole( 'button', { name: 'Print / Save as PDF', exact: true } )
	).toHaveCount( 0 );
} );
test( 'all five audit views meet automated WCAG AA checks', async ( {
	page,
} ) => {
	test.setTimeout( 90000 );
	await logIn( page );
	for ( const view of [
		'overview',
		'findings',
		'history',
		'settings',
		'report',
	] ) {
		await page.goto(
			`/wp-admin/admin.php?page=site-security-auditor&view=${ view === 'report' ? 'history' : view }`
		);
		await expect(
			page.getByRole( 'heading', { name: 'Security Audit', exact: true } )
		).toBeVisible();
		if ( view === 'report' ) {
			await page
				.getByRole( 'button', { name: 'Open report', exact: true } )
				.and( page.locator( ':enabled' ) )
				.first()
				.click();
			await expect(
				page.getByRole( 'button', {
					name: 'Download JSON',
					exact: true,
				} )
			).toBeVisible();
		}
		await page.waitForLoadState( 'networkidle' );
		await page.addScriptTag( { content: axe.source } );
		const violations = await page.evaluate( async () => {
			const engine = ( window as unknown as { axe: typeof axe } ).axe;
			const results = await engine.run( '.ssa-app', {
				runOnly: {
					type: 'tag',
					values: [
						'wcag2a',
						'wcag2aa',
						'wcag21a',
						'wcag21aa',
						'wcag22aa',
					],
				},
			} );
			return results.violations.map( ( violation ) => ( {
				id: violation.id,
				impact: violation.impact,
				nodes: violation.nodes.map( ( node ) => ( {
					target: node.target,
					summary: node.failureSummary,
				} ) ),
			} ) );
		} );
		expect( violations, `${ view } accessibility violations` ).toEqual(
			[]
		);
	}
} );

async function logIn(
	page: import( '@playwright/test' ).Page
): Promise< void > {
	await page.goto( '/wp-login.php' );
	await page
		.locator( '#user_login' )
		.fill( process.env.WP_ADMIN_USER || 'admin' );
	await page
		.locator( '#user_pass' )
		.fill( process.env.WP_ADMIN_PASSWORD || 'password' );
	await page.locator( '#wp-submit' ).click();
	await expect( page ).toHaveURL( /wp-admin/ );
}

test( 'private audit data requires an administrator and write nonce', async ( {
	page,
	request,
} ) => {
	const anonymous = await request.get( `${ api }/overview` );
	expect( [ 401, 403 ] ).toContain( anonymous.status() );

	await logIn( page );
	await page.goto( '/wp-admin/admin.php?page=site-security-auditor' );
	const nonce = await page.evaluate(
		() =>
			( window as unknown as { ssaSettings: { nonce: string } } )
				.ssaSettings.nonce
	);
	const overview = await page.request.get( `${ api }/overview`, {
		headers: { 'X-WP-Nonce': nonce },
	} );
	expect( overview.status() ).toBe( 200 );

	const writeWithoutNonce = await page.request.post( `${ api }/settings`, {
		data: { vulnerability_intelligence: false },
	} );
	expect( writeWithoutNonce.status() ).toBe( 403 );
} );

test( 'administrator can open the real audit dashboard', async ( { page } ) => {
	await logIn( page );
	await page.goto( '/wp-admin/admin.php?page=site-security-auditor' );

	await expect(
		page.getByRole( 'heading', { name: 'Security Audit' } )
	).toBeVisible();
	await expect(
		page.getByRole( 'navigation', { name: 'Security audit views' } )
	).toBeVisible();
	await expect(
		page.getByRole( 'button', { name: /Run (another )?audit/ } )
	).toBeVisible();
} );

test( 'stored findings support keyboard details, filtering and selected exports', async ( {
	page,
} ) => {
	await logIn( page );
	await page.goto(
		'/wp-admin/admin.php?page=site-security-auditor&view=findings'
	);
	const details = page
		.getByRole( 'button', { name: 'View details', exact: true } )
		.first();
	await expect( details ).toBeVisible();
	await details.click();
	await expect(
		page.getByRole( 'heading', { name: 'Evidence', exact: true } )
	).toBeVisible();
	await page.keyboard.press( 'Escape' );
	await expect( details ).toBeFocused();
	await page
		.getByLabel( 'Search findings', { exact: true } )
		.fill( 'no-matching-fixture-18472' );
	await expect( page.getByText( /No findings match/ ) ).toBeVisible();
	await page.getByRole( 'button', { name: 'Reset filters' } ).click();
	await expect( details ).toBeVisible();
	await page.setViewportSize( { width: 360, height: 800 } );
	const bounds = await page.locator( '.ssa-app' ).boundingBox();
	expect( bounds!.x + bounds!.width ).toBeLessThanOrEqual( 361 );
	await page.screenshot( {
		path: '../artifacts/screenshots/findings-mobile.png',
		fullPage: true,
	} );
	await page.setViewportSize( { width: 1280, height: 900 } );
	await page.getByRole( 'button', { name: 'History', exact: true } ).click();
	await page
		.getByRole( 'button', {
			name: 'Open report',
			exact: true,
			disabled: false,
		} )
		.first()
		.click();
	const selectedId = Number(
		new URL( page.url() ).searchParams.get( 'scan' )
	);
	await expect(
		page.getByRole( 'button', { name: 'Download JSON' } )
	).toBeVisible();
	const downloaded = page.waitForEvent( 'download' );
	await page.getByRole( 'button', { name: 'Download JSON' } ).click();
	const download = await downloaded;
	const stream = await download.createReadStream();
	const chunks: Buffer[] = [];
	for await ( const chunk of stream! ) {
		chunks.push( Buffer.from( chunk ) );
	}
	expect( JSON.parse( Buffer.concat( chunks ).toString() ).scan.id ).toBe(
		selectedId
	);
	await page.emulateMedia( { media: 'print' } );
	await expect( page.locator( '.ssa-tabs' ) ).toBeHidden();
	expect(
		await page
			.locator( '.ssa-app' )
			.evaluate( ( el ) => getComputedStyle( el ).overflow )
	).toBe( 'visible' );
	const pdf = await page.pdf( {
		path: '../artifacts/screenshots/report.pdf',
		format: 'A4',
	} );
	expect(
		( pdf.toString( 'latin1' ).match( /\/Type\s*\/Page\b/g ) || [] ).length
	).toBeGreaterThan( 1 );
} );

test( 'findings remain readable at double text size on a narrow screen', async ( {
	page,
} ) => {
	await logIn( page );
	await page.goto(
		'/wp-admin/admin.php?page=site-security-auditor&view=findings'
	);
	await expect(
		page
			.getByRole( 'button', { name: 'View details', exact: true } )
			.first()
	).toBeVisible();
	await page.screenshot( {
		path: '../artifacts/screenshots/findings-desktop.png',
		fullPage: true,
	} );
	await page.setViewportSize( { width: 360, height: 800 } );
	await page.locator( '.ssa-app' ).evaluate( ( app ) => {
		// Double computed text sizes together to avoid compounding inherited sizes.
		const sizes = [ app, ...app.querySelectorAll( '*' ) ].map(
			( element ) => ( {
				element: element as HTMLElement,
				size: parseFloat( getComputedStyle( element ).fontSize ),
			} )
		);
		for ( const { element, size } of sizes ) {
			element.style.fontSize = `${ size * 2 }px`;
		}
	} );
	const dimensions = await page.locator( '.ssa-app' ).evaluate( ( app ) => ( {
		width: app.clientWidth,
		content: app.scrollWidth,
	} ) );
	await page.screenshot( {
		path: '../artifacts/screenshots/findings-text-zoom.png',
		fullPage: true,
	} );
	expect( dimensions.content ).toBeLessThanOrEqual( dimensions.width + 1 );
} );

test( 'failed consent save restores the stored value', async ( { page } ) => {
	await logIn( page );
	await page.goto(
		'/wp-admin/admin.php?page=site-security-auditor&view=settings'
	);
	const consent = page.getByRole( 'checkbox', {
		name: /Vulnerability intelligence/,
	} );
	await expect( consent ).not.toBeChecked();
	await page.route(
		/site-security-auditor\/v1\/settings(?:\?|$)/,
		async ( route ) => {
			if ( route.request().method() === 'POST' ) {
				await route.fulfill( {
					status: 503,
					contentType: 'application/json',
					body: JSON.stringify( {
						code: 'fixture',
						message: 'Simulated save failure',
					} ),
				} );
			} else {
				await route.continue();
			}
		}
	);
	await consent.check();
	await page
		.getByRole( 'button', { name: 'Save settings', exact: true } )
		.click();
	await expect( page.getByRole( 'alert' ) ).toContainText(
		'Simulated save failure'
	);
	await expect( consent ).not.toBeChecked();
} );

test( 'administrator can advance and cancel a real scan without automatic write requests', async ( {
	page,
} ) => {
	await logIn( page );
	let delayedInitialFindings = false;
	await page.route(
		/site-security-auditor\/v1\/scans\/\d+\/findings/,
		async ( route ) => {
			if ( ! delayedInitialFindings ) {
				delayedInitialFindings = true;
				await new Promise( ( resolve ) => setTimeout( resolve, 1500 ) );
			}
			await route.continue();
		}
	);
	await page.goto( '/wp-admin/admin.php?page=site-security-auditor' );
	const writes: string[] = [];
	page.on( 'request', ( request ) => {
		if ( request.method() === 'POST' && request.url().includes( api ) ) {
			writes.push( request.url() );
		}
	} );
	const started = page.waitForResponse(
		( response ) =>
			response.request().method() === 'POST' &&
			new URL( response.url() ).pathname === `${ api }/scans`
	);
	await page
		.getByRole( 'button', { name: 'Run another audit', exact: true } )
		.click();
	const scan = await ( await started ).json();
	expect( scan.status ).toBe( 'queued' );
	await expect(
		page.getByRole( 'heading', { name: 'Audit in progress', exact: true } )
	).toBeVisible();
	// A full polling interval must refresh state without advancing the scan by POST.
	await page.waitForTimeout( 6000 );
	expect(
		writes.filter( ( url ) => url.includes( '/advance' ) )
	).toHaveLength( 0 );
	const advanced = page.waitForResponse(
		( response ) =>
			response.request().method() === 'POST' &&
			response.url().includes( `/scans/${ scan.id }/advance` )
	);
	await page
		.getByRole( 'button', { name: 'Continue scan', exact: true } )
		.click();
	const progress = await ( await advanced ).json();
	expect( progress.id ).toBe( scan.id );
	expect( Object.keys( progress.checks ).length ).toBeGreaterThan( 0 );
	await page
		.getByRole( 'button', { name: 'Cancel audit', exact: true } )
		.click();
	const dialog = page.getByRole( 'dialog', { name: 'Cancel audit?' } );
	await expect( dialog ).toBeVisible();
	const cancelled = page.waitForResponse(
		( response ) =>
			response.request().method() === 'POST' &&
			response.url().includes( `/scans/${ scan.id }/cancel` )
	);
	await dialog
		.getByRole( 'button', { name: 'Cancel audit', exact: true } )
		.click();
	expect( ( await ( await cancelled ).json() ).status ).toBe( 'cancelled' );
	await expect(
		page.getByRole( 'heading', { name: 'Audit in progress', exact: true } )
	).toBeHidden();
	await expect(
		page.getByRole( 'button', { name: 'Run another audit', exact: true } )
	).toBeVisible();
	expect(
		writes.filter( ( url ) => url.includes( '/advance' ) )
	).toHaveLength( 1 );
	await page.getByRole( 'button', { name: 'History', exact: true } ).click();
	const cancelledRow = page
		.getByRole( 'row' )
		.filter( { has: page.getByText( 'Cancelled', { exact: true } ) } )
		.first();
	await expect(
		cancelledRow.getByRole( 'button', { name: 'Open report', exact: true } )
	).toBeDisabled();
} );

test( 'manual continuation completes all real checks when cron is delayed', async ( {
	page,
} ) => {
	test.setTimeout( 90000 );
	await logIn( page );
	await page.goto( '/wp-admin/admin.php?page=site-security-auditor' );
	const started = page.waitForResponse(
		( response ) =>
			response.request().method() === 'POST' &&
			new URL( response.url() ).pathname === `${ api }/scans`
	);
	await page
		.getByRole( 'button', { name: 'Run another audit', exact: true } )
		.click();
	let scan = await ( await started ).json();
	const id = scan.id;
	const nonce = await page.evaluate(
		() =>
			( window as unknown as { ssaSettings: { nonce: string } } )
				.ssaSettings.nonce
	);
	let advances = 0;
	for (
		let batch = 0;
		batch < 20 && [ 'queued', 'running' ].includes( scan.status );
		batch++
	) {
		const button = page.getByRole( 'button', {
			name: 'Continue scan',
			exact: true,
		} );
		try {
			await expect( button ).toBeEnabled();
		} catch ( error ) {
			// Cron may finish between an advance response and the refreshed UI.
			const response = await page.request.get( `${ api }/scans/${ id }`, {
				headers: { 'X-WP-Nonce': nonce },
			} );
			scan = await response.json();
			if ( ! [ 'completed', 'partial' ].includes( scan.status ) ) {
				throw error;
			}
			break;
		}
		const advanced = page.waitForResponse(
			( response ) =>
				response.request().method() === 'POST' &&
				response.url().includes( `/scans/${ id }/advance` )
		);
		await button.click();
		scan = await ( await advanced ).json();
		advances++;
		expect( scan.id ).toBe( id );
	}
	expect( advances ).toBeGreaterThan( 0 );
	expect( [ 'completed', 'partial' ] ).toContain( scan.status );
	expect( Object.keys( scan.checks ) ).toHaveLength( 16 );
	await expect(
		page.getByRole( 'heading', { name: 'Audit in progress', exact: true } )
	).toBeHidden();
	await expect(
		page.getByRole( 'button', { name: 'Run another audit', exact: true } )
	).toBeVisible();
} );

test( 'completed poll detail refreshes the findings for that scan', async ( {
	page,
} ) => {
	await logIn( page );
	await page.addInitScript( () => {
		const setInterval = window.setInterval.bind( window );
		window.setInterval = ( ( callback, delay, ...args ) =>
			setInterval(
				callback,
				delay === 5000 ? 50 : delay,
				...args
			) ) as typeof window.setInterval;
	} );
	const scan = ( status: string ) => ( {
		id: 900030,
		status,
		checks: {},
		score: status === 'completed' ? 100 : null,
		coverage: status === 'completed' ? 100 : 0,
		started_at: '2026-11-10 08:00:00',
		completed_at: status === 'completed' ? '2026-11-10 08:01:00' : null,
	} );
	let overviewCalls = 0;
	let detailCalls = 0;
	let findingsCalls = 0;
	await page.route( `**${ api }/**`, async ( route ) => {
		const path = new URL( route.request().url() ).pathname.slice(
			api.length
		);
		if ( path === '/overview' ) {
			overviewCalls++;
			await route.fulfill( {
				json: {
					latest: scan(
						overviewCalls >= 3 ? 'completed' : 'running'
					),
				},
			} );
		} else if ( path === '/scans' ) {
			await route.fulfill( { json: { items: [], total: 0 } } );
		} else if ( path === '/settings' ) {
			await route.fulfill( { json: {} } );
		} else if ( path === '/scans/900030' ) {
			detailCalls++;
			await route.fulfill( {
				json: scan( detailCalls >= 2 ? 'completed' : 'running' ),
			} );
		} else if ( path === '/scans/900030/findings' ) {
			findingsCalls++;
			await route.fulfill( {
				json: {
					items:
						findingsCalls >= 2
							? [
									{
										id: 'fresh-finding',
										scan_id: 900030,
										check_id: 'fresh',
										component_type: 'plugin',
										component_key: 'fresh',
										component_name: 'Fresh finding',
										component_version: '1.0',
										status: 'fail',
										severity: 'high',
										kind: 'security',
										title: 'Fresh completed finding',
										summary: 'Fresh',
										evidence: 'Fresh',
										remediation: [],
										references: [],
										checked_at: '2026-11-10 08:01:00',
										source: 'test',
										source_updated_at: null,
									},
								]
							: [],
					total: findingsCalls >= 2 ? 1 : 0,
				},
			} );
		} else {
			await route.continue();
		}
	} );
	await page.goto( '/wp-admin/admin.php?page=site-security-auditor' );
	await expect(
		page.getByText( 'Fresh completed finding', { exact: true } )
	).toBeVisible( { timeout: 10000 } );
	expect( overviewCalls ).toBeGreaterThanOrEqual( 3 );
	expect( detailCalls ).toBeGreaterThanOrEqual( 3 );
	expect( findingsCalls ).toBeGreaterThanOrEqual( 2 );
} );

test( 'history waits for its response and a successful poll clears its error', async ( {
	page,
} ) => {
	await logIn( page );
	await page.addInitScript( () => {
		const setInterval = window.setInterval.bind( window );
		window.setInterval = ( ( callback, delay, ...args ) =>
			setInterval(
				callback,
				delay === 5000 ? 50 : delay,
				...args
			) ) as typeof window.setInterval;
	} );
	const scan = {
		id: 900040,
		status: 'running',
		checks: {},
		score: null,
		coverage: 0,
		started_at: '2026-11-10 08:00:00',
		completed_at: null,
	};
	let releaseHistory!: () => void;
	const historyPending = new Promise< void >( ( resolve ) => {
		releaseHistory = resolve;
	} );
	let releasePoll!: () => void;
	const pollPending = new Promise< void >( ( resolve ) => {
		releasePoll = resolve;
	} );
	let overviewCalls = 0;
	await page.route( `**${ api }/**`, async ( route ) => {
		const path = new URL( route.request().url() ).pathname.slice(
			api.length
		);
		if ( path === '/overview' ) {
			overviewCalls++;
			if ( overviewCalls === 2 ) {
				await route.fulfill( {
					status: 503,
					contentType: 'application/json',
					body: JSON.stringify( {
						code: 'fixture',
						message: 'Temporary poll failure',
					} ),
				} );
			} else {
				if ( overviewCalls === 3 ) {
					await pollPending;
				}
				await route.fulfill( { json: { latest: scan } } );
			}
		} else if ( path === '/scans' ) {
			await historyPending;
			await route.fulfill( { json: { items: [], total: 0 } } );
		} else if ( path === '/settings' ) {
			await route.fulfill( { json: {} } );
		} else if ( path === '/scans/900040' ) {
			await route.fulfill( { json: scan } );
		} else if ( path === '/scans/900040/findings' ) {
			await route.fulfill( { json: { items: [], total: 0 } } );
		} else {
			await route.continue();
		}
	} );
	await page.goto(
		'/wp-admin/admin.php?page=site-security-auditor&view=history'
	);
	await expect(
		page.getByText( 'Loading audit history…', { exact: true } )
	).toBeVisible();
	await expect(
		page.getByText( 'No audit history is available.', { exact: true } )
	).toHaveCount( 0 );
	releaseHistory();
	await expect(
		page.getByText( 'No audit history is available.', { exact: true } )
	).toBeVisible();
	await expect( page.getByRole( 'alert' ) ).toHaveText(
		'Temporary poll failure'
	);
	releasePoll();
	await expect( page.getByRole( 'alert' ) ).toHaveCount( 0, {
		timeout: 10000,
	} );
} );
