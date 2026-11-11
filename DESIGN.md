# Site Security Auditor: UI and UX Design

**File:** `DESIGN.md`  
**Version:** 1.0  
**Source of truth for product behaviour:** `SPEC.md`  
**Delivery order:** Follow `PLAN.md`  
**Audience:** Codex implementing a real WordPress admin plugin, not a standalone SaaS mock-up.

## 1. Design objective

Create a modern, calm, credible WordPress security dashboard. It should feel as polished as a specialist cloud-security product while behaving properly inside wp-admin. Prioritise information hierarchy and audit evidence over visual effects. Use a subtle glass-inspired treatment for surfaces only where it improves clarity; no animated backgrounds, distracting gradients or meaningless metrics.

**Personality:** precise, trustworthy, understated and action-oriented.  
**User's first question:** “What should I fix first, and how confident is this result?”

## 2. Design rules

1. Use one WordPress top-level menu item, `Security Audit`, with the plugin icon. Do not replace or overlap the normal WordPress sidebar, toolbar or notices.
2. All custom CSS must be scoped under `.ssa-app`. Never restyle global `body`, WordPress nav menus, other plugins or the Gutenberg editor.
3. Support narrow WordPress admin layouts and 200% text zoom. No horizontal page overflow at 360px. Data tables may scroll inside an explicitly labelled container.
4. No fabricated real-time telemetry, geographic attack maps, risk trends, security badges or claims of continuous monitoring. Every value must come from a real stored scan.
5. Treat unknown data visibly. Use `Not checked` / `Unknown` labels rather than green success states.
6. No automated “Fix now” button in v1. Use `View remediation` and `Open relevant WordPress screen` where safe.
7. All critical actions require clear feedback and sensible disabled/loading states. Never mark a scan complete before backend confirms it.
8. WordPress admin navigation, keyboard shortcuts and common UI patterns take precedence over visual novelty.

## 3. Layout and responsive behaviour

```text
Existing WordPress admin sidebar | Plugin workspace (.ssa-app)
                               ┌──────────────────────────────────────┐
                               │ Security Audit       [Run audit]     │
                               │ Last completed: 02 Nov 2026         │
                               │ Overview Findings History Settings │
                               ├──────────────────────────────────────┤
                               │ [Posture] [Coverage] [Critical]      │
                               │ [High]                               │
                               ├──────────────────────────────────────┤
                               │ What needs attention                │
                               │ [Severity] Finding       [Details]  │
                               │ [Severity] Finding       [Details]  │
                               ├──────────────────────────────────────┤
                               │ Audit scope and confidence          │
                               │ Local / Feed / Integrity status     │
                               └──────────────────────────────────────┘
```

- Desktop (>=1200px workspace): max content width 1380px; 24px workspace padding; 12-column conceptual grid; metrics in a responsive 4-column row when space permits.
- Tablet (~768px to 1199px): 16px padding; two metric columns; tab navigation may wrap if required.
- Mobile (<768px): 12px padding, single-column content, vertically stacked actions, full-width scan button, collapsible finding details and scrollable table within its own region.
- Account for WordPress sidebar width automatically by taking the *available content area*, not assuming full viewport width. Prefer CSS container queries / flex wrap where supported, with graceful fallbacks.
- Minimum interactive hit target 44px when practicable; preserve visible keyboard focus.

## 4. Visual tokens

Use CSS custom properties on `.ssa-app` to keep implementation consistent. These are design targets; verify real contrast ratios rather than assuming values pass WCAG.

| Token | Light mode | Usage |
|---|---|---|
| `--ssa-canvas` | `#F5F7FA` | Workspace background |
| `--ssa-panel` | `#FFFFFF` | Card backgrounds |
| `--ssa-panel-soft` | `#F9FBFD` | Muted sections |
| `--ssa-ink` | `#182335` | Primary copy |
| `--ssa-muted` | `#536176` | Secondary text |
| `--ssa-border` | `#DDE4ED` | Separators and borders |
| `--ssa-brand` | `#3157D5` | Primary actions |
| `--ssa-brand-hover` | `#2545AD` | Hover/active action |
| `--ssa-success` | `#18794E` | Verified passes |
| `--ssa-critical` | `#A61B29` | Critical findings |
| `--ssa-high` | `#B44D12` | High findings |
| `--ssa-medium` | `#8A660C` | Medium findings |
| `--ssa-unknown` | `#52657D` | Unknown and not assessed |
| `--ssa-radius` | `14px` | Card corners |
| `--ssa-shadow` | `0 8px 28px rgba(30,42,62,.06)` | Subtle elevation |

**Typography:** inherit WordPress's system font stack. Page heading 26-30px semibold; section heading 18-20px; body 14-16px; metadata 12-13px and never below 12px for essential content. Use tabular numerals for scores and counts. Colour is never the only severity cue: use text labels and icons.

**Surfaces:** white or subtly translucent cards (`rgba(255,255,255,.88)`) with a 1px border. Backdrop blur only as progressive enhancement on modern browsers. No strong glass effects under dense tables or long text.

**Dark mode:** do not implement a custom toggle in v1. Keep the light workspace consistent with standard wp-admin; use well-defined token boundaries to enable future theme support without rewriting components.

**Motion:** 120-180ms simple opacity/background transitions; honour `prefers-reduced-motion: reduce`; no bouncing counters, infinite spinners beyond genuine pending states or animated decorative charts.

## 5. Navigation architecture

Top-level menu: `Security Audit`.

Within the workspace, provide four primary tabs and one report subview:

- **Overview**: `/wp-admin/admin.php?page=site-security-auditor` (default).
- **Findings**: `...?page=site-security-auditor&view=findings`.
- **History**: `...?page=site-security-auditor&view=history`.
- **Settings**: `...?page=site-security-auditor&view=settings`.
- **Report**: `...?page=site-security-auditor&view=report&scan=<id>` (access controlled by REST and PHP page capability).

All links stay on the registered admin page. Avoid arbitrary URL navigation and avoid public-facing routes for private scan data. Reflect tab selection in the URL so reloads and deep links work.

## 6. Overview wireframe and behaviour

```text
Security Audit                                   [ Run audit ]
Know what was checked, why it matters and what to do.

[Posture indicator]  [Coverage: 12/14]  [Critical: 0]  [High: 2]

Prioritised findings                          [View all findings]
  HIGH  An installed plugin has an advisory     [View details]
  MED   WordPress core update available         [View details]

Coverage and confidence
  Local checks                 10 checked / 1 unknown
  Vulnerability intelligence   Not enabled [Configure]
  Core integrity               Completed / Unknown / Not enabled

Last audits                                  [History]
  Scan date    State      Posture       Coverage

Scope note: This is a limited security posture audit, not a malware scan.
```

- When no audit exists, show a helpful empty state with one prominent Run audit CTA, explanation of what will happen and direct link to consent settings.
- If coverage under 70%, replace the score with `Insufficient coverage`, with a tooltip-like inline explanation and a coverage metric.
- Show numeric metric only if derived from a completed/partial scan; never use placeholder numbers outside explicit demo/test fixtures.
- Order findings by critical, high, medium, low, unrated, info, then newest verified. Provide a clearly labelled `Unknown checks` area.
- Scanning state includes last completed stage, remaining work and timestamp. If background execution stalls, offer `Continue scan` to authorised users.
- Show `Run another audit` only when an existing scan is finished or cancelled. Active scan prevents duplicate starts.

## 7. Findings view

Toolbar: search field (title / component name), severity select, status select, category select, result count and Reset filters.

List/table columns on desktop: severity, finding/check, component, state, verified time and `View details`. On narrow screens, render rows as accessible stacked cards without cutting off labels.

Detail panel includes:

1. Severity and precise classification: `Known vulnerability`, `Configuration risk`, `Hardening advice`, `Integrity difference` or `Unverified`.
2. Plain-language summary and why it matters.
3. **Evidence**: the actual observed setting, installed version or advisory match. Truncate very long text with Expand control; never show secrets or raw absolute filesystem paths.
4. **How to address it**: ordered steps with notes on backup or compatibility impact.
5. **Verification**: check name, source, lookup/check time, provider status and relevant links.
6. **Limitations**: especially for checks such as `FORCE_SSL_ADMIN`, checksum mismatches and optional feeds.

Use a side panel on wide screens and a full-width modal/page on narrow screens. Close with Escape, return focus to the triggering control and provide a visible close button. If robust focus trapping is not implemented, use a routed full-page detail instead of a broken modal.

## 8. History and comparison

History uses a table with date, `Completed`/`Partial`/`Failed`/`Cancelled`, score or insufficient-coverage label, coverage, checked count and `Open report`.

Compare the two most recent useful scans by stable identities. Show each comparison with `New`, `Still present`, `Resolved` or `Not evaluated`; never say `Resolved` if the relevant check is unknown. If no comparable scan exists, explain why rather than displaying an empty chart.

Do not use a trend chart in v1. Two points of data do not create a useful long-term risk trend.

## 9. Report and printing

Report header:

```text
SITE SECURITY AUDIT
Example Site (example.com)
Audit: 02 November 2026, 14:00 UTC
Status: Completed | Checks assessed: 12 of 14 | Posture: 76/100

Findings by severity
Evidence and remediation for each issue
Unknown or excluded checks
Methodology, data sources, score explanation and limitations
```

- Client-side print stylesheet via `@media print` hides wp-admin chrome, nav, action controls, purely decorative cards, buttons and filters.
- Include page breaks between logical report sections and repeat essential table headings where feasible.
- Exports must use the selected stored scan, not current live readings. Use consistent timestamps (UTC with optional user's local display, explicitly labelled).
- Use `window.print()` from a user action to enable **Print / Save as PDF**. Do not include a non-functional Download PDF button.
- CSV: UTF-8 with correct escaping and spreadsheet formula-injection mitigation for untrusted strings beginning with `=`, `+`, `-`, `@` or leading control characters. JSON: stable documented keys and safe bounded payloads.
- Report footer: “This audit checks selected WordPress configuration and vulnerability indicators. It does not establish that the site is secure or free from compromise.”

## 10. Settings and consent UX

Use simple checkboxes with clear explanatory text and persisted state:

**Vulnerability intelligence: Off by default**  
“When enabled, the plugin sends plugin and theme slugs and the WordPress core version to WPVulnerability to check for published advisories. Installed plugin and theme versions are compared locally. That provider may see the requesting server IP. No user lists, authentication secrets or full site URL are sent.”  
Link to the provider's documentation and privacy information where available.

**Core integrity lookup: Off by default**  
“When enabled, the plugin requests official file checksums from WordPress.org using the site's WordPress version and locale, then compares local core files in bounded batches.”

**Weekly scheduled audit: Off by default**  
“WordPress scheduled tasks depend on site traffic or server cron. Results may be delayed on low-traffic sites. Optional network checks are only run if enabled above.”

Save settings explicitly, confirm success accessibly and ensure opt-out is immediate for new work. Do not bundle consent into an ambiguous single checkbox. Provide a note explaining current data retention and uninstall deletion.

## 11. Status component language

| State | Visible label | Colour treatment | Explanation |
|---|---|---|---|
| `pass` | Passed | green text and check icon | Observed state meets this check |
| `fail` | Action needed | red/orange depending severity | Finding backed by evidence |
| `unknown` | Not verified | neutral grey/blue with question icon | Could not establish state |
| `not_applicable` | Not applicable | subdued neutral | Check does not apply |
| `queued` | Queued | neutral | Waiting for worker |
| `running` | Running | blue + optional progress | Worker active or scheduled |
| `partial` | Partial audit | amber | Some checks unavailable |
| `failed` | Audit failed | red | No reliable overall result |
| `cancelled` | Cancelled | neutral | Stopped by administrator |

Don't use success colour for a successfully completed scan that contains critical failures. Scan processing state and security finding state are different dimensions.

## 12. UI components and boundaries

Recommended React component tree:

```text
AdminApp
  AppShell
    PageHeading + NavigationTabs
    GlobalNoticeArea
    OverviewPage
      ScanAction
      PostureCard
      CoverageCard
      SeverityMetrics
      PriorityFindings
      AuditScope
    FindingsPage
      FindingFilters
      FindingsTable / MobileCards
      FindingDetailPanel
    HistoryPage
      ScanHistoryList
      ComparisonList
    ReportPage
      ReportHeader
      FindingsSections
      MethodologyFooter
      PrintControls
    SettingsPage
      ConsentSettings
      ScheduleSettings
```

- Prefer WordPress-provided React packages, UI components and icons. Define presentational components separately from data hooks and API calls.
- Use an accessible live region for scan updates (`aria-live="polite"`) and blocking errors (`role="alert"`). Avoid repeated noisy screen-reader announcements while polling.
- Date formatting uses WordPress locale/time settings where available and explicit UTC in raw exports.
- Show a confirmation dialog before cancelling a running scan and clear success/error feedback after saving consent.
- Keep visual and function tests alongside each feature.

## 13. Interaction states to implement and test

| Screen | Required cases |
|---|---|
| Overview | first use, no scan, queued, running, completed clean, completed with findings, partial, failed, insufficient coverage |
| Findings | no findings, filtered empty, many findings, long title, unknown evidence, provider outage, mobile layout |
| History | zero scans, one scan, comparison, expired history, missing scan |
| Report | print preview, blocked unauthorised request, special characters in evidence, CSV injection input |
| Settings | off by default, opt-in, saving, error, opt-out, disabled scheduled task |
| General | keyboard-only, screen reader landmarks, 200% zoom, reduced motion, slow REST request, expired nonce |

## 14. Accessibility criteria

Meet WCAG 2.2 AA where feasible for implemented controls and content. At minimum: semantic headings, labels, clear link purpose, keyboard reachability, visible focus, accessible errors, no colour-only status, contrast checks for critical/body text, logical tab order and no keyboard trap. Use automated accessibility checks plus manual keyboard review. Use native controls when they are simpler and more reliable than custom widgets.

## 15. Assets and delivery expectations

No remote fonts, CDN images, remote scripts or large animation libraries. Build CSS/JS locally and enqueue only on the plugin's own wp-admin page. Include the WordPress build dependency metadata. A local SVG icon is optional if sanitised and bundled. No external design images are required for v1.

The delivered dashboard must use actual backend scan data. Static seeded demo data may exist **only** in test fixtures or an explicitly labelled development-only mock mode that is absent from the release ZIP.
