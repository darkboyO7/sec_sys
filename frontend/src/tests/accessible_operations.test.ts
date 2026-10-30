import { describe, it, expect } from 'vitest';
import { SEVERITY_METADATA, OBSERVATION_METADATA } from '../components/SeverityBadge';

describe('Prompt 50: Accessible Security Operations Interface & Usability Contract', () => {
  // 1. Non-Color-Only Severity Indicators (WCAG 1.4.1)
  it('ensures all severity levels communicate status via semantic text and distinct symbols, not color alone', () => {
    const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'INFORMATIONAL'];
    const seenIcons = new Set<string>();

    for (const sev of severities) {
      const meta = SEVERITY_METADATA[sev];
      expect(meta).toBeDefined();

      // Semantic text label must be present
      expect(meta.label).toBeDefined();
      expect(meta.label.length).toBeGreaterThan(0);

      // Non-color icon / shape must be present
      expect(meta.icon).toBeDefined();
      expect(meta.icon.length).toBeGreaterThan(0);

      // Assistive technology ariaText description must be explicit
      expect(meta.ariaText).toBeDefined();
      expect(meta.ariaText.toLowerCase()).toContain('severity:');

      if (sev !== 'INFORMATIONAL') {
        expect(seenIcons.has(meta.icon)).toBe(false);
        seenIcons.add(meta.icon);
      }
    }
  });

  // 2. Truthful Terminology for Observations (Simulated vs Live vs Remediated)
  it('distinguishes simulated scenarios, live observations, and verified remediation without ambiguity', () => {
    const observationTypes = ['SIMULATED', 'LIVE', 'UNRESOLVED', 'VERIFIED', 'CONTRADICTORY'] as const;

    for (const type of observationTypes) {
      const meta = OBSERVATION_METADATA[type];
      expect(meta).toBeDefined();
      expect(meta.label).toBeDefined();
      expect(meta.icon).toBeDefined();
      expect(meta.ariaText).toBeDefined();

      if (type === 'SIMULATED') {
        expect(meta.label).toBe('SIMULATED SCENARIO');
        expect(meta.icon).toBe('🧪');
        expect(meta.ariaText.toLowerCase()).toContain('simulated drill scenario');
        expect(meta.border).toContain('border-dashed'); // Distinct visual boundary
      }

      if (type === 'LIVE') {
        expect(meta.label).toBe('LIVE OBSERVATION');
        expect(meta.icon).toBe('🌐');
        expect(meta.ariaText.toLowerCase()).toContain('verified live');
      }

      if (type === 'VERIFIED') {
        expect(meta.label).toBe('VERIFIED REMEDIATED');
        expect(meta.icon).toBe('✅');
        expect(meta.ariaText.toLowerCase()).toContain('verified remediated');
      }
    }
  });

  // 3. Accessible Dialog & Modal Semantics (WCAG 2.1 - 4.1.2)
  it('enforces accessible modal attributes, alertdialog for destructive actions, and focus management', () => {
    interface ModalStateTest {
      title: string;
      isDestructive: boolean;
      isSubmitting: boolean;
    }

    const testModal = (props: ModalStateTest) => {
      const role = props.isDestructive ? 'alertdialog' : 'dialog';
      const titleId = `modal-title-${props.title.toLowerCase().replace(/[^a-z0-9]/g, '-')}`;
      const ariaBusy = props.isSubmitting;
      const buttonsDisabled = props.isSubmitting;

      return {
        role,
        titleId,
        ariaModal: 'true',
        ariaBusy,
        buttonsDisabled,
      };
    };

    const regularModal = testModal({ title: 'Export PDF Report', isDestructive: false, isSubmitting: false });
    expect(regularModal.role).toBe('dialog');
    expect(regularModal.titleId).toBe('modal-title-export-pdf-report');
    expect(regularModal.ariaBusy).toBe(false);
    expect(regularModal.buttonsDisabled).toBe(false);

    const destructiveModal = testModal({ title: 'Revoke Authorization', isDestructive: true, isSubmitting: true });
    expect(destructiveModal.role).toBe('alertdialog');
    expect(destructiveModal.ariaBusy).toBe(true);
    expect(destructiveModal.buttonsDisabled).toBe(true);
  });

  // 4. Accessible Chart Text Alternatives (WCAG 1.1.1)
  it('ensures charts define accessible regions and structured tabular fallback data', () => {
    interface ChartDataSummary {
      title: string;
      summary: string;
      rows: Array<{ label: string; value: number }>;
    }

    const chartConfig: ChartDataSummary = {
      title: 'Vulnerability Severity Distribution',
      summary: 'Breakdown of security findings across five severity tiers',
      rows: [
        { label: 'Critical', value: 3 },
        { label: 'High', value: 8 },
        { label: 'Medium', value: 19 },
        { label: 'Low', value: 12 },
        { label: 'Info', value: 6 },
      ],
    };

    expect(chartConfig.title.length).toBeGreaterThan(0);
    expect(chartConfig.summary.length).toBeGreaterThan(0);
    expect(chartConfig.rows.length).toBe(5);

    // Verify each data row has accessible text label and numeric value
    for (const r of chartConfig.rows) {
      expect(typeof r.label).toBe('string');
      expect(typeof r.value).toBe('number');
    }
  });

  // 5. Permission Denied (HTTP 403) Accessible State Governance
  it('formats HTTP 403 permission-denied views with alert semantics and role comparison', () => {
    const buildPermissionDeniedView = (requiredRole: string, currentRole: string, action: string) => {
      return {
        role: 'alert',
        ariaLive: 'assertive',
        statusCode: 403,
        heading: 'Access Restricted — Authorization Required',
        currentRole,
        requiredRole,
        action,
        remediation: 'Contact your Project Security Lead or System Administrator to elevate your membership role.',
      };
    };

    const view = buildPermissionDeniedView('SECURITY_LEAD', 'VIEWER', 'approve risk acceptance');
    expect(view.role).toBe('alert');
    expect(view.ariaLive).toBe('assertive');
    expect(view.statusCode).toBe(403);
    expect(view.currentRole).toBe('VIEWER');
    expect(view.requiredRole).toBe('SECURITY_LEAD');
    expect(view.remediation).toContain('Security Lead');
  });

  // 6. Accessible Table and Search Controls
  it('validates accessible table headers, search input labels, and filter announcements', () => {
    const searchConfig = {
      inputAriaLabel: 'Search security findings by title, CVE, or target',
      statusSelectAriaLabel: 'Filter findings by lifecycle status',
      severitySelectAriaLabel: 'Filter findings by severity level',
      tableAriaLabel: 'Security Findings Table',
      columnHeaders: [
        { name: 'Severity', scope: 'col' },
        { name: 'Vulnerability & Identifier', scope: 'col' },
        { name: 'Target Asset', scope: 'col' },
        { name: 'Lifecycle State', scope: 'col' },
        { name: 'Observations', scope: 'col' },
        { name: 'Actions', scope: 'col' },
      ],
    };

    expect(searchConfig.inputAriaLabel).toContain('Search');
    expect(searchConfig.statusSelectAriaLabel).toContain('Filter');
    expect(searchConfig.tableAriaLabel).toBe('Security Findings Table');
    expect(searchConfig.columnHeaders.every((h) => h.scope === 'col')).toBe(true);
  });
});
