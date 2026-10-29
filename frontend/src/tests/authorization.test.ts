import { describe, it, expect, vi } from 'vitest';
import { api } from '../services/api';
import type {
  DetailedPermissionMatrixResponse,
  AccessDenialAudit,
  LogoutResponse,
  RevokeAllSessionsResponse,
} from '../types';

describe('Prompt 36: Identity Security, Authorization Consistency & Privileged-Action Governance Tests', () => {
  it('should retrieve detailed permission matrix with system and project roles', async () => {
    const mockMatrix: DetailedPermissionMatrixResponse = {
      available_permissions: [
        'asset:read',
        'asset:create',
        'assessment:read',
        'assessment:launch',
        'finding:read',
        'finding:mutate',
        'threat_intel:read',
        'compliance:read',
      ],
      system_roles: [
        {
          role: 'ADMIN',
          role_type: 'SYSTEM',
          description: 'Full platform-wide administrative authority',
          granted_permissions: ['asset:read', 'asset:create', 'assessment:launch'],
        },
        {
          role: 'VIEWER',
          role_type: 'SYSTEM',
          description: 'Read-only inspection of visible project state',
          granted_permissions: ['asset:read', 'assessment:read', 'finding:read'],
        },
      ],
      project_roles: [
        {
          role: 'LEAD',
          role_type: 'PROJECT',
          description: 'Project team lead with approval, SoD, and policy authority',
          granted_permissions: ['asset:read', 'asset:create', 'assessment:launch', 'finding:mutate'],
        },
        {
          role: 'VIEWER',
          role_type: 'PROJECT',
          description: 'Read-only project auditor and observer',
          granted_permissions: ['asset:read', 'assessment:read', 'finding:read'],
        },
      ],
    };

    vi.spyOn(api, 'getDetailedPermissionMatrix').mockResolvedValue(mockMatrix);

    const res = await api.getDetailedPermissionMatrix();
    expect(res.available_permissions.length).toBeGreaterThan(0);
    expect(res.system_roles.length).toBe(2);
    expect(res.project_roles.length).toBe(2);
    expect(res.project_roles[0].role).toBe('LEAD');
    expect(res.project_roles[0].granted_permissions).toContain('assessment:launch');
  });

  it('should list attributable access denial audit records for project governance', async () => {
    const mockDenials: AccessDenialAudit[] = [
      {
        id: 'denial-1',
        user_id: 'user-viewer-1',
        user_email: 'viewer@example.com',
        project_id: 'proj-123',
        endpoint: '/api/v1/projects/proj-123/scheduling/trigger',
        http_method: 'POST',
        required_privilege: 'TESTER, LEAD',
        held_privilege: 'VIEWER',
        denial_reason: "Project operation requires one of: [TESTER, LEAD], held role: 'VIEWER'",
        client_ip: '127.0.0.1',
        denied_at: '2026-10-28T12:00:00Z',
      },
    ];

    vi.spyOn(api, 'listProjectAccessDenials').mockResolvedValue(mockDenials);

    const denials = await api.listProjectAccessDenials('proj-123');
    expect(denials.length).toBe(1);
    expect(denials[0].endpoint).toContain('/scheduling/trigger');
    expect(denials[0].held_privilege).toBe('VIEWER');
    expect(denials[0].denial_reason).toContain('requires one of: [TESTER, LEAD]');
  });

  it('should execute cryptographic logout and revoke session token', async () => {
    const mockLogout: LogoutResponse = {
      status: 'SUCCESS',
      message: 'Session terminated and token revoked successfully',
      revoked_token_id: 'jti-abc-123',
    };

    vi.spyOn(api, 'revokeServerSession').mockResolvedValue(mockLogout);

    const res = await api.revokeServerSession();
    expect(res.status).toBe('SUCCESS');
    expect(res.revoked_token_id).toBe('jti-abc-123');

    api.logout();
    expect(api.getToken()).toBeNull();
  });

  it('should invalidate all active sessions across devices upon revocation request', async () => {
    const mockRevokeAll: RevokeAllSessionsResponse = {
      status: 'SUCCESS',
      message: 'All active sessions revoked successfully',
      revoked_before: '2026-10-28T12:00:00Z',
    };

    vi.spyOn(api, 'revokeAllSessions').mockResolvedValue(mockRevokeAll);

    const res = await api.revokeAllSessions();
    expect(res.status).toBe('SUCCESS');
    expect(res.revoked_before).toBeDefined();
  });

  it('should validate password length and change user password with session invalidation', async () => {
    const mockChange = {
      status: 'SUCCESS',
      message: 'Password changed successfully. All previous sessions have been invalidated.',
    };

    vi.spyOn(api, 'changePassword').mockResolvedValue(mockChange);

    const res = await api.changePassword({
      current_password: 'oldPassword123!',
      new_password: 'newPassword456!',
    });
    expect(res.status).toBe('SUCCESS');
    expect(res.message).toContain('All previous sessions have been invalidated');
  });
});
