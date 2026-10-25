import React, { useState } from 'react';
import { X, Lock, Mail, User as UserIcon, Shield, AlertCircle } from 'lucide-react';
import { api } from '../services/api';
import type { User, SystemRole } from '../types';

interface AuthModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (user: User) => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [role, setRole] = useState<SystemRole>('SECURITY_TESTER');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (isLogin) {
        const res = await api.login({ email, password });
        onSuccess(res.user);
      } else {
        await api.register({
          email,
          password,
          full_name: fullName,
          system_role: role,
        });
        // Auto-login after registration
        const res = await api.login({ email, password });
        onSuccess(res.user);
      }
      onClose();
    } catch (err: any) {
      setError(err.message || 'Authentication failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-md bg-cyber-850 border border-cyber-700 rounded-xl shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-150">
        <div className="p-5 border-b border-cyber-750 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-accent-cyan" />
            <h3 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
              {isLogin ? 'Control Plane Authentication' : 'Create Operator Account'}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white p-1 rounded-lg hover:bg-cyber-750 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {error && (
            <div className="flex items-center gap-2 p-3 bg-rose-500/10 border border-rose-500/20 rounded-lg text-xs text-rose-300">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {!isLogin && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Full Name</label>
              <div className="relative">
                <UserIcon className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                <input
                  type="text"
                  required
                  value={fullName}
                  onChange={(e) => setFullName(e.target.value)}
                  placeholder="Security Specialist Name"
                  className="w-full bg-cyber-900 border border-cyber-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
                />
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Work Email</label>
            <div className="relative">
              <Mail className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="analyst@sec.corp"
                className="w-full bg-cyber-900 border border-cyber-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Password</label>
            <div className="relative">
              <Lock className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
              <input
                type="password"
                required
                minLength={8}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••"
                className="w-full bg-cyber-900 border border-cyber-700 rounded-lg pl-9 pr-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-accent-cyan"
              />
            </div>
          </div>

          {!isLogin && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">System Role</label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as SystemRole)}
                className="w-full bg-cyber-900 border border-cyber-700 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-accent-cyan font-mono"
              >
                <option value="SECURITY_TESTER">SECURITY_TESTER (Standard Operator)</option>
                <option value="SECURITY_LEAD">SECURITY_LEAD (Scope Approver)</option>
                <option value="AUDITOR">AUDITOR (Read-only Compliance)</option>
                <option value="ADMIN">ADMIN (Full Platform Authority)</option>
              </select>
              <p className="text-[10px] text-slate-500 mt-1">
                Note: In a fresh database, the first user registered is automatically granted ADMIN privileges.
              </p>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 px-4 bg-accent-blue hover:bg-accent-blue/90 disabled:bg-cyber-750 text-white font-semibold text-xs rounded-lg transition-colors shadow-sm"
          >
            {loading ? 'Authenticating...' : isLogin ? 'Sign In to Control Plane' : 'Register Operator'}
          </button>
        </form>

        <div className="p-4 bg-cyber-900/60 border-t border-cyber-750/70 text-center">
          <button
            onClick={() => {
              setIsLogin(!isLogin);
              setError(null);
            }}
            className="text-xs text-accent-cyan hover:underline"
          >
            {isLogin ? "Don't have an operator account? Register" : 'Already registered? Sign In'}
          </button>
        </div>
      </div>
    </div>
  );
};
