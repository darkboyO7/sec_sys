/**
 * Frontend Environment Configuration & Safe Profile Introspection (Prompt 49).
 * Defines client-side environment settings, validates API URLs, and prevents
 * accidental leakage or bundling of backend secrets.
 */

export type AppProfile = 'development' | 'testing' | 'staging' | 'production';

export interface FrontendEnvironmentConfig {
  profile: AppProfile;
  apiBaseUrl: string;
  isProduction: boolean;
  isStaging: boolean;
  isDevelopment: boolean;
  isTesting: boolean;
  features: {
    debugPanel: boolean;
    mockDataShortcuts: boolean;
    detailedErrorDetails: boolean;
  };
}

export function getFrontendEnvironment(): FrontendEnvironmentConfig {
  const envObj = (typeof import.meta !== 'undefined' && import.meta.env) ? import.meta.env : {} as Record<string, any>;
  const rawProfile = (envObj.VITE_APP_PROFILE || envObj.MODE || 'development').toLowerCase().trim();

  let profile: AppProfile = 'development';
  if (rawProfile === 'production') profile = 'production';
  else if (rawProfile === 'staging') profile = 'staging';
  else if (rawProfile === 'testing' || rawProfile === 'test') profile = 'testing';
  else profile = 'development';

  const isProduction = profile === 'production';
  const isStaging = profile === 'staging';
  const isDevelopment = profile === 'development';
  const isTesting = profile === 'testing';

  // API Base URL resolution:
  let apiBaseUrl = (envObj.VITE_API_URL || '/api/v1').trim();

  // Guard: In production, disallow localhost or 127.0.0.1 API endpoints
  if (isProduction && (apiBaseUrl.includes('localhost') || apiBaseUrl.includes('127.0.0.1'))) {
    console.warn('[SECURITY] Production profile cannot use localhost API base URL. Falling back to relative /api/v1.');
    apiBaseUrl = '/api/v1';
  }

  return {
    profile,
    apiBaseUrl,
    isProduction,
    isStaging,
    isDevelopment,
    isTesting,
    features: {
      debugPanel: isDevelopment || isTesting,
      mockDataShortcuts: isDevelopment || isTesting,
      detailedErrorDetails: isDevelopment || isTesting,
    },
  };
}

export const envConfig = getFrontendEnvironment();
