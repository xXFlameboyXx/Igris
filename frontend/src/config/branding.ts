/**
 * IGRIS Branding Configuration (Single Source of Truth)
 *
 * Place the custom logo PNG at `frontend/public/assets/igris-logo.png`.
 * When present, the application will automatically display it.
 * If the PNG file is missing or fails to load, the UI gracefully renders
 * the stylized "IGRIS" fallback badge without any render errors.
 */

export const BRANDING = {
  appName: "IGRIS",
  appFullName: "IGRIS",
  tagline: "Explainable Malware Assessment & Analyst Platform",
  logoPath: "/assets/igris-logo.png",
  logoAlt: "IGRIS Forensics & Malware Intelligence",
  version: "v0.1.0",
  releasePhase: "Phase 12 Analyst Console",
} as const;
