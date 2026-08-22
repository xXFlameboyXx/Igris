import React, { useState } from "react";
import { BRANDING } from "../../config/branding";

interface BrandLogoProps {
  size?: "sm" | "md" | "lg";
  showText?: boolean;
  className?: string;
}

/**
 * BrandLogo component that displays the configured PNG logo if available
 * (from `frontend/public/assets/igris-logo.png`) or gracefully falls back to
 * a stylized crimson cybersecurity "IGRIS" typographic badge if missing.
 */
export function BrandLogo({
  size = "md",
  showText = false,
  className = "",
}: BrandLogoProps) {
  const [imageError, setImageError] = useState(false);

  const sizeClasses = {
    sm: "brand-logo-sm",
    md: "brand-logo-md",
    lg: "brand-logo-lg",
  };

  return (
    <div className={`brand-logo-container ${sizeClasses[size]} ${className}`} aria-label={BRANDING.appName}>
      {!imageError ? (
        <img
          src={BRANDING.logoPath}
          alt={BRANDING.logoAlt}
          className="brand-logo-img"
          onError={() => setImageError(true)}
          loading="eager"
        />
      ) : (
        <div className="brand-logo-fallback" title={BRANDING.appFullName}>
          <span className="brand-logo-monogram">IG</span>
        </div>
      )}

      {showText && (
        <div className="brand-text-lockup">
          <span className="brand-text-name">{BRANDING.appName}</span>
          <span className="brand-text-tagline">{BRANDING.tagline}</span>
        </div>
      )}
    </div>
  );
}
