import React from "react";
import { Shell } from "./components/layout/Shell";
import { ErrorBoundary } from "./components/common/ErrorBoundary";

export default function App() {
  return (
    <ErrorBoundary level="global">
      <Shell />
    </ErrorBoundary>
  );
}

