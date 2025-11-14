import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { I18nProvider } from "./lib/i18n";

const container = document.getElementById("root");

if (!container) {
  throw new Error("Unable to find root mount node.");
}

ReactDOM.createRoot(container).render(
  <React.StrictMode>
    <I18nProvider>
      <ErrorBoundary>
        <App />
      </ErrorBoundary>
    </I18nProvider>
  </React.StrictMode>
);
