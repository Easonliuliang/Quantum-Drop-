import { type ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { Header } from "./Header";
import type { Page } from "./types";

interface MainLayoutProps {
  currentPage: Page;
  onPageChange: (page: Page) => void;
  hasActiveTransfer: boolean;
  hasLogs: boolean;
  children: ReactNode;
}

export function MainLayout({
  currentPage,
  onPageChange,
  hasActiveTransfer,
  hasLogs,
  children,
}: MainLayoutProps) {
  return (
    <div className="app-layout">
      <Header />
      <div className="layout-body">
        <Sidebar
          currentPage={currentPage}
          onPageChange={onPageChange}
          hasActiveTransfer={hasActiveTransfer}
          hasLogs={hasLogs}
        />
        <main className="main-content" role="main">
          {children}
        </main>
      </div>
    </div>
  );
}
