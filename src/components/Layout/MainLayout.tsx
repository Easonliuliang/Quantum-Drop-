import { type ReactNode } from "react";
import { TopNav } from "./TopNav";
import type { Page } from "./types";

interface MainLayoutProps {
  currentPage: Page;
  onPageChange: (page: Page) => void;
  children: ReactNode;
}

export function MainLayout({
  currentPage,
  onPageChange,
  children,
}: MainLayoutProps) {
  return (
    <div className="app-layout">
      <header className="app-header">
        <TopNav currentPage={currentPage} onPageChange={onPageChange} />
      </header>
      <main className="main-content" role="main">
        {children}
      </main>
    </div>
  );
}
