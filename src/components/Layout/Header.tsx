import { LocaleSwitch } from "../LocaleSwitch";

interface HeaderProps {
  title?: string;
}

export function Header({ title = "时光穿梭机" }: HeaderProps) {
  return (
    <header className="app-header">
      <div className="header-left">
        <h1 className="app-title">{title}</h1>
      </div>
      <div className="header-right">
        <LocaleSwitch />
      </div>
    </header>
  );
}
