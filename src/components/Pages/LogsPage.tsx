type LogEntry = {
  id: string;
  message: string;
  count: number;
  timestamp: number;
};

interface LogsPageProps {
  logs: LogEntry[];
}

export function LogsPage({ logs }: LogsPageProps) {
  return (
    <div className="logs-page">
      <div className="log-panel" aria-live="off">
        <h3>事件流</h3>
        <ul>
          {logs.map((entry) => (
            <li key={entry.id}>
              <span className="log-message">{entry.message}</span>
              {entry.count > 1 && <span className="log-count">×{entry.count}</span>}
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
