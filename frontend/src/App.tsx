import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Logs from './pages/Logs';
import Rules from './pages/Rules';
import Alerts from './pages/Alerts';
import Coverage from './pages/Coverage';

export default function App() {
  return (
    <BrowserRouter>
      <div className="app-layout">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/rules" element={<Rules />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route path="/coverage" element={<Coverage />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  );
}
