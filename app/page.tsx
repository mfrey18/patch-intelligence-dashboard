import { DashboardClient } from "./DashboardClient";
import { demoDashboard } from "../lib/demo-data";

export default function Home() { return <DashboardClient initialData={demoDashboard} />; }
