import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "../app/globals.css";
import "./pages.css";
import { App } from "./App";

const root = document.getElementById("root");
if (!root) throw new Error("Static dashboard root element is missing");

createRoot(root).render(<StrictMode><App /></StrictMode>);
