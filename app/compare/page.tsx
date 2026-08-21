import type { Metadata } from "next";
import { CveComparisonClient } from "../CveComparisonClient";

export const metadata: Metadata = { title: "Compare vulnerabilities · Vulnerability Intelligence", description: "Read-only, URL-shareable comparison of canonical vulnerability, threat, EPSS, vendor, product, and provenance data." };
export default function ComparePage() { return <CveComparisonClient />; }
