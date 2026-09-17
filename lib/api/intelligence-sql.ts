export function scopePredicate(cve='c',advisory='a') {
  return `${cve}.record_status<>'rejected' AND (${advisory}.id IS NOT NULL OR EXISTS(SELECT 1 FROM kev_entries sk WHERE sk.cve_id=${cve}.id AND sk.active=TRUE AND sk.date_added>=CURRENT_TIMESTAMP-INTERVAL '6 months') OR EXISTS(SELECT 1 FROM vulncheck_entries sv WHERE sv.cve_id=${cve}.id AND sv.active=TRUE AND sv.date_added>=CURRENT_TIMESTAMP-INTERVAL '6 months'))`;
}
export const severitySql = `COALESCE(NULLIF(MAX(CASE WHEN a.id IS NULL THEN 0 ELSE CASE ac.normalized_severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3 WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END END),0),CASE WHEN c.cvss_score>=9 THEN 4 WHEN c.cvss_score>=7 THEN 3 WHEN c.cvss_score>=4 THEN 2 WHEN c.cvss_score>0 THEN 1 ELSE 0 END)`;
export function intelligenceColumns(id:string) {
  return `EXISTS(SELECT 1 FROM vulncheck_entries vi WHERE vi.cve_id=${id} AND vi.active=TRUE) vulncheck,
  COALESCE((SELECT jsonb_agg(DISTINCT ee.source_id) FROM exploit_evidence ee WHERE ee.cve_id=${id} AND ee.evidence_type='known_exploitation' AND ee.status='confirmed'),'[]'::jsonb) exploitation_sources,
  CASE WHEN EXISTS(SELECT 1 FROM advisory_cves av JOIN advisories ad ON ad.id=av.advisory_id WHERE av.cve_id=${id} AND av.vendor_cvss_score IS NOT NULL AND COALESCE(ad.published_at,ad.source_updated_at)>=CURRENT_TIMESTAMP-INTERVAL '6 months') THEN 'vendor' ELSE (SELECT ec.assessment_source FROM cves ec WHERE ec.id=${id}) END assessment_source`;
}
