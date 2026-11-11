-- Rapid7 InsightVM / Nexpose: every vulnerability exception, one row each, for maps/rapid7-insightvm.yaml.
-- Run it as a "SQL Query Export" report (reporting data model 2.0 or later) and save the CSV.
-- Scope becomes the target: global = every asset (*), site = tag:site:<name>, asset group = tag:group:<name>,
-- asset or instance = the host name (or its address). Site and group names match the asset export
-- (maps/rapid7-insightvm-assets.sql). A name with a comma in it cannot be matched: targets are split on commas.
-- An exception on a check with no CVE id comes out with an empty cve and is skipped with a warning.
SELECT
  dve.vulnerability_exception_id AS exception_id,
  (SELECT string_agg(DISTINCT dvr.reference, ';')
     FROM dim_vulnerability_reference dvr
    WHERE dvr.vulnerability_id = dve.vulnerability_id AND dvr.source = 'CVE') AS cve,
  CASE
    WHEN dve.group_id IS NOT NULL THEN 'tag:group:' || dag.name
    WHEN dve.scope_id = 'G' THEN '*'
    WHEN dve.scope_id = 'S' THEN 'tag:site:' || ds.name
    ELSE COALESCE(da.host_name, host(da.ip_address))
  END AS target,
  to_char(dve.submitted_date, 'YYYY-MM-DD') AS submitted_date,
  to_char(dve.expiration_date, 'YYYY-MM-DD') AS expiration_date,
  der.description || ': ' || COALESCE(dve.additional_comments, '') AS justification,
  COALESCE(dve.reviewed_by, dve.submitted_by) AS owner,
  des.description AS status,
  der.description AS reason
FROM dim_vulnerability_exception dve
JOIN dim_exception_reason der ON der.reason_id = dve.reason_id
JOIN dim_exception_status des ON des.status_id = dve.status_id
LEFT JOIN dim_site ds ON ds.site_id = dve.site_id
LEFT JOIN dim_asset_group dag ON dag.asset_group_id = dve.group_id
LEFT JOIN dim_asset da ON da.asset_id = dve.asset_id
ORDER BY dve.vulnerability_exception_id
