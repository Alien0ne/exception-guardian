-- Rapid7 InsightVM / Nexpose: every asset with its sites, asset groups and first-discovered day, for
-- maps/rapid7-insightvm-assets.yaml. Run it as a "SQL Query Export" report and save the CSV.
-- first_discovered is the first scan that found the asset, not the day the host was built.
SELECT
  da.asset_id AS asset_id,
  COALESCE(da.host_name, host(da.ip_address)) AS host_name,
  (SELECT string_agg(DISTINCT host(ip.ip_address), ';')
     FROM dim_asset_ip_address ip WHERE ip.asset_id = da.asset_id) AS ip_addresses,
  dos.description AS operating_system,
  (SELECT string_agg(DISTINCT s.name, ';')
     FROM dim_site_asset sa JOIN dim_site s ON s.site_id = sa.site_id
    WHERE sa.asset_id = da.asset_id) AS sites,
  (SELECT string_agg(DISTINCT g.name, ';')
     FROM dim_asset_group_asset ga JOIN dim_asset_group g ON g.asset_group_id = ga.asset_group_id
    WHERE ga.asset_id = da.asset_id) AS asset_groups,
  to_char(fad.first_discovered, 'YYYY-MM-DD') AS first_discovered
FROM dim_asset da
LEFT JOIN dim_operating_system dos ON dos.operating_system_id = da.operating_system_id
LEFT JOIN fact_asset_discovery fad ON fad.asset_id = da.asset_id
ORDER BY da.asset_id
