# Hunt brief: $rule_id

Exception $rule_code ($source, $rule_type) suppressed $cves on $hosts. It now grades **REVOKE**.

## No hunt possible: patch or mitigate

No log can show these weaknesses being used, so there is nothing to hunt for. Patch or mitigate them on the hosts
below, then revoke the exception.

$detection_lines

## Affected hosts

$host_lines

## CVEs and evidence

| Evidence | Then | Now | Source |
|---|---|---|---|
$evidence_rows

Quoted fields (names, CVEs, hosts) come from the source system and are shown escaped.
