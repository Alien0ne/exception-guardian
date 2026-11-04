# Hunt brief: $rule_id

Exception $rule_code ($source, $rule_type) suppressed $cves on $hosts. It now grades **REVOKE**. Before the
exception is revoked, hunt for signs that the suppressed weakness was already used.

## Hypothesis

While exception $rule_id was active ($window_start → $window_end), an attacker exploited $cves on $hosts and the
finding stayed hidden from the vulnerability queue.

## Affected hosts

$host_lines

## CVEs and evidence

| Evidence | Then | Now | Source |
|---|---|---|---|
$evidence_rows
$infra_section
## Look-back window

From **$window_start** (exception created) to **$window_end** (today).$window_note

## Detections

$detection_lines

## Suggested SOC-Hunter starting prompt

> Hunt for exploitation of $cves on $hosts between $window_start and $window_end. The exception $rule_id hid this
> exposure from the vulnerability queue. Start with the detections listed in this brief, run each query over the
> window, and report any hit with its host, time and process tree.$infra_prompt

Quoted fields (names, CVEs, hosts) come from the source system and are shown escaped.
