package com.yourorg.scanner.dashboard;

import java.util.List;

/**
 * Optional request body for POST /api/scans/trigger. When paths is null
 * or empty, the scan runs against the configured target-drives instead.
 */
public record ScanTriggerRequest(List<String> paths) {}