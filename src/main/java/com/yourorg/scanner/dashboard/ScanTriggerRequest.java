package com.yourorg.scanner.dashboard;

import java.util.List;

/**
 * Optional request body for POST /api/scans/trigger.
 * - paths: null/empty -> scan configured target-drives; non-empty -> scan only these paths.
 * - dataTypes: null/empty -> detect all supported types; non-empty -> detect only these
 *   (values must match SensitiveDataType enum names, e.g. "CARD_NUMBER").
 */
public record ScanTriggerRequest(List<String> paths, List<String> dataTypes) {}