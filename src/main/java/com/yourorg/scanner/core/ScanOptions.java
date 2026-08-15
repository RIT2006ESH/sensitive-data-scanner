package com.yourorg.scanner.core;

import java.util.List;

/** Scan-time overrides for how the file walker and extension filter behave. */
public record ScanOptions(
        boolean recursive,
        boolean includeHiddenFiles,
        boolean excludeConfiguredPaths,
        boolean followSymbolicLinks,
        List<String> fileTypeFilters
) {
    public static ScanOptions defaults() {
        return new ScanOptions(true, true, true, false, null);
    }
}
