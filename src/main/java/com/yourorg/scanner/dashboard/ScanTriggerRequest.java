package com.yourorg.scanner.dashboard;

import java.util.List;
import java.util.Map;

public record ScanTriggerRequest(
        List<String> paths,
        List<String> dataTypes,
        Map<String, String> customPatterns,
        Boolean recursive,
        Boolean includeHiddenFiles,
        Boolean excludeConfiguredPaths,
        Boolean followSymbolicLinks,
        List<String> fileTypeFilters
) {}