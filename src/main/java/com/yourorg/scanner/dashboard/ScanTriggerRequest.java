package com.yourorg.scanner.dashboard;

import java.util.List;


public record ScanTriggerRequest(List<String> paths, List<String> dataTypes) {}