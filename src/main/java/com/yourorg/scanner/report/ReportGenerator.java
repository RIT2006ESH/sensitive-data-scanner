package com.yourorg.scanner.report;

import com.yourorg.scanner.model.ScanResult;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;


public interface ReportGenerator {


    Path generateReport(List<ScanResult> findings, Path outputDirectory) throws IOException;
}