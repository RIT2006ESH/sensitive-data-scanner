package com.yourorg.scanner.report;

import com.yourorg.scanner.model.ScanResult;

import java.io.IOException;
import java.nio.file.Path;
import java.util.List;

/**
 * Writes a completed scan run's findings out to a report file.
 * One implementation per output format (CSV, Excel, ...).
 */
public interface ReportGenerator {

    /**
     * @param findings        all confirmed, masked findings from the run
     * @param outputDirectory folder to write the report into (created if missing)
     * @return the path to the generated report file
     * @throws IOException if the report cannot be written
     */
    Path generateReport(List<ScanResult> findings, Path outputDirectory) throws IOException;
}