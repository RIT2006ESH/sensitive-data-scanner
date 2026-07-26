package com.yourorg.scanner.detector;

import com.yourorg.scanner.model.SensitiveDataType;

import java.util.List;

/**
 * Scans a block of text for candidate matches of one sensitive data type.
 * Candidates returned here are NOT yet validated — that happens in the
 * validator layer next. A detector's job is purely pattern matching.
 */
public interface SensitiveDataDetector {

    /** Which category of data this detector looks for. */
    SensitiveDataType getType();

    /**
     * @param text plain text extracted from a file
     * @return raw candidate matches found in the text (may include false positives)
     */
    List<String> detectCandidates(String text);
}