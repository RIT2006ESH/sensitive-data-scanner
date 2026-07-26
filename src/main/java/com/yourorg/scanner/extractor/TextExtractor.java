package com.yourorg.scanner.extractor;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Converts a file's content into plain text for downstream detection.
 * One implementation per supported file format.
 */
public interface TextExtractor {

    /**
     * @param filePath absolute path to the file to read
     * @return the extracted plain text (never null; empty string if nothing readable)
     * @throws IOException if the file cannot be opened or parsed
     */
    String extractText(Path filePath) throws IOException;
}