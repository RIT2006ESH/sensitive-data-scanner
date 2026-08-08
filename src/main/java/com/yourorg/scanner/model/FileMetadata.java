package com.yourorg.scanner.model;

import java.nio.file.Path;


public class FileMetadata {

    private final String fileName;
    private final Path filePath;
    private final String extension;
    private final long sizeBytes;

    public FileMetadata(String fileName, Path filePath, String extension, long sizeBytes) {
        this.fileName = fileName;
        this.filePath = filePath;
        this.extension = extension;
        this.sizeBytes = sizeBytes;
    }

    public String getFileName() {
        return fileName;
    }

    public Path getFilePath() {
        return filePath;
    }

    public String getExtension() {
        return extension;
    }

    public long getSizeBytes() {
        return sizeBytes;
    }
}