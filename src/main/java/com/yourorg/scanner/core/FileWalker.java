package com.yourorg.scanner.core;

import com.yourorg.scanner.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;

/**
 * Recursively walks each configured target drive/folder and returns every
 * file found, skipping excluded paths and any location that raises an
 * access error (e.g. permission denied) rather than aborting the whole scan.
 */
@Component
public class FileWalker {

    private static final Logger log = LoggerFactory.getLogger(FileWalker.class);

    private final AppProperties appProperties;

    public FileWalker(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    /**
     * @return every file discovered under all configured target drives,
     *         excluding paths listed in scanner.excluded-paths
     */
    public List<Path> walk() {
        List<Path> discoveredFiles = new ArrayList<>();

        for (String drive : appProperties.getTargetDrives()) {
            Path rootPath = Paths.get(drive);

            if (!Files.exists(rootPath)) {
                log.warn("Configured target drive does not exist, skipping: {}", drive);
                continue;
            }

            walkSingleRoot(rootPath, discoveredFiles);
        }

        return discoveredFiles;
    }

    private void walkSingleRoot(Path rootPath, List<Path> discoveredFiles) {
        try {
            Files.walkFileTree(rootPath, new SimpleFileVisitor<Path>() {

                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    if (isExcluded(dir)) {
                        log.debug("Skipping excluded directory: {}", dir);
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    discoveredFiles.add(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    log.warn("Could not access file, skipping: {} ({})", file, exc.getMessage());
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.error("Error walking directory tree starting at {}: {}", rootPath, e.getMessage());
        }
    }

    private boolean isExcluded(Path dir) {
        String dirString = dir.toString();
        for (String excludedPath : appProperties.getExcludedPaths()) {
            if (dirString.equalsIgnoreCase(excludedPath) || dirString.startsWith(excludedPath)) {
                return true;
            }
        }
        return false;
    }
}