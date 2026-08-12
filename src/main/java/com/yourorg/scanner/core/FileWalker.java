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
import java.util.List;
import java.util.function.Consumer;

/**
 * Walks target drives/folders and streams each discovered file to a
 * callback as soon as it's found, rather than collecting a full list
 * first. This lets processing (and any live progress reporting) start
 * immediately instead of waiting for an entire tree to be enumerated.
 *
 * Excluded paths/folder-names from AppProperties always apply, regardless
 * of whether the walk targets the configured drives or an ad-hoc override.
 */
@Component
public class FileWalker {

    private static final Logger log = LoggerFactory.getLogger(FileWalker.class);

    private final AppProperties appProperties;

    public FileWalker(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    /** Walks the drives configured in application.yml (scanner.target-drives). */
    public void walk(Consumer<Path> fileHandler) {
        walk(appProperties.getTargetDrives(), fileHandler);
    }

    /** Walks the given target paths instead of the configured drives. */
    public void walk(List<String> targetPaths, Consumer<Path> fileHandler) {
        for (String target : targetPaths) {
            Path rootPath = Paths.get(target);

            if (!Files.exists(rootPath)) {
                log.warn("Configured target path does not exist, skipping: {}", target);
                continue;
            }

            walkSingleRoot(rootPath, fileHandler);
        }
    }

    private void walkSingleRoot(Path rootPath, Consumer<Path> fileHandler) {
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
                    fileHandler.accept(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    log.debug("Could not access, skipping: {} ({})", file, exc.getMessage());
                    return FileVisitResult.CONTINUE;
                }
            });
        } catch (IOException e) {
            log.error("Error walking directory tree starting at {}: {}", rootPath, e.getMessage());
        }
    }

    private boolean isExcluded(Path dir) {
        if (isExcludedByPath(dir)) {
            return true;
        }
        return isExcludedByFolderName(dir);
    }

    private boolean isExcludedByPath(Path dir) {
        List<String> excludedPaths = appProperties.getExcludedPaths();
        if (excludedPaths == null) {
            return false;
        }
        for (String excludedPath : excludedPaths) {
            Path excluded = Paths.get(excludedPath);
            if (dir.equals(excluded) || dir.startsWith(excluded)) {
                return true;
            }
        }
        return false;
    }

    private boolean isExcludedByFolderName(Path dir) {
        List<String> excludedFolderNames = appProperties.getExcludedFolderNames();
        if (excludedFolderNames == null || dir.getFileName() == null) {
            return false;
        }
        String dirName = dir.getFileName().toString();
        for (String excludedName : excludedFolderNames) {
            if (dirName.equalsIgnoreCase(excludedName)) {
                return true;
            }
        }
        return false;
    }
}