package com.yourorg.scanner.core;

import com.yourorg.scanner.config.AppProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.FileVisitOption;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.function.Consumer;

@Component
public class FileWalker {

    private static final Logger log = LoggerFactory.getLogger(FileWalker.class);

    private final AppProperties appProperties;

    public FileWalker(AppProperties appProperties) {
        this.appProperties = appProperties;
    }

    /** Walks the drives configured in application.yml (scanner.target-drives) with default options. */
    public void walk(Consumer<Path> fileHandler) {
        walk(appProperties.getTargetDrives(), ScanOptions.defaults(), fileHandler);
    }

    /** Walks the given target paths with default options. */
    public void walk(List<String> targetPaths, Consumer<Path> fileHandler) {
        walk(targetPaths, ScanOptions.defaults(), fileHandler);
    }

    /**
     * Walks the given target paths honoring the supplied scan options.
     * When more than one root is given (e.g. C:\ and D:\), each root is walked
     * concurrently on its own virtual thread rather than sequentially, so multi-drive
     * or multi-folder scans complete in roughly the time of the slowest single root
     * instead of the sum of all of them.
     */
    public void walk(List<String> targetPaths, ScanOptions options, Consumer<Path> fileHandler) {
        ScanOptions effectiveOptions = options != null ? options : ScanOptions.defaults();

        List<Path> validRoots = new ArrayList<>();
        for (String target : targetPaths) {
            Path rootPath = Paths.get(target);
            if (!Files.exists(rootPath)) {
                log.warn("Configured target path does not exist, skipping: {}", target);
                continue;
            }
            validRoots.add(rootPath);
        }

        if (validRoots.isEmpty()) {
            return;
        }

        if (validRoots.size() == 1) {
            // No benefit spinning up a separate thread for a single root.
            walkSingleRoot(validRoots.get(0), effectiveOptions, fileHandler);
            return;
        }

        log.info("Walking {} target paths concurrently: {}", validRoots.size(), validRoots);

        ExecutorService rootExecutor = Executors.newVirtualThreadPerTaskExecutor();
        List<Future<?>> futures = new ArrayList<>();
        for (Path rootPath : validRoots) {
            futures.add(rootExecutor.submit(() -> walkSingleRoot(rootPath, effectiveOptions, fileHandler)));
        }
        rootExecutor.shutdown();

        for (Future<?> future : futures) {
            try {
                future.get();
            } catch (ExecutionException e) {
                log.error("Error walking one of the target roots: {}",
                        e.getCause() != null ? e.getCause().getMessage() : e.getMessage());
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.warn("Interrupted while waiting for a target root to finish walking");
                rootExecutor.shutdownNow();
                return;
            }
        }
    }

    private void walkSingleRoot(Path rootPath, ScanOptions options, Consumer<Path> fileHandler) {
        Set<FileVisitOption> visitOptions = options.followSymbolicLinks()
                ? EnumSet.of(FileVisitOption.FOLLOW_LINKS)
                : EnumSet.noneOf(FileVisitOption.class);

        int maxDepth = options.recursive() ? Integer.MAX_VALUE : 1;

        try {
            Files.walkFileTree(rootPath, visitOptions, maxDepth, new SimpleFileVisitor<Path>() {

                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    boolean isRoot = dir.equals(rootPath);

                    if (!isRoot && options.excludeConfiguredPaths() && isExcluded(dir)) {
                        log.debug("Skipping excluded directory: {}", dir);
                        return FileVisitResult.SKIP_SUBTREE;
                    }

                    if (!isRoot && !options.includeHiddenFiles() && isHiddenSafe(dir)) {
                        log.debug("Skipping hidden directory: {}", dir);
                        return FileVisitResult.SKIP_SUBTREE;
                    }

                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (!options.includeHiddenFiles() && isHiddenSafe(file)) {
                        return FileVisitResult.CONTINUE;
                    }
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

    private boolean isHiddenSafe(Path path) {
        try {
            return Files.isHidden(path);
        } catch (IOException e) {
            return false;
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