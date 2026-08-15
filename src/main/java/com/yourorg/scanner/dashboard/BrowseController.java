package com.yourorg.scanner.dashboard;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;
import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Backs the dashboard's Browse button. A browser's native file/folder
 * picker can never expose the true absolute server-side path (browsers
 * deliberately withhold it for privacy/fingerprinting reasons), so this
 * lets the frontend navigate the real server filesystem instead.
 * Read-only: lists directory names only, never file contents.
 */
@RestController
@RequestMapping("/api/scans")
public class BrowseController {

    public record BrowseEntry(String name, String path) {}
    public record BrowseResponse(String currentPath, String parentPath, List<BrowseEntry> folders) {}

    @GetMapping("/browse")
    public BrowseResponse browse(@RequestParam(required = false) String path) {
        if (path == null || path.isBlank()) {
            return listRoots();
        }

        Path dir = Paths.get(path);
        if (!Files.isDirectory(dir)) {
            return listRoots();
        }

        List<BrowseEntry> folders = new ArrayList<>();
        try (DirectoryStream<Path> stream = Files.newDirectoryStream(dir, Files::isDirectory)) {
            for (Path entry : stream) {
                folders.add(new BrowseEntry(entry.getFileName().toString(), entry.toAbsolutePath().toString()));
            }
        } catch (IOException e) {
            // Permission-denied or similar -- return what we have rather than failing outright.
        }
        folders.sort(Comparator.comparing(BrowseEntry::name, String.CASE_INSENSITIVE_ORDER));

        Path parent = dir.getParent();
        String parentPath = parent == null ? "" : parent.toAbsolutePath().toString();

        return new BrowseResponse(dir.toAbsolutePath().toString(), parentPath, folders);
    }

    private BrowseResponse listRoots() {
        List<BrowseEntry> roots = new ArrayList<>();
        for (File root : File.listRoots()) {
            roots.add(new BrowseEntry(root.getPath(), root.getPath()));
        }
        return new BrowseResponse("", null, roots);
    }
}