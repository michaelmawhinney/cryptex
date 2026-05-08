<?php

declare(strict_types=1);

$paths = [
    __DIR__ . '/../src',
    __DIR__ . '/../tests',
];

$hasErrors = false;

foreach ($paths as $path) {
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS)
    );

    foreach ($iterator as $file) {
        if (!$file->isFile() || $file->getExtension() !== 'php') {
            continue;
        }

        $command = escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($file->getPathname());
        passthru($command, $exitCode);

        if ($exitCode !== 0) {
            $hasErrors = true;
        }
    }
}

exit($hasErrors ? 1 : 0);
