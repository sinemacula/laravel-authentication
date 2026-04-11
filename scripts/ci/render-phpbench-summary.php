<?php

declare(strict_types = 1);

// phpcs:disable PSR1.Files.SideEffects.FoundWithSymbols

$reportPath = $argv[1] ?? 'build/phpbench.xml';

echo "## PHPBench Summary\n\n";

if (!is_file($reportPath)) {
    echo '_No PHPBench report was produced._' . PHP_EOL;

    exit(0);
}

$document = new \DOMDocument;
$previous = libxml_use_internal_errors(true);
$loaded   = $document->load($reportPath);
$errors   = libxml_get_errors();

libxml_clear_errors();
libxml_use_internal_errors($previous);

if (!$loaded) {
    echo '_Unable to parse the PHPBench XML report._' . PHP_EOL;

    foreach ($errors as $error) {
        $message = trim($error->message);

        if ($message === '') {
            continue;
        }

        echo '- ' . $message . PHP_EOL;
    }

    exit(0);
}

$xpath          = new \DOMXPath($document);
$benchmarkNodes = $xpath->query('//*[local-name()=\'benchmark\']');

if ($benchmarkNodes === false || $benchmarkNodes->length === 0) {
    echo '_The PHPBench report did not contain any benchmark results._' . PHP_EOL;

    exit(0);
}

$groups = [
    'Bearer'     => [],
    'Refresh'    => [],
    'JWT Crypto' => [],
    'Basic'      => [],
    'Other'      => [],
];

foreach ($benchmarkNodes as $benchmarkNode) {
    if (!$benchmarkNode instanceof \DOMElement) {
        continue;
    }

    $className    = readAttribute($benchmarkNode, ['class', 'suite', 'name']);
    $subjectNodes = $xpath->query('.//*[local-name()=\'subject\']', $benchmarkNode);

    if ($subjectNodes === false || $subjectNodes->length === 0) {
        continue;
    }

    foreach ($subjectNodes as $subjectNode) {
        if (!$subjectNode instanceof \DOMElement) {
            continue;
        }

        $subjectName = readAttribute($subjectNode, ['name', 'id']);

        if ($subjectName === '') {
            continue;
        }

        $variantNodes = $xpath->query('.//*[local-name()=\'variant\']', $subjectNode);

        if ($variantNodes === false || $variantNodes->length === 0) {
            $groups[groupForBenchmark($className, $subjectName)][] = [
                'scenario'   => prettifySubject($subjectName),
                'mode'       => 'n/a',
                'rsd'        => 'n/a',
                'revs'       => 'n/a',
                'iterations' => 'n/a',
            ];

            continue;
        }

        foreach ($variantNodes as $variantNode) {
            if (!$variantNode instanceof \DOMElement) {
                continue;
            }

            $statsNode      = firstChildElement($xpath, './/*[local-name()=\'stats\']', $variantNode);
            $iterationNodes = $xpath->query('./*[local-name()=\'iteration\']', $variantNode);
            $iterationCount = $iterationNodes === false ? 'n/a' : (string) $iterationNodes->length;
            $timeUnit       = readAttribute($variantNode, ['output-time-unit']);

            $groups[groupForBenchmark($className, $subjectName)][] = [
                'scenario'   => prettifySubject($subjectName),
                'mode'       => formatMode(readAttribute($statsNode, ['mode', 'mo', 'Mo']), $timeUnit),
                'rsd'        => formatPercent(readAttribute($statsNode, ['rstdev', 'rsd', 'RSD'])),
                'revs'       => readAttribute($variantNode, ['revs']) ?: 'n/a',
                'iterations' => $iterationCount,
            ];
        }
    }
}

foreach ($groups as $groupName => $rows) {
    if ($rows === []) {
        continue;
    }

    usort($rows, static fn (array $left, array $right): int => strcmp($left['scenario'], $right['scenario']));

    echo '### ' . $groupName . PHP_EOL . PHP_EOL;
    echo '| Scenario | Mode | RSD | Revs | Iterations |' . PHP_EOL;
    echo '| --- | ---: | ---: | ---: | ---: |' . PHP_EOL;

    foreach ($rows as $row) {
        echo sprintf(
            '| %s | %s | %s | %s | %s |' . PHP_EOL,
            escapePipes($row['scenario']),
            escapePipes($row['mode']),
            escapePipes($row['rsd']),
            escapePipes($row['revs']),
            escapePipes($row['iterations']),
        );
    }

    echo PHP_EOL;
}

/**
 * Read the first non-empty attribute value from an element.
 *
 * @param  ?\DOMElement  $element
 * @param  list<string>  $names
 * @return string
 */
function readAttribute(?\DOMElement $element, array $names): string
{
    if (!$element instanceof \DOMElement) {
        return '';
    }

    foreach ($names as $name) {
        $value = trim($element->getAttribute($name));

        if ($value !== '') {
            return $value;
        }
    }

    return '';
}

/**
 * Return the first matching descendant element for the supplied XPath query.
 *
 * @param  \DOMXPath  $xpath
 * @param  string  $query
 * @param  \DOMElement  $context
 * @return ?\DOMElement
 */
function firstChildElement(\DOMXPath $xpath, string $query, \DOMElement $context): ?\DOMElement
{
    $nodes = $xpath->query($query, $context);

    if ($nodes === false || $nodes->length === 0) {
        return null;
    }

    $node = $nodes->item(0);

    return $node instanceof \DOMElement ? $node : null;
}

/**
 * Group benchmarks into the CI-facing reporting families.
 *
 * @param  string  $className
 * @param  string  $subjectName
 * @return string
 */
function groupForBenchmark(string $className, string $subjectName): string
{
    $needle = strtolower($className . ' ' . $subjectName);
    $group  = 'Other';

    if (str_contains($needle, 'jwttokenservice')) {
        $group = 'JWT Crypto';
    } elseif (str_contains($needle, 'refreshtokenexchange')) {
        $group = 'Refresh';
    } elseif (str_contains($needle, 'basicguard')) {
        $group = 'Basic';
    } elseif (str_contains($needle, 'jwtguard') || str_contains($needle, 'updatedevicetimestamp')) {
        $group = 'Bearer';
    }

    return $group;
}

/**
 * Convert a PHPBench subject method name into a readable scenario label.
 *
 * @param  string  $subjectName
 * @return string
 */
function prettifySubject(string $subjectName): string
{
    $trimmed = preg_replace('/^bench/', '', $subjectName)       ?? $subjectName;
    $spaced  = preg_replace('/(?<!^)([A-Z])/', ' $1', $trimmed) ?? $trimmed;

    return trim($spaced);
}

/**
 * Escape Markdown table separators in cell values.
 *
 * @param  string  $value
 * @return string
 */
function escapePipes(string $value): string
{
    return str_replace('|', '\|', $value);
}

/**
 * Format the raw mode value into the same scale used by PHPBench's console
 * report.
 *
 * @param  string  $value
 * @param  string  $unit
 * @return string
 */
function formatMode(string $value, string $unit): string
{
    $formatted = $value === '' ? 'n/a' : $value;

    if ($value !== '' && is_numeric($value)) {
        $numeric = (float) $value;

        if ($unit === 'microseconds') {
            $formatted = $numeric >= 1000
                ? sprintf('%.3fms/op', $numeric / 1000)
                : sprintf('%.3fμs/op', $numeric);
        } elseif ($unit === 'milliseconds') {
            $formatted = sprintf('%.3fms/op', $numeric);
        } elseif ($unit === 'seconds') {
            $formatted = sprintf('%.3fs/op', $numeric);
        } else {
            $formatted = sprintf('%.3f %s/op', $numeric, $unit === '' ? 'units' : $unit);
        }
    }

    return $formatted;
}

/**
 * Format a percentage-like floating-point value.
 *
 * @param  string  $value
 * @return string
 */
function formatPercent(string $value): string
{
    if ($value === '' || !is_numeric($value)) {
        return $value === '' ? 'n/a' : $value;
    }

    return sprintf('±%.2f%%', (float) $value);
}
