<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Contracts\Config\Repository;
use Illuminate\Support\Facades\Config;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\OneTimeCodes;

/**
 * Finds one-time codes the way their keys are documented, an HMAC-SHA256 of the
 * parts joined by NUL bytes under a key derived from the application key for
 * each purpose, so tests compute a row's key and a code's hash themselves
 * rather than asking the engine; and builds an engine that issues known codes.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithCodes
{
    /**
     * The key of the binding's code row.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @return string
     */
    protected static function bindingDigest(CodeBinding $binding): string
    {
        $parts = ['binding', $binding->purpose->value, $binding->guard, $binding->type, $binding->identifier, $binding->identity];

        return hash_hmac('sha256', implode("\0", $parts), self::derivedCodeKey('bindings'));
    }

    /**
     * The hash a code issued for the binding in the issuance is stored as.
     *
     * @param  \SineMacula\Laravel\Authentication\Codes\CodeBinding  $binding
     * @param  string  $issueId
     * @param  string  $code
     * @return string
     */
    protected static function codeHash(CodeBinding $binding, string $issueId, string $code): string
    {
        return hash_hmac('sha256', implode("\0", ['code', self::bindingDigest($binding), $issueId, $code]), self::derivedCodeKey('hashes'));
    }

    /**
     * An engine that issues the given codes in turn, as the container would
     * build it otherwise.
     *
     * @param  list<string>  $codes
     * @return \SineMacula\Laravel\Authentication\Codes\OneTimeCodes
     */
    protected static function sequence(array $codes): OneTimeCodes
    {
        return new OneTimeCodes(app(Repository::class), static function () use (&$codes): string {
            $code = array_shift($codes);

            self::assertIsString($code, 'The engine issued more codes than the test gave it.');

            return $code;
        });
    }

    /**
     * Bind an engine that issues the given codes in turn, for the sign-in
     * methods and the code service the container builds from now on.
     *
     * @param  list<string>  $codes
     * @return void
     */
    protected static function issueCodes(array $codes): void
    {
        app()->instance(OneTimeCodes::class, self::sequence($codes));
    }

    /**
     * The key derived from the application key for one of the code key's
     * purposes (`bindings` or `hashes`).
     *
     * @param  string  $purpose
     * @return string
     */
    private static function derivedCodeKey(string $purpose): string
    {
        return hash_hmac('sha256', 'sinemacula/laravel-authentication one-time code ' . $purpose, Config::string('app.key'), true);
    }
}
