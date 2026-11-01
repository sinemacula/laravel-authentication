<?php

declare(strict_types = 1);

namespace Tests\Unit\Freshness;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Freshness\FreshnessRequirement;
use SineMacula\Laravel\Authentication\Freshness\FreshnessSettings;
use SineMacula\Laravel\Authentication\Proofs\Enums\ProofKind;

/**
 * Unit tests for the freshness settings: the package's entries and a guard's
 * own, which replace them or, with `null`, remove them; operation names read
 * whole, dots included; and every malformed block, name and entry refused,
 * naming where it is.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(FreshnessSettings::class)]
final class FreshnessSettingsTest extends TestCase
{
    /**
     * The package's entry for an operation, with its flags, and none for an
     * operation it does not name or a name that is not an operation's.
     *
     * @return void
     */
    public function testThePackagesEntryApplies(): void
    {
        $settings = self::settings([
            'identifier_change' => ['max_age_seconds' => '900', 'proofs' => ['first_factor', 'first_factor_reauthentication']],
            'mfa.add_factor'    => ['max_age_seconds' => 300, 'proofs' => ['additional_factor'], 'multifactor' => true, 'phishing_resistant' => true],
        ]);

        $change = $settings->requirement('api', 'identifier_change');
        $factor = $settings->requirement('api', 'mfa.add_factor');

        self::assertEquals(new FreshnessRequirement(900, [ProofKind::FIRST_FACTOR, ProofKind::FIRST_FACTOR_REAUTHENTICATION]), $change);
        self::assertEquals(new FreshnessRequirement(300, [ProofKind::ADDITIONAL_FACTOR], true, true), $factor);
        self::assertNull($settings->requirement('api', 'password_establishment'));
        self::assertNull($settings->requirement('api', 'Identifier Change'));
        self::assertNull(self::settings(null)->requirement('api', 'identifier_change'));
    }

    /**
     * A guard's own block replaces the package's entry for each operation it
     * names, `null` removing it, and leaves the others to the package.
     *
     * @return void
     */
    public function testAGuardsOwnEntryWinsAndNullRemovesTheOperation(): void
    {
        $settings = self::settings(
            [
                'identifier_change'      => ['max_age_seconds' => 900, 'proofs' => ['first_factor']],
                'password_establishment' => ['max_age_seconds' => 900, 'proofs' => ['first_factor']],
            ],
            [
                'identifier_change'      => ['max_age_seconds' => 60, 'proofs' => ['recovery_code']],
                'password_establishment' => null,
                'sso.reauthenticate'     => ['max_age_seconds' => 30, 'proofs' => ['external_reauthentication']],
            ],
        );

        self::assertEquals(new FreshnessRequirement(60, [ProofKind::RECOVERY_CODE]), $settings->requirement('api', 'identifier_change'));
        self::assertNull($settings->requirement('api', 'password_establishment'));
        self::assertEquals(new FreshnessRequirement(30, [ProofKind::EXTERNAL_REAUTHENTICATION]), $settings->requirement('api', 'sso.reauthenticate'));
        self::assertEquals(new FreshnessRequirement(900, [ProofKind::FIRST_FACTOR]), $settings->requirement('admin', 'identifier_change'));
    }

    /**
     * Rows of names that are and are not an operation's.
     *
     * @return iterable<string, array{0: string, 1: bool}>
     */
    public static function provideNames(): iterable
    {
        yield from [
            'a word'               => ['identifier_change', true],
            'dotted'               => ['mfa.add_factor', true],
            'deeply dotted'        => ['sso.tenant.reauthenticate2', true],
            'upper case'           => ['Identifier_change', false],
            'a leading digit'      => ['2fa.add', false],
            'an empty segment'     => ['mfa..add', false],
            'a trailing dot'       => ['mfa.', false],
            'a hyphen'             => ['add-factor', false],
            'a segment from digit' => ['mfa.2', false],
            'empty'                => ['', false],
        ];
    }

    /**
     * An operation's name is dot-separated lower-case segments of letters,
     * digits and underscores, each starting with a letter.
     *
     * @param  string  $name
     * @param  bool  $operation
     * @return void
     */
    #[DataProvider('provideNames')]
    public function testOperationNames(string $name, bool $operation): void
    {
        self::assertSame($operation, FreshnessSettings::isOperation($name));
    }

    /**
     * Rows of `[package block, guard block, message]`: every malformed block,
     * name and entry, at the package's level and a guard's.
     *
     * @return iterable<string, array{0: mixed, 1: mixed, 2: string}>
     */
    public static function provideMalformed(): iterable
    {
        $key   = 'authentication.freshness.identifier_change';
        $entry = ' must set `max_age_seconds` and `proofs`, and may set `multifactor` and `phishing_resistant`, or be null.';
        $kinds = '.proofs must list distinct proof kinds, at least one, from `first_factor`, `first_factor_reauthentication`, '
            . '`additional_factor`, `recovery_code`, `external_reauthentication`.';
        $age   = '.max_age_seconds must be an integer from 1 to 86400.';
        $named = ', which is not an operation (dot-separated lower-case segments).';
        $one   = static fn (array $body): array => ['identifier_change' => $body];
        $with  = static fn (array $changes): array => $one([...['max_age_seconds' => 900, 'proofs' => ['first_factor']], ...$changes]);

        yield from [
            'a package block that is no map' => ['soon', null, 'authentication.freshness must map operation names to their freshness.'],
            'a guard block that is no map'   => [[], 'soon', 'auth.guards.api.freshness must map operation names to their freshness.'],
            'a name that is no operation'    => [['Change' => null], null, 'authentication.freshness names [Change]' . $named],
            'a numeric name'                 => [[7 => null], null, 'authentication.freshness names [7]' . $named],
            'an entry that is no map'        => [['identifier_change' => 900], null, $key . $entry],
            'an unknown key'                 => [$with(['mfa' => true]), null, $key . $entry],
            'no proofs'                      => [$one(['max_age_seconds' => 900]), null, $key . $entry],
            'no age'                         => [$one(['proofs' => ['first_factor']]), null, $key . $age],
            'an age too long'                => [$with(['max_age_seconds' => 86401]), null, $key . $age],
            'an unknown kind'                => [$with(['proofs' => ['password']]), null, $key . $kinds],
            'a kind twice'                   => [$with(['proofs' => ['first_factor', 'first_factor']]), null, $key . $kinds],
            'no kinds'                       => [$with(['proofs' => []]), null, $key . $kinds],
            'kinds that are no list'         => [$with(['proofs' => 'first_factor']), null, $key . $kinds],
            'a kind that is no string'       => [$with(['proofs' => [1]]), null, $key . $kinds],
            'a flag that is no boolean'      => [$with(['multifactor' => 'yes']), null, $key . '.multifactor must be true or false.'],
            'a guard entry malformed'        => [[], $with(['max_age_seconds' => 0]), 'auth.guards.api.freshness.identifier_change' . $age],
            'a guard phishing flag'          => [[], $with(['phishing_resistant' => 1]), 'auth.guards.api.freshness.identifier_change.phishing_resistant must be true or false.'],
        ];
    }

    /**
     * A malformed setting fails closed when the operation is read, naming the
     * block and the operation.
     *
     * @param  mixed  $package
     * @param  mixed  $guard
     * @param  string  $message
     * @return void
     */
    #[DataProvider('provideMalformed')]
    public function testAMalformedSettingFailsClosedWhenRead(mixed $package, mixed $guard, string $message): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage($message);

        self::settings($package, $guard)->requirement('api', 'identifier_change');
    }

    /**
     * Validating reads every entry of the block it is asked about: the
     * package's, or a guard's, which a guard without one passes.
     *
     * @return void
     */
    public function testValidatingReadsEveryEntryOfTheBlock(): void
    {
        $valid = ['identifier_change' => ['max_age_seconds' => 900, 'proofs' => ['first_factor']]];

        self::settings($valid, $valid)->validate();
        self::settings($valid, $valid)->validate('api');
        self::settings($valid)->validate('api');

        try {
            self::settings([...$valid, 'mfa.add_factor' => ['max_age_seconds' => 900, 'proofs' => ['nope']]])->validate();
            self::fail('Expected the package block to be refused.');
        } catch (\InvalidArgumentException $exception) {
            self::assertStringStartsWith('authentication.freshness.mfa.add_factor.proofs', $exception->getMessage());
        }

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('auth.guards.api.freshness.sso.reauthenticate');

        self::settings($valid, ['sso.reauthenticate' => ['proofs' => ['first_factor']]])->validate('api');
    }

    /**
     * Settings over the given package block and the `api` guard's own, each
     * left out when `null`.
     *
     * @param  mixed  $package
     * @param  mixed  $guard
     * @return \SineMacula\Laravel\Authentication\Freshness\FreshnessSettings
     */
    private static function settings(mixed $package, mixed $guard = null): FreshnessSettings
    {
        $config = new Repository;

        if ($package !== null) {
            $config->set('authentication', ['freshness' => $package]);
        }

        $config->set('auth.guards', [
            'api'   => $guard === null ? ['driver' => 'jwt'] : ['driver' => 'jwt', 'freshness' => $guard],
            'admin' => ['driver' => 'jwt'],
        ]);

        return new FreshnessSettings($config);
    }
}
