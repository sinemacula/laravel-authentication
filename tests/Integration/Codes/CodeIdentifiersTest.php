<?php

declare(strict_types = 1);

namespace Tests\Integration\Codes;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\DB;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use SineMacula\Laravel\Authentication\Codes\CodeBinding;
use SineMacula\Laravel\Authentication\Codes\CodeIdentifiers;
use SineMacula\Laravel\Authentication\Verification\IdentifierVerifier;
use Tests\Concerns\InteractsWithCodeIdentities;
use Tests\Integration\Fixtures\CodeIdentity;
use Tests\TestCase;

/**
 * Integration tests for how the one-time code flows read an identity's own
 * identifier and decide whether it holds the identifier a code is bound to: the
 * stored value in its canonical form, compared exactly.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(CodeIdentifiers::class)]
final class CodeIdentifiersTest extends TestCase
{
    use InteractsWithCodeIdentities;

    /**
     * Create the identities table.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        self::createCodeIdentitiesTable();
    }

    /**
     * Drop the identities table.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        self::dropCodeIdentitiesTable();

        parent::tearDown();
    }

    /**
     * Rows of `[stored phone, stored email, type, own identifier]`.
     *
     * @return iterable<string, array{0: ?string, 1: ?string, 2: string, 3: ?string}>
     */
    public static function provideOwnIdentifiers(): iterable
    {
        yield from [
            'a number in E.164'               => ['+447700900123', null, 'phone', '+447700900123'],
            'an address in another case'      => [null, ' Ada@Example.TEST', 'email', 'ada@example.test'],
            'no number'                       => [null, 'ada@example.test', 'phone', null],
            'a number the normaliser rejects' => ['07700 900123', null, 'phone', null],
        ];
    }

    /**
     * The identity's own identifier of the type is the stored one in its
     * canonical form, or `null` when it has none the normaliser accepts.
     *
     * @param  ?string  $phone
     * @param  ?string  $email
     * @param  string  $type
     * @param  ?string  $expected
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideOwnIdentifiers')]
    public function testTheOwnIdentifierIsTheStoredOneInCanonicalForm(?string $phone, ?string $email, string $type, ?string $expected): void
    {
        $identity = self::stored($phone, $email);

        self::assertSame($expected, CodeIdentifiers::of($identity, $type, app(IdentifierVerifier::class)));
    }

    /**
     * Rows of `[stored address, bound address, whether the identity holds it]`.
     *
     * @return iterable<string, array{0: ?string, 1: string, 2: bool}>
     */
    public static function provideHeldIdentifiers(): iterable
    {
        yield from [
            'the same address'                 => ['ada@example.test', 'ada@example.test', true],
            'the same address in another case' => ['Ada@Example.Test', 'ada@example.test', true],
            'an accented look-alike'           => ['ada@example.test', 'ada@exämple.test', false],
            'another address'                  => ['ada@example.test', 'bob@example.test', false],
            'no address'                       => [null, 'ada@example.test', false],
        ];
    }

    /**
     * An identity holds the bound identifier only when its own is exactly it,
     * in canonical form.
     *
     * @param  ?string  $stored
     * @param  string  $bound
     * @param  bool  $holds
     * @return void
     *
     * @throws \Throwable
     */
    #[DataProvider('provideHeldIdentifiers')]
    public function testAnIdentityHoldsOnlyItsOwnIdentifier(?string $stored, string $bound, bool $holds): void
    {
        $identity = self::stored(null, $stored);

        self::assertSame($holds, CodeIdentifiers::isHeldBy($identity, CodeBinding::signIn('mobile', 'email', $bound), app(IdentifierVerifier::class)));
    }

    /**
     * `CodeIdentifiers` is a static utility; instantiation is disallowed
     * through the private constructor. Reflection invokes it so the line is
     * covered while still documenting the access modifier.
     *
     * @return void
     *
     * @SuppressWarnings("php:S3011")
     */
    public function testConstructorIsPrivate(): void
    {
        $reflection  = new \ReflectionClass(CodeIdentifiers::class);
        $constructor = $reflection->getConstructor();

        self::assertNotNull($constructor);
        self::assertTrue($constructor->isPrivate());

        $instance = $reflection->newInstanceWithoutConstructor();
        $constructor->invoke($instance);
    }

    /**
     * Configure the guards.
     *
     * @param  mixed  $app
     * @return void
     *
     * @throws \Illuminate\Contracts\Container\BindingResolutionException
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureCodeGuards($app->make(ConfigRepository::class));
    }

    /**
     * An identity whose identifiers are stored exactly as given, as a row
     * written outside the model's casts would hold them.
     *
     * @param  ?string  $phone
     * @param  ?string  $email
     * @return \Tests\Integration\Fixtures\CodeIdentity
     */
    private static function stored(?string $phone, ?string $email): CodeIdentity
    {
        $id = DB::table('code_identities')->insertGetId(['phone' => $phone, 'email' => $email]);

        return CodeIdentity::query()->findOrFail($id);
    }
}
