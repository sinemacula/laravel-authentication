<?php

declare(strict_types = 1);

namespace Tests\Unit\Architecture;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversNothing;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\ApiKeys\ApiKeyService;
use SineMacula\Laravel\Authentication\ClientCredentials\ClientCredentialsExchange;
use SineMacula\Laravel\Authentication\Codes\CodeService;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Jwt\JwtTokenService;
use SineMacula\Laravel\Authentication\Passkeys\PasskeyService;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Proofs\FirstFactor;
use SineMacula\Laravel\Authentication\Sessions\SessionService;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Verification\VerificationLinks;

/**
 * Holds the package's services to the shape their actions take: one public
 * method per action, taking plain values and never an
 * `Illuminate\Http\Request`, with no request-reading or token-only twin, and
 * the client (or the sign-in context that carries it) a required value wherever
 * a method takes one, never read from a guard's request. Reading a request is
 * the helpers' alone (`RefreshTokenTransport::extract()`,
 * `ClientContext::fromRequest()`, `SignInContext::fromRequest()`,
 * `PendingCredential::extract()`, `SignedLink::fromRequest()`,
 * `ClientCredentialsRequest::extract()`, `RequestBody::fields()`).
 *
 * The test checks shape only: the behavioural tests of each action, with a
 * guard request that differs from the client given, prove that nothing is read
 * from the guard's request.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversNothing]
final class PlainValueActionsTest extends TestCase
{
    /** @var list<class-string> The package's services. */
    private const array SERVICES = [
        SessionService::class,
        CodeService::class,
        PasskeyService::class,
        PasswordService::class,
        IdentifierChangeService::class,
        ClientCredentialsExchange::class,
        VerificationLinks::class,
        ApiKeyService::class,
        JwtTokenService::class,
    ];

    /**
     * Rows of `[the service]`.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideServices(): iterable
    {
        foreach (self::SERVICES as $service) {
            yield $service => [$service];
        }
    }

    /**
     * No public method of a service takes a request, and none is a
     * request-reading or plain-value twin of another.
     *
     * @param  class-string  $service
     * @return void
     */
    #[DataProvider('provideServices')]
    public function testNoServiceMethodTakesARequestOrHasATwin(string $service): void
    {
        foreach (self::publicMethods($service) as $method) {

            self::assertDoesNotMatchRegularExpression('/(FromRequest|Presented)$/', $method->getName(), "{$service}::{$method->getName()}() is a twin of another action.");

            foreach ($method->getParameters() as $parameter) {
                foreach (self::typeNames($parameter) as $type) {
                    self::assertFalse(is_a($type, Request::class, true), "{$service}::{$method->getName()}() takes a request as \${$parameter->getName()}.");
                }
            }
        }
    }

    /**
     * Rows of `[the service]` for the services whose actions limit or report
     * for a client.
     *
     * @return iterable<string, array{0: class-string}>
     */
    public static function provideClientServices(): iterable
    {
        foreach (array_diff(self::SERVICES, [ApiKeyService::class, JwtTokenService::class]) as $service) {
            yield $service => [$service];
        }
    }

    /**
     * Every public method of a service that takes the client, or the sign-in
     * context that carries it, takes it as a required, non-nullable value.
     *
     * @param  class-string  $service
     * @return void
     */
    #[DataProvider('provideClientServices')]
    public function testEveryClientIsARequiredPlainValue(string $service): void
    {
        $clients = 0;

        foreach (self::publicMethods($service) as $method) {
            foreach ($method->getParameters() as $parameter) {

                $types = self::typeNames($parameter);

                if (!in_array(ClientContext::class, $types, true) && !in_array(SignInContext::class, $types, true)) {
                    continue;
                }

                $type = $parameter->getType();

                self::assertNotNull($type);
                self::assertFalse($parameter->isOptional(), "{$service}::{$method->getName()}() takes \${$parameter->getName()} as optional.");
                self::assertFalse($type->allowsNull(), "{$service}::{$method->getName()}() takes \${$parameter->getName()} as nullable.");

                $clients++;
            }
        }

        self::assertGreaterThan(0, $clients, "{$service} takes no client.");
    }

    /**
     * Rows of `[the session action, its parameters in order]`.
     *
     * @return iterable<string, array{0: string, 1: list<string>}>
     */
    public static function provideSessionActions(): iterable
    {
        yield 'refresh' => ['refresh', ['presented', 'client', 'expectedSession']];
        yield 'switch' => ['switchTo', ['presented', 'target', 'client', 'expectedSession']];
        yield 'sign out by refresh credential' => ['signOutWith', ['presented', 'client', 'expectedSession']];
        yield 'satisfy' => ['satisfy', ['credential', 'proof', 'client']];
        yield 'choose' => ['choose', ['credential', 'principal', 'client', 'tenant']];
    }

    /**
     * Each of the five session actions is one method, taking what was presented
     * first, its own values, and then the client; the three refresh-credential
     * actions end with the optional expected session.
     *
     * @param  string  $action
     * @param  list<string>  $parameters
     * @return void
     */
    #[DataProvider('provideSessionActions')]
    public function testEachSessionActionTakesWhatWasPresentedAndTheClient(string $action, array $parameters): void
    {
        $method = new \ReflectionMethod(SessionService::class, $action);

        self::assertSame($parameters, array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $method->getParameters()));
    }

    /**
     * `start()` is one method: the first factor the application verified, the
     * principal, the method name and the sign-in context that carries the
     * client, with no variant taking an evaluation, provenance or time.
     *
     * @return void
     */
    public function testStartTakesTheFirstFactorThePrincipalTheMethodAndTheContext(): void
    {
        $parameters = (new \ReflectionMethod(SessionService::class, 'start'))->getParameters();

        self::assertSame(['factor', 'principal', 'method', 'context'], array_map(static fn (\ReflectionParameter $parameter): string => $parameter->getName(), $parameters));
        self::assertSame([FirstFactor::class], self::typeNames($parameters[0]));
        self::assertSame([], array_filter(get_class_methods(SessionService::class), static fn (string $name): bool => str_starts_with($name, 'start') && $name !== 'start'));
    }

    /**
     * Rows of a refresh-credential action that takes the optional expected
     * session.
     *
     * @return iterable<string, array{0: string}>
     */
    public static function provideExpectedSessionActions(): iterable
    {
        yield 'refresh' => ['refresh'];
        yield 'switch' => ['switchTo'];
        yield 'sign out by refresh credential' => ['signOutWith'];
    }

    /**
     * The expected session is an optional integer or string, and only `null`
     * leaves it unchecked.
     *
     * @param  string  $action
     * @return void
     */
    #[DataProvider('provideExpectedSessionActions')]
    public function testTheExpectedSessionIsAnOptionalIdentifierDefaultingToNull(string $action): void
    {
        $parameters = (new \ReflectionMethod(SessionService::class, $action))->getParameters();
        $parameter  = end($parameters);

        self::assertInstanceOf(\ReflectionParameter::class, $parameter);

        self::assertSame('expectedSession', $parameter->getName());
        self::assertSame(['int', 'null', 'string'], self::sortedTypeNames($parameter));
        self::assertTrue($parameter->isDefaultValueAvailable());
        self::assertNull($parameter->getDefaultValue());
    }

    /**
     * The public methods of the service, its traits' included.
     *
     * @param  class-string  $service
     * @return list<\ReflectionMethod>
     */
    private static function publicMethods(string $service): array
    {
        return array_values(array_filter(
            (new \ReflectionClass($service))->getMethods(\ReflectionMethod::IS_PUBLIC),
            static fn (\ReflectionMethod $method): bool => !$method->isConstructor(),
        ));
    }

    /**
     * The sorted type names of the parameter's type.
     *
     * @param  \ReflectionParameter  $parameter
     * @return list<string>
     */
    private static function sortedTypeNames(\ReflectionParameter $parameter): array
    {
        $type = $parameter->getType();

        self::assertInstanceOf(\ReflectionUnionType::class, $type);

        $names = [];

        foreach ($type->getTypes() as $member) {
            self::assertInstanceOf(\ReflectionNamedType::class, $member);

            $names[] = $member->getName();
        }

        sort($names);

        return $names;
    }

    /**
     * The class names the parameter's type names.
     *
     * @param  \ReflectionParameter  $parameter
     * @return list<string>
     */
    private static function typeNames(\ReflectionParameter $parameter): array
    {
        $type  = $parameter->getType();
        $types = $type instanceof \ReflectionUnionType || $type instanceof \ReflectionIntersectionType ? $type->getTypes() : [$type];

        return array_values(array_map(
            static fn (\ReflectionNamedType $named): string => $named->getName(),
            array_filter($types, static fn (?\ReflectionType $named): bool => $named instanceof \ReflectionNamedType),
        ));
    }
}
