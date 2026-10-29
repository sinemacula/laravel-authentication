<?php

declare(strict_types = 1);

namespace Tests\Unit\Passwords;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Contracts\BreachedPasswordChecker;
use SineMacula\Laravel\Authentication\IdentifierChanges\IdentifierChangeService;
use SineMacula\Laravel\Authentication\Passwords\NoBreachedPasswordCheck;
use SineMacula\Laravel\Authentication\Passwords\PasswordPolicy;
use SineMacula\Laravel\Authentication\Passwords\PasswordService;
use SineMacula\Laravel\Authentication\Passwords\PasswordWriter;
use SineMacula\Laravel\Authentication\Passwords\ResetInput;
use SineMacula\Laravel\Authentication\Passwords\ResetRequests;
use SineMacula\Laravel\Authentication\Passwords\ResetSubmissions;
use SineMacula\Laravel\Authentication\Sessions\Reauthentication;
use SineMacula\Laravel\Authentication\Sessions\RecentAuthentication;
use SineMacula\Laravel\Authentication\Testing\FakeBreachedPasswordChecker;

/**
 * Pins `#[\SensitiveParameter]` on every parameter through which a plaintext
 * password, a reset token or code, or the input holding one passes on its way
 * to the hasher, the breached checker or the code engine: an exception thrown
 * below any of them (a breached checker's bug, which propagates, say) must not
 * carry the secret in its trace's arguments.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(PasswordService::class)]
#[CoversClass(PasswordPolicy::class)]
#[CoversClass(PasswordWriter::class)]
#[CoversClass(NoBreachedPasswordCheck::class)]
#[CoversClass(ResetRequests::class)]
#[CoversClass(ResetSubmissions::class)]
#[CoversClass(ResetInput::class)]
#[CoversClass(Reauthentication::class)]
#[CoversClass(RecentAuthentication::class)]
#[CoversClass(IdentifierChangeService::class)]
final class SensitiveParametersTest extends TestCase
{
    /**
     * Rows of each method and the parameters of it that carry a secret.
     *
     * @return iterable<string, array{0: class-string, 1: string, 2: list<string>}>
     */
    public static function provideSecretParameters(): iterable
    {
        yield from [
            'PasswordService::check()'                  => [PasswordService::class, 'check', ['password']],
            'PasswordService::set()'                    => [PasswordService::class, 'set', ['password']],
            'PasswordService::sendResetLink()'          => [PasswordService::class, 'sendResetLink', ['input']],
            'PasswordService::sendResetCode()'          => [PasswordService::class, 'sendResetCode', ['input']],
            'PasswordService::reset()'                  => [PasswordService::class, 'reset', ['input']],
            'PasswordService::resetWithCode()'          => [PasswordService::class, 'resetWithCode', ['input']],
            'PasswordPolicy::check()'                   => [PasswordPolicy::class, 'check', ['password']],
            'PasswordPolicy::lengthViolations()'        => [PasswordPolicy::class, 'lengthViolations', ['password']],
            'PasswordPolicy::hashingViolations()'       => [PasswordPolicy::class, 'hashingViolations', ['password']],
            'PasswordPolicy::compositionViolations()'   => [PasswordPolicy::class, 'compositionViolations', ['password']],
            'PasswordPolicy::breachedViolation()'       => [PasswordPolicy::class, 'breachedViolation', ['password']],
            'PasswordWriter::write()'                   => [PasswordWriter::class, 'write', ['password']],
            'PasswordWriter::store()'                   => [PasswordWriter::class, 'store', ['hash']],
            'BreachedPasswordChecker::isBreached()'     => [BreachedPasswordChecker::class, 'isBreached', ['password']],
            'NoBreachedPasswordCheck::isBreached()'     => [NoBreachedPasswordCheck::class, 'isBreached', ['password']],
            'FakeBreachedPasswordChecker::isBreached()' => [FakeBreachedPasswordChecker::class, 'isBreached', ['password']],
            'ResetRequests::link()'                     => [ResetRequests::class, 'link', ['input']],
            'ResetRequests::code()'                     => [ResetRequests::class, 'code', ['input']],
            'ResetRequests::send()'                     => [ResetRequests::class, 'send', ['input']],
            'ResetSubmissions::link()'                  => [ResetSubmissions::class, 'link', ['input']],
            'ResetSubmissions::code()'                  => [ResetSubmissions::class, 'code', ['input']],
            'ResetSubmissions::reset()'                 => [ResetSubmissions::class, 'reset', ['input']],
            'ResetSubmissions::attempt()'               => [ResetSubmissions::class, 'attempt', ['proof', 'password']],
            'ResetSubmissions::spend()'                 => [ResetSubmissions::class, 'spend', ['proof', 'password']],
            'ResetSubmissions::checkProof()'            => [ResetSubmissions::class, 'checkProof', ['proof']],
            'ResetSubmissions::isWellFormed()'          => [ResetSubmissions::class, 'isWellFormed', ['proof']],
            'ResetInput::identifier()'                  => [ResetInput::class, 'identifier', ['input']],
            'ResetInput::secret()'                      => [ResetInput::class, 'secret', ['input']],
            'Reauthentication::password()'              => [Reauthentication::class, 'password', ['password']],
            'RecentAuthentication::isCurrentPassword()' => [RecentAuthentication::class, 'isCurrentPassword', ['password']],
            'IdentifierChangeService::confirmByCode()'  => [IdentifierChangeService::class, 'confirmByCode', ['code']],
        ];
    }

    /**
     * Each parameter carrying a secret is marked `#[\SensitiveParameter]`.
     *
     * @param  class-string  $class
     * @param  string  $method
     * @param  list<string>  $parameters
     * @return void
     *
     * @throws \ReflectionException
     */
    #[DataProvider('provideSecretParameters')]
    public function testTheSecretParametersAreSensitive(string $class, string $method, array $parameters): void
    {
        foreach ($parameters as $parameter) {
            $attributes = (new \ReflectionParameter([$class, $method], $parameter))->getAttributes(\SensitiveParameter::class);

            self::assertNotSame([], $attributes, "{$class}::{$method}() does not mark \${$parameter} sensitive.");
        }
    }
}
