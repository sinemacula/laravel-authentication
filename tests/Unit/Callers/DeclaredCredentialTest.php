<?php

declare(strict_types = 1);

namespace Tests\Unit\Callers;

use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Authentication\Callers\DeclaredCredential;
use SineMacula\Laravel\Authentication\Callers\Enums\CallerCredential;
use SineMacula\Laravel\Authentication\Sessions\Enums\PendingAction;

/**
 * Unit tests for the credential a route declares its caller is read from.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(DeclaredCredential::class)]
final class DeclaredCredentialTest extends TestCase
{
    /**
     * A route that declares nothing reads the default guard's access
     * credential, whatever else its request's attributes hold.
     *
     * @return void
     */
    public function testARouteThatDeclaresNothingReadsTheAccessCredential(): void
    {
        $request = Request::create('/');

        $request->attributes->set('authentication.credential', 'refresh');

        foreach ([DeclaredCredential::of(Request::create('/')), DeclaredCredential::of($request), DeclaredCredential::access()] as $declared) {
            self::assertSame(CallerCredential::ACCESS, $declared->credential);
            self::assertNull($declared->guard);
            self::assertNull($declared->action);
        }
    }

    /**
     * The refresh credential is of the guard named, or the default guard.
     *
     * @return void
     */
    public function testTheRefreshCredentialIsOfTheGuardNamed(): void
    {
        $named = DeclaredCredential::refresh('admin');

        self::assertSame(CallerCredential::REFRESH, $named->credential);
        self::assertSame('admin', $named->guard);
        self::assertNull($named->action);
        self::assertNull(DeclaredCredential::refresh(null)->guard);
    }

    /**
     * The pending credential is for the pending action its stable value names,
     * of the guard named or the default one.
     *
     * @return void
     */
    public function testThePendingCredentialIsForTheActionNamed(): void
    {
        $declared = DeclaredCredential::pending('mfa.verify', 'admin');

        self::assertSame(CallerCredential::PENDING, $declared->credential);
        self::assertSame('admin', $declared->guard);
        self::assertSame(PendingAction::VERIFY, $declared->action);
        self::assertSame(PendingAction::CHOOSE_PRINCIPAL, DeclaredCredential::pending('choose_principal', null)->action);
        self::assertNull(DeclaredCredential::pending('choose_principal', null)->guard);
    }

    /**
     * A value that is not a pending action is refused, listing the actions, as
     * is an action's case name.
     *
     * @return void
     */
    public function testAValueThatIsNotAPendingActionIsRefused(): void
    {
        $actions = implode(', ', array_map(static fn (PendingAction $action): string => $action->value, PendingAction::cases()));

        foreach (['CHOOSE_PRINCIPAL', 'choose', ''] as $value) {
            try {
                DeclaredCredential::pending($value, null);

                self::fail(sprintf('[%s] was taken for a pending action.', $value));
            } catch (\InvalidArgumentException $exception) {
                self::assertSame(sprintf('The authentication.pending middleware takes a pending action (%s); [%s] is not one.', $actions, $value), $exception->getMessage());
            }
        }
    }

    /**
     * A declaration is read back from the request it is made on, and the same
     * declaration may be made again; nothing is declared on another request.
     *
     * @return void
     */
    public function testADeclarationIsReadBackFromItsRequest(): void
    {
        $request  = Request::create('/');
        $declared = DeclaredCredential::pending('choose_principal', 'admin');

        $declared->declareOn($request);
        DeclaredCredential::pending('choose_principal', 'admin')->declareOn($request);

        self::assertSame(CallerCredential::PENDING, DeclaredCredential::of($request)->credential);
        self::assertSame('admin', DeclaredCredential::of($request)->guard);
        self::assertSame(PendingAction::CHOOSE_PRINCIPAL, DeclaredCredential::of($request)->action);
        self::assertSame(CallerCredential::ACCESS, DeclaredCredential::of(Request::create('/'))->credential);
    }

    /**
     * A route declares one credential: another credential, guard or action
     * declared on the same request is a misconfiguration.
     *
     * @return void
     */
    public function testASecondDifferentDeclarationIsRefused(): void
    {
        $others = [
            DeclaredCredential::refresh('admin'),
            DeclaredCredential::pending('choose_principal', 'api'),
            DeclaredCredential::pending('mfa.verify', 'admin'),
        ];

        foreach ($others as $other) {

            $request = Request::create('/');

            DeclaredCredential::pending('choose_principal', 'admin')->declareOn($request);

            try {
                $other->declareOn($request);

                self::fail('A second credential was declared.');
            } catch (\LogicException $exception) {
                self::assertSame('A route reads its caller from one credential: it declares authentication.refresh or authentication.pending once.', $exception->getMessage());
                self::assertSame(PendingAction::CHOOSE_PRINCIPAL, DeclaredCredential::of($request)->action);
            }
        }
    }
}
