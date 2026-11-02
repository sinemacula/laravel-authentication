<?php

declare(strict_types = 1);

namespace Tests\Feature\Routing;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Foundation\Application;
use Illuminate\Routing\Middleware\SubstituteBindings;
use Illuminate\Support\Facades\Route;
use Illuminate\Testing\TestResponse;
use PHPUnit\Framework\Attributes\CoversTrait;
use SineMacula\Laravel\Authentication\Concerns\ResolvesMeRouteBinding;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Support\IdentifierCoercion;
use Tests\Concerns\InteractsWithMeBindings;
use Tests\Integration\Fixtures\MeMember;
use Tests\Integration\Fixtures\MeSession;
use Tests\TestCase;

/**
 * Feature tests of the four route binding methods the trait overrides, each
 * reached as Laravel reaches it: a top-level binding, one that allows trashed
 * models, a scoped child binding, and one that allows trashed children, each
 * binding `me` and scoping an id to the caller as the `me` binding does.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversTrait(ResolvesMeRouteBinding::class)]
final class ResolvesMeRouteBindingTest extends TestCase
{
    use InteractsWithMeBindings;

    /**
     * Create the tables and register the routes.
     *
     * @return void
     */
    #[\Override]
    protected function setUp(): void
    {
        parent::setUp();

        $this->createMeTables();

        Route::pattern('member', '[0-9a-f-]{36}|me');
        Route::pattern('session', '[0-9a-f-]{36}|me');

        $show = static fn (MeSession $session): array => ['id' => $session->getKey()];
        $nest = static fn (MeMember $member, MeSession $session): array => ['member' => $member->getKey(), 'session' => $session->getKey()];

        Route::middleware(['auth:' . self::MEMBERS, SubstituteBindings::class])->group(static function () use ($show, $nest): void {
            Route::get('/sessions/{session}', $show);
            Route::get('/trashed/sessions/{session}', $show)->withTrashed();
            Route::get('/members/{member}/sessions/{session}', $nest)->scopeBindings();
            Route::get('/trashed/members/{member}/sessions/{session}', $nest)->scopeBindings()->withTrashed();
        });
    }

    /**
     * Drop the tables.
     *
     * @return void
     */
    #[\Override]
    protected function tearDown(): void
    {
        $this->dropMeTables();

        parent::tearDown();
    }

    /**
     * A top-level binding binds `me` and the caller's own sessions, a trashed
     * one only on a route that allows trashed models, and never another
     * member's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testATopLevelBindingResolvesMeAndScopesAnIdToTheCaller(): void
    {
        $this->seedMember('ada@example.test');
        $this->seedMember('grace@example.test');

        $current = $this->signedIn('ada@example.test');
        $deleted = $this->signedIn('ada@example.test');
        $theirs  = $this->signedIn('grace@example.test');
        $token   = $current->tokens->accessToken;
        $id      = self::key($deleted->record->getKey());

        $deleted->record->delete();

        $this->bearer('/sessions/me', $token)->assertOk()->assertExactJson(['id' => $current->record->getKey()]);
        $this->bearer('/sessions/' . $id, $token)->assertNotFound();
        $this->bearer('/trashed/sessions/' . $id, $token)->assertOk()->assertExactJson(['id' => $id]);
        $this->bearer('/trashed/sessions/me', $token)->assertOk()->assertExactJson(['id' => $current->record->getKey()]);
        $this->bearer('/trashed/sessions/' . self::key($theirs->record->getKey()), $token)->assertNotFound();
    }

    /**
     * A scoped child binding binds `me` and the parent's own sessions, a
     * trashed one only on a route that allows trashed models, and never another
     * member's.
     *
     * @return void
     *
     * @throws \Throwable
     */
    public function testAChildBindingResolvesMeAndScopesAnIdToTheCaller(): void
    {
        [$member] = $this->seedMember('ada@example.test');

        $this->seedMember('grace@example.test');

        $current = $this->signedIn('ada@example.test');
        $deleted = $this->signedIn('ada@example.test');
        $theirs  = $this->signedIn('grace@example.test');
        $token   = $current->tokens->accessToken;
        $id      = self::key($deleted->record->getKey());
        $key     = $member->getKey();

        $deleted->record->delete();

        $this->bearer('/members/me/sessions/me', $token)->assertOk()->assertExactJson(['member' => $key, 'session' => $current->record->getKey()]);
        $this->bearer('/members/me/sessions/' . $id, $token)->assertNotFound();
        $this->bearer('/trashed/members/me/sessions/' . $id, $token)->assertOk()->assertExactJson(['member' => $key, 'session' => $id]);
        $this->bearer('/trashed/members/me/sessions/me', $token)->assertOk()->assertExactJson(['member' => $key, 'session' => $current->record->getKey()]);
        $this->bearer('/trashed/members/me/sessions/' . self::key($theirs->record->getKey()), $token)->assertNotFound();
    }

    /**
     * Register the members' guards.
     *
     * @param  mixed  $app
     * @return void
     */
    #[\Override]
    protected function defineEnvironment(mixed $app): void
    {
        parent::defineEnvironment($app);

        assert($app instanceof Application);

        self::configureMeGuards($app->make(ConfigRepository::class));
    }

    /**
     * A key as a route segment.
     *
     * @param  mixed  $key
     * @return string
     */
    private static function key(mixed $key): string
    {
        return (string) IdentifierCoercion::stringify($key);
    }

    /**
     * Get the route with the access token, on guards resolved afresh.
     *
     * @param  string  $uri
     * @param  string  $token
     * @return \Illuminate\Testing\TestResponse<\Symfony\Component\HttpFoundation\Response>
     */
    private function bearer(string $uri, #[\SensitiveParameter] string $token): TestResponse
    {
        Auth::forgetGuards();

        return $this->getJson($uri, ['Authorization' => 'Bearer ' . $token]);
    }
}
