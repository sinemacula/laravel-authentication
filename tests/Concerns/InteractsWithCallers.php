<?php

declare(strict_types = 1);

namespace Tests\Concerns;

use Illuminate\Config\Repository as ConfigRepository;
use Illuminate\Contracts\Hashing\Hasher;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Schema;
use SineMacula\Laravel\Authentication\Facades\Auth;
use SineMacula\Laravel\Authentication\Sessions\SignedInSession;
use SineMacula\Laravel\Authentication\Sessions\SignInContext;
use SineMacula\Laravel\Authentication\Sessions\SignInResult;
use Tests\Integration\Fixtures\CallerMember;
use Tests\Integration\Fixtures\CallerMembership;

/**
 * Shared set-up for the tests of the caller of a request: two applications
 * (`members`, the default guard, and `others`) over `CallerMember`, whose
 * sessions are the shipped session model's; the member and membership tables;
 * seeded members; and sign-ins, active or pending.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithCallers
{
    /** @var string The guard the requests default to. */
    protected const string MEMBERS = 'members';

    /** @var string A second application over the same members. */
    protected const string OTHERS = 'others';

    /** @var string Plaintext password of every seeded member. */
    protected const string MEMBER_PASSWORD = 'correct horse battery staple';

    /**
     * Create the member and membership tables on the connection, or the default
     * one.
     *
     * @param  ?string  $connection
     * @return void
     */
    protected function createCallerTables(?string $connection = null): void
    {
        Schema::connection($connection)->create('caller_members', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::connection($connection)->create('caller_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->uuid('identity_id');
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });
    }

    /**
     * Drop the tables `createCallerTables()` created.
     *
     * @param  ?string  $connection
     * @return void
     */
    protected function dropCallerTables(?string $connection = null): void
    {
        foreach (['caller_memberships', 'caller_members'] as $table) {
            Schema::connection($connection)->dropIfExists($table);
        }
    }

    /**
     * Register both applications over the members, the members' guard the
     * default, each allowing password sign-in, with a cheap password hash and a
     * timebox short enough not to slow the suite.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected static function configureCallerGuards(ConfigRepository $config): void
    {
        $application = ['methods' => ['password']];

        $config->set('auth.defaults.guard', self::MEMBERS);
        $config->set('auth.providers.caller_members', ['driver' => 'model', 'model' => CallerMember::class]);
        $config->set('auth.guards.' . self::MEMBERS, ['driver' => 'jwt', 'provider' => 'caller_members', 'application' => $application]);
        $config->set('auth.guards.' . self::OTHERS, ['driver' => 'jwt', 'provider' => 'caller_members', 'application' => $application]);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist a member with the given number of memberships.
     *
     * @param  string  $email
     * @param  int  $memberships
     * @return array{0: \Tests\Integration\Fixtures\CallerMember, 1: list<\Tests\Integration\Fixtures\CallerMembership>}
     */
    protected function seedMember(string $email, int $memberships = 1): array
    {
        $member = CallerMember::query()->create(['email' => $email, 'password' => app(Hasher::class)->make(self::MEMBER_PASSWORD)]);
        $made   = [];

        for ($index = 0; $index < $memberships; $index++) {
            $made[] = CallerMembership::query()->create(['identity_id' => $member->getKey()]);
        }

        return [$member, $made];
    }

    /**
     * Sign the member in on the guard, as the membership named or its only one,
     * from a request of its own, and return the session.
     *
     * @param  string  $email
     * @param  ?\Tests\Integration\Fixtures\CallerMembership  $membership
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    protected function signedIn(string $email, ?CallerMembership $membership = null, string $guard = self::MEMBERS): SignedInSession
    {
        $session = $this->memberSignIn($email, $membership, $guard)->session;

        self::assertNotNull($session);

        return $session;
    }

    /**
     * Sign the member in on the guard, naming the membership, if any, from a
     * request of its own, and return the result, active or pending.
     *
     * @param  string  $email
     * @param  ?\Tests\Integration\Fixtures\CallerMembership  $membership
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    protected function memberSignIn(string $email, ?CallerMembership $membership = null, string $guard = self::MEMBERS): SignInResult
    {
        $request = Request::create('/sign-in', 'POST');

        app()->instance('request', $request);

        Auth::forgetGuards();

        return Auth::sessions($guard)->signIn('password', ['email' => $email, 'password' => self::MEMBER_PASSWORD], SignInContext::fromRequest($request, principal: $membership));
    }
}
