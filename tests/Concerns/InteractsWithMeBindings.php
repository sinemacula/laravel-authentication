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
use Tests\Integration\Fixtures\MeMember;
use Tests\Integration\Fixtures\MeMembership;
use Tests\Integration\Fixtures\MeSession;

/**
 * Shared set-up for the tests of the `me` route binding: two applications
 * (`members`, the default guard, and `others`) over `MeMember`, whose
 * memberships and sessions use the trait; the member, membership and session
 * tables, the sessions in a soft-deleting table of their own; seeded members;
 * and sign-ins, active or pending.
 *
 * The session table is pointed at once the shipped migrations have run, and
 * pointed back before they are rolled back, as the session model's table is
 * read from the configuration each time.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
trait InteractsWithMeBindings
{
    use InteractsWithSessionRecords;

    /** @var string The guard the routes default to. */
    protected const string MEMBERS = 'members';

    /** @var string A second application over the same members. */
    protected const string OTHERS = 'others';

    /** @var string The soft-deleting table the members' sessions are kept in. */
    protected const string SESSIONS = 'me_sessions';

    /** @var string Plaintext password of every seeded member. */
    protected const string MEMBER_PASSWORD = 'correct horse battery staple';

    /**
     * Create the member, membership and session tables on the connection, or
     * the default one, and point the session model and table at them.
     *
     * @param  ?string  $connection
     * @return void
     */
    protected function createMeTables(?string $connection = null): void
    {
        Schema::connection($connection)->create('me_members', static function (Blueprint $blueprint): void {
            $blueprint->uuid('id')->primary();
            $blueprint->string('email')->unique();
            $blueprint->string('password');
            $blueprint->timestamps();
        });

        Schema::connection($connection)->create('me_memberships', static function (Blueprint $blueprint): void {
            $blueprint->increments('id');
            $blueprint->uuid('identity_id');
            $blueprint->timestamps();
            $blueprint->softDeletes();
        });

        self::createSessionRecordTable(self::SESSIONS, connection: $connection);

        Schema::connection($connection)->table(self::SESSIONS, static function (Blueprint $blueprint): void {
            $blueprint->softDeletes();
        });

        config()->set('authentication.session.model', MeSession::class);
        config()->set('authentication.session.table', self::SESSIONS);
    }

    /**
     * Drop the tables `createMeTables()` created, and point the session table
     * back for the shipped migrations' rollback.
     *
     * @param  ?string  $connection
     * @return void
     */
    protected function dropMeTables(?string $connection = null): void
    {
        foreach ([self::SESSIONS, 'me_memberships', 'me_members'] as $table) {
            Schema::connection($connection)->dropIfExists($table);
        }

        config()->set('authentication.session.table', 'authentication_sessions');
    }

    /**
     * Register both applications over the members, the members' guard the
     * default, each allowing password sign-in, with a cheap password hash and a
     * timebox short enough not to slow the suite.
     *
     * @param  \Illuminate\Config\Repository  $config
     * @return void
     */
    protected static function configureMeGuards(ConfigRepository $config): void
    {
        $application = ['methods' => ['password']];

        $config->set('auth.defaults.guard', self::MEMBERS);
        $config->set('auth.providers.me_members', ['driver' => 'model', 'model' => MeMember::class]);
        $config->set('auth.guards.' . self::MEMBERS, ['driver' => 'jwt', 'provider' => 'me_members', 'application' => $application]);
        $config->set('auth.guards.' . self::OTHERS, ['driver' => 'jwt', 'provider' => 'me_members', 'application' => $application]);
        $config->set('hashing.bcrypt.rounds', 4);
        $config->set('authentication.timebox.credentials_microseconds', 1);
    }

    /**
     * Persist a member with the given number of memberships.
     *
     * @param  string  $email
     * @param  int  $memberships
     * @return array{0: \Tests\Integration\Fixtures\MeMember, 1: list<\Tests\Integration\Fixtures\MeMembership>}
     */
    protected function seedMember(string $email, int $memberships = 1): array
    {
        $member = MeMember::query()->create(['email' => $email, 'password' => app(Hasher::class)->make(self::MEMBER_PASSWORD)]);
        $made   = [];

        for ($index = 0; $index < $memberships; $index++) {
            $made[] = MeMembership::query()->create(['identity_id' => $member->getKey()]);
        }

        return [$member, $made];
    }

    /**
     * Sign the member in on the guard, as the membership named or its only one,
     * from a request of its own, and return the session.
     *
     * @param  string  $email
     * @param  ?\Tests\Integration\Fixtures\MeMembership  $membership
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignedInSession
     *
     * @throws \Throwable
     */
    protected function signedIn(string $email, ?MeMembership $membership = null, string $guard = self::MEMBERS): SignedInSession
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
     * @param  ?\Tests\Integration\Fixtures\MeMembership  $membership
     * @param  string  $guard
     * @return \SineMacula\Laravel\Authentication\Sessions\SignInResult
     *
     * @throws \Throwable
     */
    protected function memberSignIn(string $email, ?MeMembership $membership = null, string $guard = self::MEMBERS): SignInResult
    {
        $request = Request::create('/sign-in', 'POST');

        app()->instance('request', $request);

        Auth::forgetGuards();

        return Auth::sessions($guard)->signIn('password', ['email' => $email, 'password' => self::MEMBER_PASSWORD], SignInContext::fromRequest($request, principal: $membership));
    }
}
