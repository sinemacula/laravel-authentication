<?php

declare(strict_types = 1);

namespace SineMacula\Laravel\Authentication\Sessions;

use Carbon\CarbonImmutable;
use Carbon\CarbonInterface;
use Illuminate\Http\Request;
use SineMacula\Laravel\Authentication\Contracts\Principal;
use SineMacula\Laravel\Authentication\Http\ClientContext;
use SineMacula\Laravel\Authentication\Http\ClientText;
use SineMacula\Laravel\Authentication\Secrets\Secret;
use SineMacula\Laravel\Authentication\Tenancy\TenantSelection;

/**
 * Where a sign-in comes from and what it asks for: the client (its IP address
 * and user agent, and the same-site facts of its request), the name and
 * platform it gives itself, the principal it wants to act as and the tenant it
 * wants to act in, the refresh token it holds for a session it signed in on
 * before, and a deadline of the session's own. The tenant applies once a
 * principal is selected at sign-in; a choice of principal names its own.
 *
 * A cookie application's `signIn()` and `start()` judge the same-site facts
 * (see `ClientContext`), and refuse a client without them as
 * `cross_site_request`: a `ClientContext` built from the IP address and user
 * agent alone fails there.
 *
 * The client name and platform come from the client, so they are made safe to
 * store as `ClientContext` makes the user agent safe: NUL bytes removed,
 * invalid UTF-8 replaced, and cut to the column's 255 characters; a value that
 * is empty after cleaning is `null`.
 *
 * The principal is verified, not trusted: it must resolve through the
 * resolver's hinted path to the same principal of the same class, owned by the
 * identity signing in. The tenant (`null` for the principal's default: its own
 * tenant, or none for a platform principal) is admitted as the session's active
 * tenant once a principal is selected: the principal's own, or one the
 * `TenantResolver` finds and `TenantAccess` lets it act in, active (refused as
 * `tenant_ineligible` or `tenant_inactive`). It is the application's to pass,
 * never read from the request. The refresh token, which an application passes
 * only when it wants a re-sign-in to replace the client's previous session,
 * proves the client holds that session: the sign-in then revokes it
 * (`superseded`) as it creates the new one (see the session service). Without
 * it nothing else is revoked. It is held as a `Secret`; a string given is
 * wrapped, and an empty one is no token.
 *
 * The deadline (`notAfter`, cut to the whole second) caps the session the
 * sign-in starts: its absolute deadline is the earlier of it and the
 * application's absolute limit, or it alone when the application sets none, and
 * refresh, a switch and a reauthentication never move it. An external
 * provider's session deadline is one source. It is the application's or a
 * trusted adapter's to supply, never read from the request, and a sign-in whose
 * deadline has already passed is refused as `session_expired`.
 *
 * @api
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 */
final readonly class SignInContext
{
    /** @var int Longest client name or platform kept, in characters. */
    private const int DESCRIPTION_MAX_LENGTH = 255;

    /** @var ?string Cleaned name the client gave itself. */
    public ?string $clientName;

    /** @var ?string Cleaned platform the client reported. */
    public ?string $platform;

    /** @var ?\Carbon\CarbonImmutable Latest the session may last, cut to the whole second. */
    public ?CarbonImmutable $notAfter;

    /** @var ?\SineMacula\Laravel\Authentication\Secrets\Secret Refresh token of the client's previous session, which the sign-in replaces when it proves it. */
    public ?Secret $refreshToken;

    /**
     * Constructor.
     *
     * @param  \SineMacula\Laravel\Authentication\Http\ClientContext  $client
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string|null  $refreshToken
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $tenant
     */
    public function __construct(

        /** Client the sign-in comes from. */
        public ClientContext $client,

        // Name the client gives itself, such as "Work laptop".
        ?string $clientName = null,

        // Platform the client reports, such as "macOS".
        ?string $platform = null,

        /** Principal the sign-in asks to act as, verified before it is used. */
        public ?Principal $principal = null,

        // Refresh token of the client's previous session, which the sign-in
        // replaces when it proves it.
        #[\SensitiveParameter]
        Secret|string|null $refreshToken = null,

        // Latest the session may last, such as a provider's session deadline.
        ?CarbonInterface $notAfter = null,

        /** Tenant the sign-in asks to act in, admitted before it is used; `null` for the principal's default. */
        public ?TenantSelection $tenant = null,
    ) {
        $this->clientName   = ClientText::clean($clientName, self::DESCRIPTION_MAX_LENGTH);
        $this->platform     = ClientText::clean($platform, self::DESCRIPTION_MAX_LENGTH);
        $this->notAfter     = $notAfter === null ? null : CarbonImmutable::instance($notAfter)->startOfSecond();
        $this->refreshToken = self::secret($refreshToken);
    }

    /**
     * The same context with the deadline capped at `$notAfter` too: the earlier
     * of the two, either alone when the other is absent, none for neither. A
     * deadline is only ever lowered this way.
     *
     * @param  ?\Carbon\CarbonInterface  $notAfter
     * @return self
     */
    public function withNotAfter(?CarbonInterface $notAfter): self
    {
        $earliest = $notAfter === null || ($this->notAfter !== null && $this->notAfter->getTimestamp() <= $notAfter->getTimestamp())
            ? $this->notAfter
            : $notAfter;

        return new self($this->client, $this->clientName, $this->platform, $this->principal, $this->refreshToken, $earliest, $this->tenant);
    }

    /**
     * Whether the deadline has been reached at the given time: a session must
     * end after it starts, so a sign-in whose deadline is this second or
     * earlier cannot start one. A context without a deadline never has.
     *
     * @param  \Carbon\CarbonInterface  $at
     * @return bool
     */
    public function hasPassedDeadline(CarbonInterface $at): bool
    {
        return $this->notAfter !== null && $this->notAfter->getTimestamp() <= $at->getTimestamp();
    }

    /**
     * Read the context of a sign-in from its request, which never supplies a
     * deadline; the principal and tenant to ask for are the application's to
     * pass.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  ?string  $clientName
     * @param  ?string  $platform
     * @param  ?\SineMacula\Laravel\Authentication\Contracts\Principal  $principal
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string|null  $refreshToken
     * @param  ?\SineMacula\Laravel\Authentication\Tenancy\TenantSelection  $tenant
     * @return self
     */
    public static function fromRequest(
        Request $request,
        ?string $clientName = null,
        ?string $platform = null,
        ?Principal $principal = null,
        #[\SensitiveParameter] Secret|string|null $refreshToken = null,
        ?TenantSelection $tenant = null,
    ): self {
        return new self(ClientContext::fromRequest($request), $clientName, $platform, $principal, $refreshToken, tenant: $tenant);
    }

    /**
     * The refresh token as a secret: a string wrapped, an empty one read as no
     * token, and a secret or none kept as it is.
     *
     * @param  \SineMacula\Laravel\Authentication\Secrets\Secret|string|null  $token
     * @return ?\SineMacula\Laravel\Authentication\Secrets\Secret
     */
    private static function secret(#[\SensitiveParameter] Secret|string|null $token): ?Secret
    {
        return match (true) {
            $token === ''     => null,
            is_string($token) => new Secret($token),
            default           => $token,
        };
    }
}
