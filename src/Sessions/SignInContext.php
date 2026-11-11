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
 * Where a sign-in comes from and what it asks for.
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

        // Refresh token of the client's previous session, to replace.
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
     * The same context with the deadline capped at `$notAfter` too, keeping the
     * earlier of the two.
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
     * Whether the deadline is at or before the given second, since a session
     * must end after it starts.
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
     * deadline.
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
     * The refresh token as a secret, with an empty string read as no token.
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
