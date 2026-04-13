# Changed Files (master...HEAD)

139 files sorted into enforcement chunks (124 PHP + 15 non-PHP).

## Chunk 1: Non-PHP files (15 files)

1. ISSUES.md
2. README.md

## Chunk 2: Benchmarks (11 files)

1. benchmarks/Crypto/JwtTokenServiceBench.php
2. benchmarks/Runtime/BasicGuardBench.php
3. benchmarks/Runtime/JwtGuardBench.php
4. benchmarks/Runtime/RefreshTokenExchangeBench.php
5. benchmarks/Runtime/UpdateDeviceTimestampBench.php
6. benchmarks/Support/BasicGuardBenchHarness.php
7. benchmarks/Support/BenchDatabase.php
8. benchmarks/Support/ImmediateTimebox.php
9. benchmarks/Support/JwtGuardBenchHarness.php
10. benchmarks/Support/RefreshTokenExchangeBenchHarness.php
11. benchmarks/Support/UpdateDeviceTimestampBenchHarness.php

## Chunk 3: Config, Migration, Scripts (3 files)

1. config/authentication.php
2. database/migrations/2026_04_06_000000_create_devices_table.php
3. scripts/ci/render-phpbench-summary.php

## Chunk 4: Source - Core (5 files)

1. src/AuthManager.php
2. src/AuthServiceProvider.php
3. src/Facades/Auth.php
4. src/Guards/AbstractGuard.php
5. src/Guards/JwtGuard.php

## Chunk 5: Source - Guards, Providers, Resolvers (7 files)

1. src/Guards/BasicGuard.php
2. src/Guards/Concerns/BindsContextualState.php
3. src/Guards/Concerns/ValidatesGuardCredentials.php
4. src/Providers/ModelProvider.php
5. src/Resolvers/DefaultPrincipalResolver.php
6. src/Resolvers/UnresolvableIdentityException.php
7. src/Listeners/UpdateDeviceTimestamp.php

## Chunk 6: Source - Contracts (13 files)

1. src/Contracts/CanBeActive.php
2. src/Contracts/ContextualGuard.php
3. src/Contracts/Device.php
4. src/Contracts/EloquentDevice.php
5. src/Contracts/HasDevices.php
6. src/Contracts/HasPrincipals.php
7. src/Contracts/HasType.php
8. src/Contracts/Identity.php
9. src/Contracts/IdentityProvider.php
10. src/Contracts/Principal.php
11. src/Contracts/PrincipalResolver.php
12. src/Contracts/ResolvesHintedPrincipal.php
13. src/Contracts/Tenant.php

## Chunk 7: Source - JWT (10 files)

1. src/Jwt/Enums/Claims.php
2. src/Jwt/Enums/TokenType.php
3. src/Jwt/ExchangedRefresh.php
4. src/Jwt/IdentifierCoercion.php
5. src/Jwt/InvalidJwtConfigurationException.php
6. src/Jwt/JwtKeyring.php
7. src/Jwt/JwtTokenService.php
8. src/Jwt/JwtTokenServiceFactory.php
9. src/Jwt/RefreshResult.php
10. src/Jwt/RefreshTokenHasher.php

## Chunk 8: Source - JWT Exchange, Models, Traits (10 files)

1. src/Jwt/RefreshTokenExchange.php
2. src/Models/Device.php
3. src/Traits/ActsAsDevice.php
4. src/Traits/ActsAsPrincipal.php
5. src/Traits/ActsAsTenant.php
6. src/Traits/Authenticatable.php
7. src/Traits/ProvidesTenantType.php
8. src/Cache/NullResolutionCache.php
9. src/Cache/ResolutionCache.php
10. src/Cache/ResolutionCacheInvalidator.php

## Chunk 9: Source - Cache, Config, Database, Events, Exceptions (10 files)

1. src/Cache/StoreBackedResolutionCache.php
2. src/Config/ResolutionCacheConfig.php
3. src/Database/DeviceTableAlreadyExistsException.php
4. src/Database/MigrationCollisionGuard.php
5. src/Events/DeviceAuthenticated.php
6. src/Events/Enums/RefreshFailureReason.php
7. src/Events/PrincipalAssigned.php
8. src/Events/RefreshFailed.php
9. src/Events/Refreshed.php
10. src/Exceptions/InvalidDeviceModelConfiguration.php

## Chunk 10: Tests - Feature (Auth, Cache) (10 files)

1. tests/Feature/AuthManagerTest.php
2. tests/Feature/AuthServiceProviderGuardConfigTest.php
3. tests/Feature/AuthServiceProviderHelpersTest.php
4. tests/Feature/AuthServiceProviderTest.php
5. tests/Feature/Cache/ResolutionCacheTest.php
6. tests/Feature/Guards/AbstractGuardContextualTest.php
7. tests/Feature/Guards/AbstractGuardLifecycleTest.php
8. tests/Feature/Guards/JwtGuardRefreshTest.php
9. tests/Feature/Guards/JwtGuardTestCase.php
10. tests/Feature/Guards/JwtGuardUserResolutionTest.php

## Chunk 11: Tests - Feature (JWT, Listeners, Models) (4 files)

1. tests/Feature/Jwt/JwtTokenServiceFactoryTest.php
2. tests/Feature/Jwt/RefreshTokenExchangeTest.php
3. tests/Feature/Listeners/UpdateDeviceTimestampTest.php
4. tests/Feature/Models/DeviceTest.php

## Chunk 12: Tests - Integration (13 files)

1. tests/Integration/Config/DeviceModelOverrideTest.php
2. tests/Integration/Events/StandardAuthEventsIntegrationTest.php
3. tests/Integration/Fixtures/TenantAware3dIdentity.php
4. tests/Integration/Fixtures/TenantAware3dPrincipal.php
5. tests/Integration/Fixtures/TenantAware3dTenant.php
6. tests/Integration/Guards/AccessOnlyIntegrationTest.php
7. tests/Integration/Guards/GuardCoexistenceIntegrationTest.php
8. tests/Integration/Guards/GuardScopedJwtIssuanceIntegrationTest.php
9. tests/Integration/Guards/GuardScopedPrincipalResolverIntegrationTest.php
10. tests/Integration/Guards/JwtGuardIntegrationTest.php
11. tests/Integration/Guards/JwtGuardRefreshPrincipalContinuityIntegrationTest.php
12. tests/Integration/Guards/JwtGuardResolutionFreshnessIntegrationTest.php
13. tests/Integration/Guards/TenantAwareThreeDimensionalResolutionIntegrationTest.php

## Chunk 13: Tests - Performance (7 files)

1. tests/Performance/Fixtures/PerformanceAccessOnlyIdentity.php
2. tests/Performance/JwtGuardCoexistenceQueryBudgetTest.php
3. tests/Performance/JwtGuardFailureBudgetTest.php
4. tests/Performance/JwtGuardQueryBudgetTest.php
5. tests/Performance/PerformanceContractTestCase.php
6. tests/Performance/RefreshTokenExchangeQueryBudgetTest.php
7. tests/Performance/UpdateDeviceTimestampQueryBudgetTest.php

## Chunk 14: Tests - Unit (15 files)

1. tests/Unit/Contracts/ContractDeclarationTest.php
2. tests/Unit/Events/DeviceAuthenticatedTest.php
3. tests/Unit/Events/PrincipalAssignedTest.php
4. tests/Unit/Events/RefreshFailedTest.php
5. tests/Unit/Events/RefreshedTest.php
6. tests/Unit/Guards/BasicGuardTest.php
7. tests/Unit/Jwt/ExchangedRefreshTest.php
8. tests/Unit/Jwt/JwtTokenServiceIssueTest.php
9. tests/Unit/Jwt/JwtTokenServiceParseTest.php
10. tests/Unit/Jwt/RefreshResultTest.php
11. tests/Unit/Providers/ModelProviderTest.php
12. tests/Unit/Resolvers/DefaultPrincipalResolverTest.php
13. tests/Unit/Stubs/BareDeviceModel.php
14. tests/Unit/Stubs/StubDevice.php
15. tests/Unit/Stubs/StubLookupIdentityProvider.php

## Chunk 15: Tests - Unit (Stubs, Traits) (6 files)

1. tests/Unit/Stubs/StubTwoDPrincipalResolver.php
2. tests/Unit/Traits/ActsAsDeviceTest.php
3. tests/Unit/Traits/ActsAsPrincipalTest.php
4. tests/Unit/Traits/ActsAsTenantTest.php
5. tests/Unit/Traits/AuthenticatableTest.php
6. tests/Unit/Traits/ProvidesTenantTypeTest.php
