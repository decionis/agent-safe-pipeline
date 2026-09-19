export {
  EVIDENCE_BUNDLE_VERSION,
  EvidenceError,
  EvidenceExport,
  LineWindow,
  type BundleFile,
  type EvidenceBundle,
  type EvidenceBundleManifest,
  type EvidenceExportInput,
  type EvidenceExportOptions,
} from "./incident/EvidenceExport.js";
export {
  verifyEvidenceBundle,
  type BundleFinding,
  type BundleFindingCode,
  type BundleSource,
  type BundleVerification,
} from "./verify/VerifyEvidenceBundle.js";
export {
  adapterActionHandler,
  effectBlock,
  type AdapterExecutionResult,
  type AdapterHandlerOptions,
} from "./adapters/AdapterActionHandler.js";
export {
  IndeterminateOutcome,
  type AdapterExecution,
  type AdapterReconciliation,
  type EffectAdapter,
  type ObservationMethod,
  type PreparedAction,
  type ProjectionValue,
  type ProviderReconciliationResult,
  type ProviderResult,
} from "./adapters/EffectAdapter.js";
export {
  EffectAwareGrantVerifier,
  type EffectAwareGrantVerifierOptions,
} from "./adapters/EffectAwareGrantVerifier.js";
export {
  compareEffect,
  compareReceipt,
  receiptStatement,
  type Comparison,
  type EffectComparisonResult,
  type ReceiptComparison,
  type ReceiptStatement,
  type ReceiptStatus,
} from "./adapters/EffectComparison.js";
export {
  EFFECT_EVIDENCE_PROFILE,
  authorityEffectEvidence,
  buildEffectRecord,
  confirmationFor,
  type ConfirmationStatus,
  type EffectOutcome,
  type EvidenceInput,
} from "./adapters/EffectEvidenceBuilder.js";
export {
  EffectEvidenceRegister,
  type RegisteredEffect,
} from "./adapters/EffectEvidenceRegister.js";
export {
  assertIJson,
  isWellFormedUtf16,
  jcsCanonical,
  jcsDigest,
  JcsError,
  type Sha256,
} from "./adapters/JcsDigest.js";
export {
  BankingActionSchema,
  BankingActionWireSchema,
  BEAP_PROFILE,
  isBankingActionName,
  transportActionName,
  transportTarget,
  type BankingAction,
} from "./adapters/banking/BankingAction.js";
export {
  BankingActionError,
  BankingAdapter,
  registeredActionNames,
  type BankingAdapterOptions,
  type BankingTransport,
} from "./adapters/banking/BankingAdapter.js";
export { bankingHandlers, type BankingHandlerOptions } from "./adapters/banking/BankingHandlers.js";
export {
  bindBankingAction,
  BindingError,
  type BindingInput,
  type BoundBankingAction,
} from "./adapters/banking/BankingIntentBinder.js";
export {
  CoreBankingHttpAdapter,
  type CoreBankingHttpOptions,
} from "./adapters/banking/CoreBankingHttpAdapter.js";
export {
  CurrencyError,
  isSupportedCurrency,
  minorUnitExponent,
  supportedCurrencies,
} from "./adapters/banking/Currency.js";
export {
  BASE_PROJECTION,
  expectedEffect,
  ProjectionError,
  projectionValue,
  PROJECTION_PROFILE,
  registeredAction,
  REGISTERED_ACTIONS as REGISTERED_BANKING_ACTIONS,
  type RegisteredAction,
} from "./adapters/banking/EffectProjections.js";
export { ibanFromReference, isValidIban, referenceIsValid } from "./adapters/banking/Iban.js";
export { Money, MoneyError } from "./adapters/banking/Money.js";
export {
  EFFECT_REASON_CODES,
  EXECUTION_REASON_CODES,
  isBankingReasonCode,
  REASON_CODE_CATEGORIES,
  type BankingReasonCode,
  type EffectReasonCode,
  type ExecutionReasonCode,
} from "./adapters/banking/ReasonCodes.js";
export {
  ChainJournal,
  type ChainJournalFs,
  type ChainJournalOptions,
} from "./audit/ChainJournal.js";
export {
  CHAIN_GENESIS,
  HashChain,
  type ChainFields,
  type ChainHead,
  type ChainedRecord,
} from "./audit/HashChain.js";
export { EVIDENCE_STREAM, HashChainedAuditSink } from "./audit/HashChainedAuditSink.js";
export { LineAuditSink, type LineWriter } from "./audit/LineAuditSink.js";
export { CONFIG_KEYS, SECRET_KEYS, type ConfigKey } from "./config/ConfigKeys.js";
export {
  ExecutorConfigLoader,
  type DownstreamConfig,
  type DownstreamCredentialConfig,
  type EgressConfig,
  type IdentityConfig,
  type DownstreamCredentialConfig as DownstreamCredentialSettings,
  type EscalationConfig,
  type EscalationMode,
  type EvidenceConfig,
  type HaltConfig,
  type LimitsConfig,
  type ExecutorConfig,
  type ExecutorMode,
  type ListenerConfig,
  type PostureSettings,
  type TrustAnchor,
  type VerificationLevel,
  type VerificationMethod,
} from "./config/ExecutorConfig.js";
export { CredentialError } from "./credential/CredentialError.js";
export type {
  DownstreamCredential,
  DownstreamGrant,
  DownstreamRequest,
} from "./credential/DownstreamCredential.js";
export { grantOf } from "./credential/GrantOf.js";
export {
  CLIENT_ASSERTION_TYPE,
  PrivateKeyJwtCredential,
  type PrivateKeyJwtAlgorithm,
  type PrivateKeyJwtOptions,
} from "./credential/PrivateKeyJwtCredential.js";
export {
  ATTESTATION_COMPONENT,
  BASE_COMPONENTS,
  GRANT_COMPONENTS,
  SIGNATURE_LABEL,
  SIGNED_COMPONENTS,
  SignedRequestCredential,
  type SignedComponent,
  type SignedRequestAlgorithm,
  type SignedRequestMaterial,
  type SignedRequestOptions,
  type SignedRequestVerification,
} from "./credential/SignedRequestCredential.js";
export { StaticHeaderCredential } from "./credential/StaticHeaderCredential.js";
export { EgressError, type EgressCode } from "./egress/EgressError.js";
export { EgressPolicy, type EgressCheck, type EgressDestination } from "./egress/EgressPolicy.js";
export {
  isGlobalFetchLocked,
  lockGlobalFetch,
  type FetchHolder,
} from "./egress/GlobalFetchLock.js";
export {
  GuardedFetch,
  type AddressResolver,
  type GuardedFetchOptions,
  type ResolvedAddress,
} from "./egress/GuardedFetch.js";
export {
  FORWARD_REQUEST_ACTION,
  REGISTERED_ACTIONS,
  forwardRequestHandlers,
  registerHandlers,
  type DownstreamResult,
} from "./handlers/ForwardRequestHandler.js";
export {
  JournaledRegistry,
  callerPrincipal,
  journaledActionHandler,
  requestDigest,
} from "./handlers/JournaledActionHandler.js";
export type {
  FetchLike,
  HandlerRegistration,
  HandlerRegistrationContext,
} from "./handlers/HandlerRegistration.js";
export { ExecutorHttpServer, type ExecutorHttpServerOptions } from "./http/ExecutorHttpServer.js";
export {
  LEGACY_CALLER_PRINCIPAL,
  RequestContext,
  type RequestScope,
} from "./http/RequestContext.js";
export {
  MAX_BODY_BYTES,
  METRICS_CONTENT_TYPE,
  RESPONSE_HEADERS,
  ROUTES,
  type RouteDefinition,
  type RoutePath,
} from "./http/Routes.js";
export {
  AuthError,
  Authenticator,
  UNAUTHENTICATED_KEY,
  type AuthMethod,
  type AuthenticatedPrincipal,
  type AuthenticationInput,
  type AuthenticatorOptions,
} from "./identity/Authenticator.js";
export {
  normaliseFingerprint,
  peerIdentity,
  type PeerIdentity,
  type PeerSocket,
} from "./identity/PeerIdentity.js";
export {
  LEGACY_CALLER_ID,
  PrincipalRegistry,
  type ClaimValue,
  type Comparator,
  type LegacyContext,
  type Principal,
  type PrincipalActor,
  type PrincipalCredential,
  type RegistryContext,
  type Role,
} from "./identity/PrincipalRegistry.js";
export {
  MAX_PRINCIPALS,
  OPERATOR_SCOPES,
  PRINCIPALS_VERSION,
  PrincipalCredentialSchema,
  PrincipalsError,
  PrincipalsFileSchema,
  credentialIdentity,
  parsePrincipalsFile,
  type OperatorScope,
  type PrincipalCredentialEntry,
  type PrincipalEntry,
} from "./identity/PrincipalsFile.js";
export { RateLimiter, type LockoutRule, type RateLimitRule } from "./identity/RateLimiter.js";
export { assertSeparationOfDuties, separationViolated } from "./identity/SeparationOfDuties.js";
export {
  JWT_ALGORITHMS,
  JwtError,
  WorkloadJwtVerifier,
  type JwksRefresh,
  type JwtCode,
  type VerifiedJwt,
  type WorkloadJwtVerifierOptions,
} from "./identity/WorkloadJwtVerifier.js";
export {
  TLS12_CIPHERS,
  TlsListener,
  type TlsListenerOptions,
  type TlsMaterial,
  type TlsMinVersion,
} from "./http/TlsListener.js";
export {
  Counter,
  Gauge,
  Metrics,
  executorMetrics,
  type ExecutorMetrics,
  type LabelValues,
} from "./incident/Metrics.js";
export {
  HaltSwitch,
  type HaltState,
  type HaltSwitchOptions,
  type HaltTrigger,
} from "./incident/HaltSwitch.js";
export { regularFileExists, watchDirectory } from "./incident/FileProbe.js";
export {
  CONTAINMENT_STREAM,
  parseTarget,
  probeContainment,
  verdictFor,
  type ContainmentFinding,
  type ContainmentProbeOptions,
  type ContainmentReport,
  type ContainmentTarget,
  type ContainmentVerdict,
} from "./containment/ContainmentProbe.js";
export { dial, dialOutcomeFor, type DialOutcome } from "./egress/TcpProbe.js";
export {
  JOURNAL_VERSION,
  JournalError,
  JournalRecordSchema,
  openAttemptsFrom,
  type ExecutionJournal,
  type JournalRecord,
  type JournalRecordKind,
  type OpenAttempt,
} from "./journal/ExecutionJournal.js";
export {
  FileExecutionJournal,
  MAX_RECORD_BYTES,
  type FileExecutionJournalOptions,
} from "./journal/FileExecutionJournal.js";
export { InMemoryExecutionJournal } from "./journal/InMemoryExecutionJournal.js";
export {
  StartupReconciler,
  type AttemptResolution,
  type RecoveryReport,
  type ResolvedAttempt,
  type StartupReconcilerOptions,
} from "./journal/StartupReconciler.js";
export {
  HardLimits,
  type HardLimitCode,
  type HardLimitSettings,
  type LimitCheck,
  type MonetaryValue,
} from "./limits/HardLimits.js";
export { MonotonicDeadline, dispatchBudgetMs } from "./time/MonotonicClock.js";
export { clockSkewGuard, type ClockSkewGuardOptions } from "./time/ClockSkewGuard.js";
export {
  SECURITY_STREAM,
  SecurityEventSchema,
  SecurityEvents,
  type SecurityEvent,
  type SecurityEventsOptions,
} from "./incident/SecurityEvents.js";
export { LineEmitter, type LineSinks } from "./logging/LineEmitter.js";
export {
  HostPosture,
  PostureError,
  type HostPostureOptions,
  type PostureMode,
  type PostureReport,
  type PostureState,
} from "./posture/HostPosture.js";
export {
  DRIFT_CHECKS,
  INSPECTED_ENVIRONMENT,
  SERVICE_ACCOUNT_TOKEN,
  WAIVABLE_CHECKS,
  processFacts,
  type PostureCheckId,
  type PostureConfig,
  type PostureFacts,
  type PostureFinding,
} from "./posture/PostureChecks.js";
export {
  CompositeSecretStore,
  type EnvironmentSecretOptions,
} from "./secrets/CompositeSecretStore.js";
export { EnvSecretStore } from "./secrets/EnvSecretStore.js";
export {
  FileSecretStore,
  MAX_SECRET_BYTES,
  type FileSecretStoreOptions,
} from "./secrets/FileSecretStore.js";
export {
  MAX_LINE_BYTES,
  Redactor,
  type Redaction,
  type RedactionPattern,
} from "./secrets/Redactor.js";
export { SecretHandle } from "./secrets/SecretHandle.js";
export {
  SecretError,
  type ReloadReason,
  type ReloadReport,
  type SecretName,
  type SecretStore,
} from "./secrets/SecretStore.js";
export {
  AuthorityClients,
  type AuthorityClientSet,
  type AuthorityClientsOptions,
} from "./service/AuthorityClients.js";
export {
  EscalationHandoffSchema,
  EscalationResolver,
  type EscalationDependencies,
  type EscalationHandoff,
  type EscalationResolution,
  type EscalationState,
} from "./service/EscalationResolver.js";
export {
  HaltRequestSchema,
  ProposalRequestSchema,
  ReconciliationRequestSchema,
  ResumeRequestSchema,
  type ActionResponse,
  type HaltRequest,
  type AuthorizationBinding,
  type ProposalRequest,
  type ReconciliationRequest,
  type ReconciliationResponse,
} from "./service/Requests.js";
export { ServiceError } from "./service/ServiceError.js";
export {
  TrustedExecutorService,
  type ExecutorStatus,
  type Readiness,
  type ServiceDependencies,
} from "./service/TrustedExecutorService.js";
export { nodeProcess, serve, type ServeProcess } from "./Serve.js";
export {
  verifyAuditChain,
  type ChainFinding,
  type ChainFindingCode,
  type ChainVerification,
  type StreamSummary,
} from "./verify/VerifyAuditChain.js";
export {
  ATTESTATION_TYPE,
  JCS_PROFILE,
  MemoryReplayStore,
  parseIJson,
  refusalBody,
  verifyProviderRequest,
  type ClaimAttestationClaims,
  type ExecutorKey,
  type ProviderRefusalCode,
  type ProviderVerdict,
  type ReceivedRequest,
  type ReplayStore,
  type VerifyingProviderOptions,
} from "./verify/VerifyingProvider.js";
export {
  EFFECT_RECEIPT_HEADER,
  EFFECT_RECEIPT_TYPE,
  EffectReceiptError,
  effectReceiptClaims,
  effectReceiptSigningInput,
  signEffectReceipt,
  type AttestedClaim,
  type EffectReceiptEffect,
  type EffectReceiptInput,
  type EffectStatus,
} from "./verify/EffectReceipt.js";
export {
  createTrustedExecutor,
  type TrustedExecutor,
  type TrustedExecutorDependencies,
  type TrustedExecutorOptions,
} from "./TrustedExecutor.js";
export {
  Gateway,
  GATEWAY_PREFIX,
  GATEWAY_RESPONSE_VERSION,
  GATEWAY_STREAM,
  type GatewayDependencies,
  type GatewayIo,
  type GatewayResponse,
  type GatewayStatus,
} from "./gateway/Gateway.js";
export {
  ACTION_NAME,
  CONSEQUENTIAL_METHODS,
  DEFAULT_AUTHORITY_ENDPOINT,
  DEFAULT_LISTEN,
  GATEWAY_ENVIRONMENT,
  GatewayConfigError,
  GatewayConfigLoader,
  GatewayFileSchema,
  LOCAL_TENANT_ID,
  renderConfigFile,
  type AuthorityKind,
  type ConfigSource,
  type ConsequentialMethod,
  type FailurePolicy,
  type GatewayConfig,
  type GatewayConfigInput,
  type GatewayFile,
  type GatewayFlags,
  type GatewayMode,
  type OutputFormat,
  type RouteConfig,
  type StoredCredentials,
  type UnmatchedPolicy,
} from "./gateway/GatewayConfig.js";
export {
  ACTIVATION_MILESTONES,
  ActivationFunnel,
  type ActivationContext,
  type ActivationMilestone,
  type ActivationReport,
} from "./gateway/Activation.js";
export {
  DEMO_AUTONOMOUS_LIMIT_MINOR,
  DEMO_HUMAN_LIMIT_MINOR,
  amountMinorOf,
  demoPolicy,
  startDemoAuthority,
  type DemoAuthorityHandle,
  type DemoPolicyRequest,
} from "./gateway/DemoAuthority.js";
export {
  HttpActionParametersSchema,
  RequestHolder,
  httpForwardHandler,
  registerHttpActions,
  type ForwardOutcome,
} from "./gateway/ForwardHandler.js";
export { gatewayMetrics, type GatewayMetrics } from "./gateway/GatewayMetrics.js";
export {
  executionLabel,
  renderHuman,
  renderJson,
  stateLabel,
  type ActivationMilestoneReport,
  type ExecutionDisposition,
  type GatewayReport,
  type GatewayState,
  type InterceptionReport,
  type NoteReport,
  type RenderOptions,
  type StartedReport,
  type StoppedReport,
} from "./gateway/GatewayReport.js";
export {
  bodyDigest,
  normalizeRequest,
  type HttpActionContext,
  type HttpActionParameters,
  type InterceptedRequest,
  type NormalizedAction,
} from "./gateway/InterceptedRequest.js";
export { RouteTable, derivedAction, type RoutePlan } from "./gateway/RouteTable.js";
export {
  Upstream,
  UpstreamResponseTooLarge,
  type UpstreamOptions,
  type UpstreamResult,
} from "./gateway/Upstream.js";
export {
  GatewayHttpServer,
  type GatewayHttpServerOptions,
  type GatewaySelector,
} from "./http/GatewayHttpServer.js";
export { packageVersion } from "./Version.js";
export {
  ArgumentError,
  optionPort,
  optionValue,
  parseArguments,
  type ArgumentSpec,
  type ParsedArguments,
} from "./cli/Arguments.js";
export { nodeCliProcess, nodeFiles, type CliFiles, type CliProcess } from "./cli/CliProcess.js";
export {
  GATEWAY_COMMANDS,
  isGatewayCommand,
  runGatewayCommand,
  type GatewayCommand,
} from "./cli/Commands.js";
export {
  ConfigFileError,
  DEFAULT_CONFIG_FILE,
  loadConfigFile,
  locateConfigFile,
  type LoadedConfigFile,
} from "./cli/ConfigFile.js";
export {
  credentialsDirectory,
  credentialsPath,
  readCredentials,
  removeCredentials,
  writeCredentials,
} from "./cli/Credentials.js";
export { effectiveConfig, runConfig } from "./cli/ConfigCommand.js";
export { DOCTOR_ARGUMENTS, runDoctor, type DoctorCheck, type DoctorOptions } from "./cli/Doctor.js";
export { usage } from "./cli/Help.js";
export {
  INIT_ARGUMENTS,
  actionNameFrom,
  routesFromOpenApi,
  runInit,
  upstreamFromPackage,
  type InitReport,
} from "./cli/Init.js";
export { LOGIN_ARGUMENTS, runLogin, runLogout } from "./cli/Login.js";
export {
  PROXY_ARGUMENTS,
  explainRefusal,
  gatewayFlags,
  refusalLine,
  resolveGateway,
  runProxy,
  speaksJson,
  type ResolvedGateway,
} from "./cli/Proxy.js";
export { runStatus } from "./cli/Status.js";
