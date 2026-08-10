export const TAKOSUMI_API_VERSION = "takosumi.dev/v1alpha1" as const;

export interface DevPrincipal {
  readonly sub: `tsub_${string}`;
  readonly email: string;
  readonly name: string;
}

export interface DevWorkspace {
  readonly id: string;
  readonly handle: string;
  readonly displayName: string;
  readonly type: "personal" | "organization";
  readonly ownerUserId: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface DevCapsule {
  readonly id: string;
  readonly workspaceId: string;
  readonly projectId: string;
  readonly name: string;
  readonly slug: string;
  readonly sourceId: string;
  readonly installConfigId: string;
  readonly environment: string;
  readonly currentStateGeneration: number;
  readonly status: "pending" | "active" | "stale" | "error" | "disabled" | "destroyed";
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface DevSource {
  readonly id: string;
  readonly workspaceId: string;
  readonly name: string;
  readonly url: string;
  readonly defaultRef: string;
  readonly defaultPath: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface DevRun {
  readonly id: string;
  readonly workspaceId: string;
  readonly capsuleId?: string;
  readonly type: "source_sync" | "plan" | "apply" | "destroy_plan";
  readonly status: "succeeded" | "awaiting_approval";
  readonly requiresApproval: boolean;
  readonly summary: string;
  readonly createdBy: string;
  readonly createdAt: string;
  readonly finishedAt?: string;
}

export interface DevInterface {
  readonly apiVersion: typeof TAKOSUMI_API_VERSION;
  readonly kind: "Interface";
  readonly metadata: {
    readonly id: string;
    readonly workspaceId: string;
    readonly name: string;
    readonly ownerRef: { readonly kind: "Workspace" | "Capsule" | "Resource"; readonly id: string };
    readonly generation: number;
    readonly labels?: Readonly<Record<string, string>>;
    readonly createdAt: string;
    readonly updatedAt: string;
  };
  readonly spec: {
    readonly type: string;
    readonly version: string;
    readonly document: unknown;
    readonly access: {
      readonly visibility: "private" | "workspace" | "public";
      readonly resourceUriInput?: string;
    };
  };
  readonly status: {
    readonly phase: "Resolved";
    readonly observedGeneration: number;
    readonly resolvedRevision: number;
    readonly resolvedInputs?: Readonly<Record<string, unknown>>;
    readonly resourceUri?: string;
  };
}

export interface DevInterfaceBinding {
  readonly apiVersion: typeof TAKOSUMI_API_VERSION;
  readonly kind: "InterfaceBinding";
  readonly metadata: {
    readonly id: string;
    readonly workspaceId: string;
    readonly generation: number;
    readonly createdAt: string;
    readonly updatedAt: string;
  };
  readonly spec: {
    readonly interfaceId: string;
    readonly subjectRef: {
      readonly kind: "Principal" | "ServiceAccount" | "Capsule" | "Resource";
      readonly id: string;
    };
    readonly permissions: readonly string[];
    readonly delivery: { readonly type: string };
  };
  readonly status: {
    readonly phase: "Ready" | "Revoked";
    readonly observedInterfaceRevision: number;
  };
}

export interface DevFixture {
  readonly principals: readonly DevPrincipal[];
  readonly workspaces: readonly DevWorkspace[];
  readonly memberships: Readonly<Record<string, readonly string[]>>;
  readonly sources: readonly DevSource[];
  readonly capsules: readonly DevCapsule[];
  readonly runs: readonly DevRun[];
  readonly interfaces: readonly DevInterface[];
  readonly bindings: readonly DevInterfaceBinding[];
}

export interface MutableDevFixture {
  principals: DevPrincipal[];
  workspaces: DevWorkspace[];
  memberships: Record<string, string[]>;
  sources: DevSource[];
  capsules: DevCapsule[];
  runs: DevRun[];
  interfaces: DevInterface[];
  bindings: DevInterfaceBinding[];
}
