import type {
  DevCapsule,
  DevFixture,
  DevInterface,
  DevInterfaceBinding,
  DevPrincipal,
  DevRun,
  DevSource,
  DevWorkspace,
  MutableDevFixture,
} from "./types.ts";

const DEFAULT_TIMESTAMP = "2026-01-01T00:00:00.000Z";

export function defaultFixture(): MutableDevFixture {
  const principal: DevPrincipal = {
    sub: "tsub_local",
    email: "developer@local.test",
    name: "Local Developer",
  };
  const workspace: DevWorkspace = {
    id: "ws_local",
    handle: "local",
    displayName: "Local Workspace",
    type: "personal",
    ownerUserId: principal.sub,
    createdAt: DEFAULT_TIMESTAMP,
    updatedAt: DEFAULT_TIMESTAMP,
  };
  return {
    principals: [principal],
    workspaces: [workspace],
    memberships: { [workspace.id]: [principal.sub] },
    sources: [],
    capsules: [],
    runs: [],
    interfaces: [],
    bindings: [],
  };
}

export class DevStore {
  readonly #state: MutableDevFixture;
  readonly #file: string | undefined;
  #write: Promise<void> = Promise.resolve();

  private constructor(state: MutableDevFixture, file?: string) {
    this.#state = state;
    this.#file = file;
  }

  static async open(file?: string): Promise<DevStore> {
    if (!file) return new DevStore(defaultFixture());
    const input = Bun.file(file);
    if (!(await input.exists())) return new DevStore(defaultFixture(), file);
    const parsed = (await input.json()) as Partial<DevFixture>;
    return new DevStore(normalizeFixture(parsed), file);
  }

  get principal(): DevPrincipal {
    return this.#state.principals[0]!;
  }

  principalBySubject(subject: string): DevPrincipal | undefined {
    return this.#state.principals.find((entry) => entry.sub === subject);
  }

  canAccessWorkspace(subject: string, workspaceId: string): boolean {
    return this.#state.memberships[workspaceId]?.includes(subject) ?? false;
  }

  listWorkspaces(subject: string): DevWorkspace[] {
    return this.#state.workspaces.filter((workspace) => this.canAccessWorkspace(subject, workspace.id));
  }

  workspace(id: string): DevWorkspace | undefined {
    return this.#state.workspaces.find((entry) => entry.id === id);
  }

  async createWorkspace(subject: string, input: { handle: string; displayName: string; type?: "personal" | "organization" }): Promise<DevWorkspace> {
    const now = new Date().toISOString();
    const workspace: DevWorkspace = {
      id: id("ws"),
      handle: input.handle,
      displayName: input.displayName,
      type: input.type ?? "organization",
      ownerUserId: subject,
      createdAt: now,
      updatedAt: now,
    };
    this.#state.workspaces.push(workspace);
    this.#state.memberships[workspace.id] = [subject];
    await this.#persist();
    return workspace;
  }

  listSources(workspaceId: string): DevSource[] {
    return this.#state.sources.filter((entry) => entry.workspaceId === workspaceId);
  }

  source(id: string): DevSource | undefined {
    return this.#state.sources.find((entry) => entry.id === id);
  }

  async createSource(workspaceId: string, input: Omit<DevSource, "id" | "workspaceId" | "createdAt" | "updatedAt">): Promise<DevSource> {
    const now = new Date().toISOString();
    const source: DevSource = { id: id("src"), workspaceId, ...input, createdAt: now, updatedAt: now };
    this.#state.sources.push(source);
    await this.#persist();
    return source;
  }

  async updateSource(sourceId: string, input: Partial<Pick<DevSource, "defaultRef" | "defaultPath">>): Promise<DevSource | undefined> {
    const index = this.#state.sources.findIndex((entry) => entry.id === sourceId);
    const current = this.#state.sources[index];
    if (!current) return undefined;
    const updated: DevSource = { ...current, ...input, updatedAt: new Date().toISOString() };
    this.#state.sources[index] = updated;
    await this.#persist();
    return updated;
  }

  listCapsules(workspaceId: string): DevCapsule[] {
    return this.#state.capsules.filter((entry) => entry.workspaceId === workspaceId);
  }

  capsule(id: string): DevCapsule | undefined {
    return this.#state.capsules.find((entry) => entry.id === id);
  }

  async createCapsule(workspaceId: string, input: { name: string; sourceId: string; environment?: string; installConfigId?: string }): Promise<DevCapsule> {
    const now = new Date().toISOString();
    const capsule: DevCapsule = {
      id: id("cap"),
      workspaceId,
      projectId: `prj_default_${workspaceId}`,
      name: input.name,
      slug: slug(input.name),
      sourceId: input.sourceId,
      installConfigId: input.installConfigId ?? "default",
      environment: input.environment ?? "default",
      currentStateGeneration: 0,
      status: "pending",
      createdAt: now,
      updatedAt: now,
    };
    this.#state.capsules.push(capsule);
    await this.#persist();
    return capsule;
  }

  async activateCapsule(capsuleId: string): Promise<DevCapsule | undefined> {
    const index = this.#state.capsules.findIndex((entry) => entry.id === capsuleId);
    const current = this.#state.capsules[index];
    if (!current) return undefined;
    const updated: DevCapsule = {
      ...current,
      status: "active",
      currentStateGeneration: current.currentStateGeneration + 1,
      updatedAt: new Date().toISOString(),
    };
    this.#state.capsules[index] = updated;
    await this.#persist();
    return updated;
  }

  run(idValue: string): DevRun | undefined {
    return this.#state.runs.find((entry) => entry.id === idValue);
  }

  async createRun(input: Omit<DevRun, "id" | "createdAt" | "finishedAt">): Promise<DevRun> {
    const now = new Date().toISOString();
    const run: DevRun = { id: id("run"), ...input, createdAt: now, finishedAt: now };
    this.#state.runs.push(run);
    await this.#persist();
    return run;
  }

  listInterfaces(workspaceId: string): DevInterface[] {
    return this.#state.interfaces.filter((entry) => entry.metadata.workspaceId === workspaceId);
  }

  interface(idValue: string): DevInterface | undefined {
    return this.#state.interfaces.find((entry) => entry.metadata.id === idValue);
  }

  async createInterface(iface: DevInterface): Promise<DevInterface> {
    this.#state.interfaces.push(iface);
    await this.#persist();
    return iface;
  }

  listBindings(interfaceId: string): DevInterfaceBinding[] {
    return this.#state.bindings.filter((entry) => entry.spec.interfaceId === interfaceId);
  }

  async createBinding(binding: DevInterfaceBinding): Promise<DevInterfaceBinding> {
    this.#state.bindings.push(binding);
    await this.#persist();
    return binding;
  }

  async #persist(): Promise<void> {
    if (!this.#file) return;
    const snapshot = JSON.stringify(this.#state, null, 2) + "\n";
    this.#write = this.#write.then(async () => {
      await Bun.write(this.#file!, snapshot);
    });
    await this.#write;
  }
}

function normalizeFixture(input: Partial<DevFixture>): MutableDevFixture {
  const defaults = defaultFixture();
  return {
    principals: [...(input.principals ?? defaults.principals)],
    workspaces: [...(input.workspaces ?? defaults.workspaces)],
    memberships: Object.fromEntries(Object.entries(input.memberships ?? defaults.memberships).map(([key, value]) => [key, [...value]])),
    sources: [...(input.sources ?? [])],
    capsules: [...(input.capsules ?? [])],
    runs: [...(input.runs ?? [])],
    interfaces: [...(input.interfaces ?? [])],
    bindings: [...(input.bindings ?? [])],
  };
}

export function id(prefix: string): string {
  return `${prefix}_${crypto.randomUUID().replaceAll("-", "")}`;
}

export function slug(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9]+/gu, "-").replace(/^-+|-+$/gu, "").slice(0, 48) || "item";
}
