// Vitest executes server modules in a Node-only process. Next.js resolves the
// real `server-only` marker during application builds; this no-op preserves the
// boundary while allowing isolated server tests to import those modules.
export {};
