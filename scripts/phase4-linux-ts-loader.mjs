import { access, readFile } from "node:fs/promises";
import { dirname, resolve as resolvePath } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

const repositoryRoot = resolvePath(dirname(fileURLToPath(import.meta.url)), "..");

async function sourceUrl(path) {
  for (const candidate of [
    path,
    `${path}.ts`,
    `${path}.tsx`,
    `${path}.js`,
    resolvePath(path, "index.ts"),
    resolvePath(path, "index.tsx"),
    resolvePath(path, "index.js"),
  ]) {
    try {
      await access(candidate);
      return pathToFileURL(candidate).href;
    } catch {}
  }
  return null;
}

export async function resolve(specifier, context, nextResolve) {
  if (specifier.startsWith("@/")) {
    const url = await sourceUrl(resolvePath(repositoryRoot, specifier.slice(2)));
    if (url) return { url, shortCircuit: true };
  }
  if (specifier.startsWith(".") && context.parentURL?.startsWith("file:")) {
    const parentPath = fileURLToPath(context.parentURL);
    if (parentPath.startsWith(repositoryRoot + "/")) {
      const url = await sourceUrl(resolvePath(dirname(parentPath), specifier));
      if (url) return { url, shortCircuit: true };
    }
  }
  return nextResolve(specifier, context);
}

export async function load(url, context, nextLoad) {
  if (url.endsWith(".ts") || url.endsWith(".tsx")) {
    const source = await readFile(fileURLToPath(url), "utf8");
    const result = ts.transpileModule(source, {
      fileName: fileURLToPath(url),
      compilerOptions: {
        target: ts.ScriptTarget.ES2022,
        module: ts.ModuleKind.ESNext,
        moduleResolution: ts.ModuleResolutionKind.Bundler,
        jsx: ts.JsxEmit.ReactJSX,
        isolatedModules: true,
        verbatimModuleSyntax: true,
        sourceMap: false,
      },
    });
    return { format: "module", source: result.outputText, shortCircuit: true };
  }
  return nextLoad(url, context);
}
