import path from "node:path";
import fs from "node:fs";
import { Project, SyntaxKind } from "ts-morph";

const projectRoot = process.cwd();

// 1) Load tsconfig
const project = new Project({
  tsConfigFilePath: path.join(projectRoot, "tsconfig.json"),
});

// 2) Read compilerOptions: baseUrl + paths
const tsConfig = project.getCompilerOptions();
const baseUrl = tsConfig.baseUrl ?? ".";
const paths = tsConfig.paths ?? {}; // { "@/*": ["src/*"], ... }

// Compile paths into matchable rules (only modify those that can be matched)
const mappings = compilePathMappings(paths);

console.log(`Base URL: ${baseUrl}`);
console.log(`Path mappings:`, JSON.stringify(paths, null, 2));
console.log(`Compiled ${mappings.length} mapping rules`);

// 3) Iterate through source files (filtered as needed)
const sourceFiles = project.getSourceFiles().filter((sf) => {
  const p = sf.getFilePath();
  // Exclude d.ts, node_modules, build directories, etc.
  return (
    !p.includes("/node_modules/") &&
    !p.includes("/.next/") &&
    !p.includes("/dist/") &&
    !p.endsWith(".d.ts")
  );
});

let changedFiles = 0;
let changedImports = 0;
let failedResolves = new Map(); // Track failed resolutions

for (const sf of sourceFiles) {
  let fileChanged = false;

  // --- A) import/export ... from '...'
  for (const decl of sf.getImportDeclarations()) {
    fileChanged ||= rewriteModuleSpecifier(sf, decl, decl.getModuleSpecifierValue());
  }
  for (const decl of sf.getExportDeclarations()) {
    const ms = decl.getModuleSpecifierValue();
    if (ms) fileChanged ||= rewriteModuleSpecifier(sf, decl, ms);
  }

  // --- B) dynamic import('...')  (CallExpression)
  for (const call of sf.getDescendantsOfKind(SyntaxKind.CallExpression)) {
    const exprText = call.getExpression().getText();
    if (exprText !== "import") continue;
    const args = call.getArguments();
    if (args.length !== 1) continue;
    const arg = args[0];
    if (arg.getKindName() !== "StringLiteral") continue;
    const spec = arg.getText().slice(1, -1); // remove quotes
    fileChanged ||= rewriteStringLiteral(sf, arg, spec);
  }

  if (fileChanged) {
    sf.saveSync();
    changedFiles += 1;
  }
}

console.log(`\nDone. Changed files: ${changedFiles}, changed imports: ${changedImports}`);

if (failedResolves.size > 0) {
  console.log(`\nFailed to resolve ${failedResolves.size} unique aliases:`);
  for (const [alias, count] of failedResolves.entries()) {
    console.log(`  ${alias} (${count} occurrences)`);
  }
}

function rewriteModuleSpecifier(sf, decl, spec) {
  const result = resolveAliasToRelative(spec, sf.getFilePath());
  if (result === null) {
    // Check if it matches paths but file cannot be found
    if (matchAgainstPaths(spec, mappings)) {
      const count = failedResolves.get(spec) || 0;
      failedResolves.set(spec, count + 1);
    }
    return false;
  }
  if (result === spec) return false;

  decl.setModuleSpecifier(result);
  changedImports += 1;
  return true;
}

function rewriteStringLiteral(sf, stringLiteralNode, spec) {
  const result = resolveAliasToRelative(spec, sf.getFilePath());
  if (result === null) {
    if (matchAgainstPaths(spec, mappings)) {
      const count = failedResolves.get(spec) || 0;
      failedResolves.set(spec, count + 1);
    }
    return false;
  }
  if (result === spec) return false;

  // Replace literal content (quote type preserved by printer)
  stringLiteralNode.replaceWithText(JSON.stringify(result));
  changedImports += 1;
  return true;
}

function resolveAliasToRelative(spec, sourceFilePath) {
  // 1) Only handle those that match tsconfig paths (avoid treating @vercel/blob as alias)
  const matches = matchAgainstPaths(spec, mappings);
  if (!matches) return null;

  // 2) For each candidate path, try to find the actual file
  for (const resolvedRelative of matches) {
    const absTarget = path.resolve(projectRoot, baseUrl, resolvedRelative);

    // 3) Find actual file (add extensions, index)
    const actual = findActualFile(absTarget);
    if (actual) {
      // 4) Calculate relative path, remove extension, handle /index
      const sourceDir = path.dirname(sourceFilePath);
      let rel = path.relative(sourceDir, actual).replaceAll(path.sep, "/");
      if (!rel.startsWith(".")) rel = "./" + rel;

      rel = stripKnownExt(rel);
      rel = stripIndex(rel);
      return rel;
    }
  }

  return null;
}

function compilePathMappings(pathsObj) {
  // Rules prioritized by "longer prefix" (more specific matches first)
  const list = Object.entries(pathsObj).flatMap(([pattern, targets]) => {
    const arr = Array.isArray(targets) ? targets : [targets];
    const starIdx = pattern.indexOf("*");
    const isWildcard = starIdx !== -1;
    const prefix = isWildcard ? pattern.slice(0, starIdx) : pattern;
    return arr.map((t) => ({
      pattern,
      prefix,
      isWildcard,
      target: t,
      specificity: prefix.length + (isWildcard ? 0 : 10000),
    }));
  });

  list.sort((a, b) => b.specificity - a.specificity);
  return list;
}

function matchAgainstPaths(spec, mappings) {
  const results = [];

  for (const m of mappings) {
    if (m.isWildcard) {
      if (!spec.startsWith(m.prefix)) continue;
      const remainder = spec.slice(m.prefix.length);
      const resolvedRelative = m.target.includes("*")
        ? m.target.replace("*", remainder)
        : m.target;
      results.push(resolvedRelative);
    } else {
      if (spec === m.pattern) {
        results.push(m.target);
      }
    }
  }

  return results.length > 0 ? results : null;
}

function findActualFile(absPathNoExt) {
  // 1) exact file
  if (isFile(absPathNoExt)) return absPathNoExt;

  // 2) try extensions
  const exts = [".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs", ".cts", ".cjs"];
  for (const ext of exts) {
    const p = absPathNoExt + ext;
    if (isFile(p)) return p;
  }

  // 3) try index files
  const idx = ["index.ts", "index.tsx", "index.js", "index.jsx", "index.mts", "index.mjs", "index.cts", "index.cjs"];
  if (isDir(absPathNoExt)) {
    for (const f of idx) {
      const p = path.join(absPathNoExt, f);
      if (isFile(p)) return p;
    }
  }
  for (const f of idx) {
    const p = path.join(absPathNoExt, f);
    if (isFile(p)) return p;
  }

  return null;
}

function isFile(p) {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}
function isDir(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function stripKnownExt(p) {
  const exts = [".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs", ".cts", ".cjs"];
  for (const ext of exts) {
    if (p.endsWith(ext)) return p.slice(0, -ext.length);
  }
  return p;
}

function stripIndex(p) {
  if (p.endsWith("/index")) return p.slice(0, -"/index".length) || ".";
  return p;
}
