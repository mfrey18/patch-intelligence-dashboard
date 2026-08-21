import { registerHooks } from "node:module";
import { readFileSync } from "node:fs";
import ts from "typescript";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (/^\.{1,2}\//.test(specifier) && !/\.[^/]+$/.test(specifier)) {
      return nextResolve(`${specifier}.ts`, context);
    }

    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.endsWith(".ts")) {
      const source = readFileSync(new URL(url), "utf8");
      const { outputText } = ts.transpileModule(source, {
        fileName: new URL(url).pathname,
        compilerOptions: {
          module: ts.ModuleKind.ESNext,
          target: ts.ScriptTarget.ES2022,
        },
      });

      return { format: "module", source: outputText, shortCircuit: true };
    }

    return nextLoad(url, context);
  },
});
