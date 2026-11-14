# `vettalon cbom-check` (experimental)

An independent second opinion on a crypto inventory. CBOM tools such as PQCA CBOMkit report what code *can* use; `cbom-check` takes their CycloneDX CBOM and the project root, and labels every crypto-asset occurrence in a Python (`.py`) or Java (`.java`) file by whether the enclosing code is **observed** to be reached, using lightweight name-based static analysis. Occurrences in any other file type are `unknown`.

Prototype status: correctness of the honesty policy matters more than analysis power. It is not a PQC scanner. By default it only labels what the CBOM lists and does not look for crypto the CBOM omits. The opt-in `--sweep` adds a separate, name-based inventory of Java JCA / BouncyCastle call sites to the receipt (see [Sweep](#sweep---sweep-java-only)); it can point at Java calls the CBOM does not list, but it does not find all crypto and never changes a label.

## How to

Generate a CBOM with CBOMkit-action (the image digest used for the checked-in fixture is in [`fixtures/cbom/README.md`](../fixtures/cbom/README.md)):

```sh
docker run --rm -v "$PWD/myapp:/github/workspace" \
  ghcr.io/cbomkit/cbomkit-action:edge   # see the CBOMkit-action docs for its inputs and output path
```

Then check it against the same project:

```sh
vettalon cbom-check --cbom cbom.json --root ./myapp
vettalon cbom-check --cbom cbom.json --root ./myapp --entry myapp.cli:main --json receipt.json
vettalon cbom-check --cbom cbom.json --root ./myservice --entry com.ex.Worker:start
vettalon cbom-check --cbom cbom.json --root ./myservice --sweep --json receipt.json
```

- `--entry SPEC` (repeatable) adds an entry point, for code a framework, a console script, a servlet container or a test runner calls without any reference in the source. A Python spec `module.path:func` resolves to a function in `module/path.py` or `module/path/__init__.py` (any directory prefix). A Java spec `package.Class:method` (plain ASCII identifiers; `Class:method` for the default package) resolves to every method or constructor named `method` in the top-level type `Class` of a file whose path ends with `package/Class.java` (any directory prefix, so `src/main/java/` needs no spelling out). Each spec is tried in both languages and used wherever it resolves; a spec that resolves in neither is an error (exit 2).
- `--json FILE` writes the receipt and **refuses to overwrite** an existing file (exit 2). The receipt is streamed into a fresh temp file in the same directory, fsynced, then hard-linked to `FILE` (which fails atomically if `FILE` exists). On a filesystem without hard links it falls back to an atomic no-replace rename (macOS `renamex_np` with `RENAME_EXCL`, Linux `renameat2` with `RENAME_NOREPLACE`); where neither works the write fails with a message and nothing is overwritten. The directory is then fsynced (best effort) and the temp file is always removed.
- `--sweep` (off by default) also lists Java crypto call sites found by name in the project's `.java` files, as `sweep[]` in the receipt and one `sweep:` summary line in the terminal output (see [Sweep](#sweep---sweep-java-only)). Without the flag the receipt has no `sweep` field and is otherwise the same.
- Exit code: 0 when the analysis finished, whatever the labels; 2 for bad input (not a CycloneDX 1.6/1.7 CBOM, a CBOM over a cap, unreadable file, bad `--entry`, existing `--json`) or when the receipt cannot be serialized or written.

Try it on the fixtures: `vettalon cbom-check --cbom fixtures/cbom/sample-py.cbomkit.json --root fixtures/cbom/sample-py` (real CBOMkit output) and `vettalon cbom-check --cbom fixtures/cbom/sample-java/hand.cbom.json --root fixtures/cbom/sample-java` (a hand-written CBOM). Adding `--sweep` to the Java command lists three calls: the two the CBOM lists (`in_cbom: true`) and a SHA-256 `MessageDigest.getInstance` in `Unlisted.java:7` that it does not (`in_cbom: false`, label `not_observed`).

## Reference

### Labels

| Label | Meaning |
|---|---|
| `reachable` | A name-based call chain from an entry point reaches the enclosing function, or the occurrence is in code that runs when something reached does (Python module top-level code, which runs on import; a Java static initializer of a type with a reached member, or an instance initializer of a type with a reached constructor). Not execution evidence. |
| `not_observed` | Python: no textual reference to the enclosing function name anywhere in the project's `.py` files except its own `def` — no bare name, no import of it, no alias of it, and no attribute reference `x.name` on any receiver — after removing comments and plain string literals (docstrings included; f-/t-string contents are code and are kept), and no unknown trigger applies. Java: the method or constructor name appears as an identifier token nowhere in the project's `.java` files except its own declaration (comments and literal contents blanked), the Java side of the project was fully analyzed, and no unknown trigger applies (see [Java rules](#java-rules)). **Not** "unreachable" and **not** "safe". |
| `unknown` | Anything that cannot be decided; the analysis fails closed. |

### Python rules

Entry points: module top-level statements (code not inside a `def`; class bodies run when their enclosing scope runs), the `if __name__ == "__main__":` block, and `--entry`. Edges are name-based: an identifier followed by `(` or passed as a value, `from x import a as b` makes `b` refer to `a`, and `recv.name` is an edge only when `recv` is bound by an `import` (`keys.encrypt(...)` after `import keys`). Any other attribute reference (`AESGCM(key).encrypt(...)`, `m = keys; m.encrypt()`) makes no edge but is still a textual reference, so a function referenced only that way is `unknown` (`referenced_but_no_entry_path`), never `not_observed`.

Lexing: one leading UTF-8 BOM is dropped, as Python does, after the file hash is taken (line numbers do not change; a second BOM counts as non-ASCII code). Comments and plain string literals are blanked. f-strings and t-strings (`f`, `t`, `rf`, `fr`, `rt`, `tr`, any case, single or triple quoted) are never treated as docstrings: their whole content is scanned as code, following the Python 3.12 grammar (same-type quotes nested in replacement fields, nested fields, format specs). A literal that does not lex makes the file a parse ambiguity.

### Java rules

The Java side works like the Python one: no real parser, no types, no call-site resolution. A lexer blanks comments and the contents of string, char and text-block literals (unicode escapes are translated first, per JLS 3.3), and a token and brace scanner finds packages, imports, types (`class`, `interface`, `enum`, `record`, `@interface`, nested, inner and local ones included) with their annotations and `extends` / `implements` lists, and members with a body: methods, constructors, static and instance initializers, field declarations with an initializer, and an enum's constant list. Lambda and anonymous-class bodies belong to the member that contains them (extra edges, never fewer).

Entry points: every launcher `main` (named `main`, returns `void`, not `private`, and takes nothing or one `String[]` / `String...` parameter; static and JDK 21+ instance mains both count) and every `--entry package.Class:method`. Framework callers (servlet containers, Spring, test runners, annotation processors) are not modelled; pass them as `--entry`.

Edges are name-based, and a receiver never blocks one:

- `name(` on any receiver, and `X::name`, reach every method named `name` in the project;
- `new X(` and `X::new` reach an instance of every type named `X`; `super(` reaches an instance of the supertype, `this(` one of the own type;
- an instance reaches every constructor, instance initializer and instance field initializer of its type (reason `constructor_reachable`);
- any reached member initializes its declaring type, which reaches the static initializers and static field initializers (JLS 12.4.1, reason `class_initialized_by_reachable_member`).

A line that holds code of several members that do not enclose one another is `reachable` when any of them is, else `unknown` (`line_shared_by_members`). A line in no member (an import, a field without `=`, a type header) is `unknown` (`outside_member`).

What forces `unknown` for a member that is not reached, checked in this order: a cap was hit (`analysis_limit`); the project is incomplete (`project_not_fully_analyzed:<why>`, below); the member is an initializer (`initializer_not_modeled`); the member or an enclosing type carries an annotation other than `@Override`, `@Deprecated`, `@SuppressWarnings`, `@SafeVarargs` or `@FunctionalInterface` (`enclosing_annotated`; those five never allow `not_observed` either); a reflection word occurs anywhere in the project's code (`reflection_in_project`); the type or a project supertype extends or implements a type that does not resolve to exactly one project type, so the method may override a library method (`overrides_external_type_possible`); the name is one the JDK calls implicitly (`jdk_implicit_name`); the name looks like a JavaBeans accessor (`bean_accessor_possible`); the method or an enclosing type's simple name appears in a config file (`named_in_config_file`); the name is called somewhere (`referenced_but_no_entry_path`) or appears in another position (`method_referenced_not_modeled`).

What marks the Java side incomplete (no Java row can be `not_observed`): sources of other JVM languages or templates, compiled code, imports of libraries that call project code reflectively, non-ASCII code, a file that does not lex or parse, a skipped file or directory, and the config caps. The full list is under [Reasons](#reasons). Python causes block only `.py` rows, Java causes only `.java` rows.

Config files: every identifier-like word in a `.xml`, `.properties`, `.yml`, `.yaml`, `.json`, `.factories`, `.imports`, `.conf`, `.toml`, `.ini` or `.MF` file, in any file below a `META-INF/` directory, and in a `provides … with …;` / `uses …;` directive of `module-info.java`, counts as a possible class or method name. The CBOM given to `--cbom` and the `--json` receipt are left out of this scan when they sit inside `--root`, since they name the very classes and methods being checked.

### Reasons

`reachable`: Python `module_top_level`, `main_block`, `name_based_chain_from_entry`; Java `name_based_chain_from_entry`, `class_initialized_by_reachable_member`, `constructor_reachable`.

`not_observed`: `no_textual_reference`.

`unknown`, Python rows:

| Reason | Cause |
|---|---|
| `referenced_but_no_entry_path` | The function name is referenced (bare, imported, aliased, or as an attribute `x.name` on any receiver) but no name-based chain from an entry point exists. |
| `enclosing_decorated` | The enclosing function (or an enclosing function/class) has a decorator. A decorator outside the allowlist below always gives this reason; an allowlisted one gives it where the result would otherwise be `not_observed`, because a decorated block is never `not_observed`. Every decorator stacked on a `def` / `class` is checked; one non-allowlisted decorator is enough. |
| `enclosing_decorated:shadowed_allowlist:<name>` | As above, but the decorator has an allowlisted shape (`<name>` is the decorator as written, e.g. `cache`, `ft.cache`) and the entry is disabled because the project may bind that name to something else (see the shadowing rule below). |
| `dynamic_dispatch_in_project` | One of the words `getattr`, `setattr`, `__import__`, `importlib`, `eval`, `exec`, `globals`, `locals`, `vars`, `__dict__`, `sys.modules` (whitespace / backslash-newline allowed around the dot), `attrgetter`, `methodcaller`, `getmembers`, `__getattribute__`, `__getattr__`, `__builtins__`, `builtins`, `__self__`, `__globals__`, `__code__`, `__closure__`, `__func__`, `__wrapped__`, `f_globals`, `f_locals`, `f_builtins`, `_getframe`, `currentframe`, `FunctionType`, `CodeType`, `MethodType`, `LambdaType`, `__subclasses__`, `__init_subclass__`, `__class_getitem__`, `metaclass`, `__set_name__`, `__prepare__`, `__mro_entries__`, `get_objects`, `get_referrers`, `get_referents`, `pickle`, `_pickle`, `cloudpickle`, `dill`, `marshal`, `shelve`, `copyreg`, `__reduce__`, `__reduce_ex__`, `get_type_hints`, `__annotations__`, `__annotate__`, `annotationlib`, `ForwardRef`, `resolve_name`, `pkgutil`, `pkg_resources`, `runpy`, `dictConfig`, `fileConfig`, `ctypes` appears anywhere in the project's code or f-/t-strings, as a bare word (no `(` needed: `ga = getattr` counts; attribute position counts too: `len.__self__.compile(...)` reaches the builtins module, `f.__globals__["han" + "dler"]()` and `sys._getframe().f_globals[...]` reach a function by a computed name). `compile` counts only when it is not an attribute: `re.compile(...)` or `pattern.compile` (a `.` before it, whitespace / backslash-newline allowed) does not count; a bare `compile` (the builtin, or after `from re import compile`) does. |
| `name_in_dunder_all` | The function name appears in an `__all__`. |
| `star_import_may_expose` | A `from m import *` may expose the function's module. |
| `method_attribute_call_exists` | The function is a method and an attribute reference `.name` exists. Methods are never `reachable`. |
| `method_referenced_not_modeled` | The function is a method referenced by bare name. |
| `dunder_name_implicit_call` | `__init__`, `__call__`, ... are called implicitly. |
| `project_not_fully_analyzed:<why>` | `not_observed` is withheld for every `.py` row. `<why>` is the first cause found: a `.py` file could not be analyzed (`file_parse_ambiguity`, `file_too_large`, `file_not_utf8`, `file_unreadable`); Python may read a file differently than we do (`lone_cr_line_ending`: a CR not followed by LF; `non_utf8_coding_cookie`: a PEP 263 declaration on line 1 or 2 naming anything but `utf-8` / `utf8` / `utf_8` / `utf-8-sig`; `non_ascii_identifier_possible`: a non-ASCII character outside comments and plain string literals, since Python NFKC-normalises identifiers and `ｍake_key()` calls `make_key`); or something was not walked (`skipped_directory`: a `.venv`, `venv`, `node_modules` or `site-packages` directory; `symlink_not_followed`, `directory_too_deep`, `directory_unreadable`, `non_utf8_path`). |
| `file_not_analyzed`, `file_not_utf8`, `file_unreadable`, `file_too_large`, `parse_ambiguity`, `line_out_of_range` | The `.py` file is not a source we analyzed, or the line is not in it. |
| `file_count_limit_exceeded`, `source_size_limit_exceeded` | More than 20 000 `.py` files or 64 MiB of Python source: every `.py` row is `unknown`. |

Decorator allowlist. These built-in / standard-library decorators do not register the function anywhere, so they do not by themselves make it `unknown` on the `reachable` / method paths. **A decorated function (or a function inside a decorated class) is never labelled `not_observed`, allowlisted decorator or not**: where the normal rules would give `not_observed` the result is `unknown` with reason `enclosing_decorated` (`enclosing_decorated:shadowed_allowlist:<name>` when a shadowed allowlist entry is the cause). The allowlist only affects `reachable` and method handling: a function with an allowlisted decorator can still be `reachable` through a name-based chain from an entry, and an allowlisted method still falls through to the method rules (`method_attribute_call_exists`, `method_referenced_not_modeled`), but none of these paths yields `not_observed` for a decorated block (an unreferenced `@staticmethod` method is `unknown`). The reason: the allowlist cannot be made spoof-proof (a callable argument to `lru_cache(...)`, a binding hidden in a one-line block header, `ft.cache = register`, `with ... as ft.cache`, a non-`.py` shadow module). A decorator matches when its expression, with all whitespace removed, is exactly one of:

- `staticmethod`, `classmethod`, `property` (canonical module: builtins);
- `abstractmethod` (`abc`);
- `cache`, `lru_cache`, `lru_cache(...)`, `cached_property`, `wraps(...)` (`functools`);
- `override`, `overload` (`typing` or `typing_extensions`);
- on a `class` only: `dataclass`, with or without `(...)` (`dataclasses`);
- each of the above as `<head>.<name>` (`functools.lru_cache(...)`, `abc.abstractmethod`, `ft.cache`), where `<head>` is a single identifier;
- `<name>.setter`, `<name>.getter`, `<name>.deleter` (`<name>` a single identifier), under the accessor rule below.

`(...)` means plain arguments only: names, numbers, `.`, `,` and `=` (`lru_cache(maxsize=128)`, `wraps(fn)`, `dataclass(frozen=True)`). Arguments holding a call, a string, a subscript, a lambda or any operator (`lru_cache(maxsize=size())`) make the decorator non-allowlisted, as does every other decorator (`@app.route(...)`, `@register`, `@wraps` without a call, `@dataclass` on a function).

Shadowing rule. A matching shape is not enough: whether an entry applies is decided once the whole project has been read, so a project-defined decorator cannot borrow an allowlisted name (`def cache(f): REG[f.__name__] = f; return f` then `@cache def handler(): ...` dispatched via `REG[key]()` is `unknown`, never `not_observed`). Binding detection over-approximates; any doubt disables the entry (reason `enclosing_decorated:shadowed_allowlist:<name>`).

- A bare `@X` applies only if no analyzed file binds `X` other than by `from <canonical module> import X`. Bindings that disable it include `def X`, `class X`, a parameter `X`, any name left of an assignment `=` (tuple / starred / chained / annotated / augmented targets, attribute and subscript targets), `X := ...` (also inside f-/t-strings), `import X`, `import ... as X`, `from M import X` / `from M import Y as X` with `M` not canonical (relative imports never are) or `Y` not `X`, `global X` / `nonlocal X`, `for X in`, `with ... as X`, `except ... as X`, and `match` `case` patterns.
- `@head.X` applies only if `head` is bound by `import <canonical module>` / `import <canonical module> as head` (or `import <canonical module>.sub`) and by nothing else (`ft = registry` or `functools.cache = ...` disable it).
- A `from M import *` with `M` not a canonical module disables every entry, and so does an analyzed file or directory named like a canonical module (`functools.py`, `typing/`), which may shadow it.
- Accessor rule: `@n.setter` / `@n.getter` / `@n.deleter` applies only on a `def` in a class body whose nearest earlier `def n` at the same indentation in that body is decorated with an applicable `@property` (or is itself an applicable accessor of one), all its decorators applicable, with nothing in that class scope rebinding `n` in between (method bodies are skipped). Otherwise (`@router.getter`, an accessor at module level or of a plain method) the reason is `enclosing_decorated`.

`unknown`, Java rows:

| Reason | Cause |
|---|---|
| `line_shared_by_members` | The line holds code of several members that do not enclose one another, and none of them is reached. |
| `outside_member` | The line is in no method, constructor, initializer or field initializer. |
| `analysis_limit` | A worklist went over 100 000 entries (the reachability queue, or the propagation of external supertypes), or the file was skipped because the project-wide budget for type names (64 MiB) ran out. |
| `project_not_fully_analyzed:<why>` | `not_observed` is withheld for every `.java` row. `<why>` is the alphabetically first of the causes found: `other_jvm_source` (a `.kt`, `.kts`, `.scala`, `.groovy`, `.clj`, `.cljs`, `.cljc`, `.jsp`, `.jspx`, `.jspf`, `.aj`, `.jsh`, `.gvy`, `.gy`, `.gsh`, `.sc`, `.tag`, `.tagx`, `.ftl`, `.ftlh`, `.ftlx`, `.vm`, `.jte`, `.mustache`, `.hbs` or `.peb` file, or an `.html` file with a Thymeleaf `th:` / `data-th-` attribute); `compiled_jvm_code` (a `.jar`, `.class`, `.war`, `.ear`, `.jmod`, `.zip`, `.so`, `.dll`, `.dylib`, `.jnilib`, `.aar`, `.dex` or `.apk` inside the root); `reflective_library_import` (an import or qualified use of a library that calls project code by name, such as Jackson, Gson, Spring, Hibernate, JPA, MapStruct, Guice, Dagger, JAX-RS, JUnit, picocli, Micronaut, Quarkus, CDI, JAXB, JSON-B, SnakeYAML, EL, OGNL, template engines, Mockito, TestNG or JMX); `non_ascii_identifier_possible` (a non-ASCII character outside comments and literals); `file_parse_ambiguity` (a file that does not lex or parse: an invalid or structural unicode escape such as `\u000a` in a comment, unbalanced braces, nesting over 256, an unparsed member header, a name over its cap, over 50 000 members); a skipped `.java` file (`file_too_large`, `file_not_utf8`, `file_unreadable`, `analysis_limit`); something not walked (`skipped_directory`: `node_modules`, `.gradle`, `.idea`, or a `.git` below the root; `symlink_not_followed`, `directory_too_deep`, `directory_unreadable`, `non_utf8_path`); or a config file not fully read (`config_file_too_large`, `config_file_unreadable`, `config_file_not_text`, `config_file_count_limit_exceeded`, `config_size_limit_exceeded`). |
| `initializer_not_modeled` | A static or instance initializer, or a field initializer, that is not reached. Initializers are never `not_observed`. |
| `enclosing_annotated` | The member or an enclosing type has an annotation. Any annotation except `@Override`, `@Deprecated`, `@SuppressWarnings`, `@SafeVarargs` and `@FunctionalInterface` gives this reason before the checks below; those five give it only where the result would otherwise be `not_observed`. |
| `reflection_in_project` | One of the words `forName`, `getMethod`, `getDeclaredMethod`, `getMethods`, `getDeclaredMethods`, `getConstructor`, `getConstructors`, `getDeclaredConstructor`, `getDeclaredConstructors`, `newInstance`, `invoke`, `MethodHandles`, `MethodHandle`, `VarHandle`, `LambdaMetafactory`, `ServiceLoader`, `Proxy`, `InvocationHandler`, `loadClass`, `defineClass`, `ClassLoader`, `URLClassLoader`, `Unsafe`, `ObjectInputStream`, `readObject`, `readResolve`, `Instrumentation`, `JNI`, `native`, `loadLibrary`, `Statement`, `Expression`, `EventHandler`, `XMLDecoder`, `XMLEncoder`, `Introspector`, `PropertyDescriptor`, `BeanInfo`, `JShell`, `MethodUtils`, `PropertyUtils`, `BeanUtils`, `registerMBean`, `StandardMBean`, `MBeanServer`, `MXBean`, any identifier starting with `ScriptEngine`, or a `load` that may load a native library (`System.load`, `x.load(...)`, `X::load`) appears as an identifier anywhere in the project's Java code. |
| `overrides_external_type_possible` | The enclosing type, or one of its project supertypes, extends or implements a type that does not resolve to exactly one project type (a JDK or library type, a wildcard import, a duplicate name), so a library may call the method through that supertype. |
| `jdk_implicit_name` | The method is named `run`, `call`, `close`, `toString`, `equals`, `hashCode`, `compareTo`, `compare`, `accept`, `apply`, `get`, `test`, `iterator`, `finalize`, `clone`, `readObject`, `writeObject`, `main`, `values`, `valueOf`, `premain`, `agentmain` or `provider`, which the JDK or the language may call without a textual call. |
| `bean_accessor_possible` | The method name is `get`, `is` or `set` followed by an uppercase letter; serializers, mappers, templates and `java.beans` call those by property name. |
| `named_in_config_file` | The method name, or the simple name of an enclosing type, appears in a config file or a `module-info.java` `provides` / `uses` directive (see [Java rules](#java-rules)). |
| `referenced_but_no_entry_path` | The name is called somewhere (`name(` or `X::name`, any receiver) but no name-based chain from an entry point reaches the member. |
| `method_referenced_not_modeled` | The name appears as an identifier in another position (a field, a variable, `x.name` without a call). |
| `file_not_analyzed`, `file_not_utf8`, `file_unreadable`, `file_too_large`, `file_parse_ambiguity`, `line_out_of_range` | The `.java` file is not a source we analyzed, or the line is not in it. |
| `file_count_limit_exceeded`, `source_size_limit_exceeded` | More than 20 000 `.java` files or 64 MiB of Java source: every `.java` row is `unknown`. |

`unknown`, any row:

| Reason | Cause |
|---|---|
| `file_missing`, `absolute_path`, `parent_component`, `path_outside_root`, `invalid_location`, `file_too_large`, `location_too_long` | The CBOM location cannot be mapped to a regular file under `--root` (absolute path, `..`, symlink out of the root, over 2 MiB, a location over 4096 bytes or 64 path components). |
| `unsupported_language:<ext>` | The file is neither `.py` nor `.java`. `<ext>` is its extension, lowercased, at most 16 characters (`none` when it has none), e.g. `unsupported_language:kt`. |
| `line_missing`, `line_invalid`, `line_negative`, `location_missing`, `location_invalid` | Malformed occurrence in the CBOM. |
| `no_occurrence` | A crypto component without evidence occurrences. |

Notes that may accompany any label (they never change it):

| Reason | Meaning |
|---|---|
| `path_suffix_stripped:<n>` | The location only matched after dropping `n` > 1 leading components (CBOMkit's single workspace prefix is not reported). |
| `cbom_value_clipped:<field>` | A CBOM string (`name`, `bom-ref`, `additionalContext`, ...) was longer than 256 characters and was clipped (shown with `…`). A clipped `bom-ref` is never used to link a material to its algorithm. |
| `cbom_value_clipped:budget` | The global 64 MiB budget for CBOM strings copied into rows (`bom_ref`, `name`, `asset_type`, `algorithm`, `symbol`) ran out; from then on every such value longer than 32 characters is clipped to 32 (shown with `…`). |
| `chain_truncated` | The global 32 MiB budget for `chain` text ran out; the chain keeps only its first and last entries. |

Document-level notes (`cbom.notes` in the receipt, also printed under the summary):

| Note | Meaning |
|---|---|
| `cbom_dependencies_truncated` | Some `dependencies` entries (over 100 000) or `dependsOn` refs (over 1024 per entry, or over 200 000 in total) were dropped by a cap. A material row may then lack the algorithm it depends on (`algorithm` / `quantum_vulnerable` null); labels are not affected. |
| `sweep_*`, `sweep:<file>:<reason>`, `cbom_value_clipped:budget` | Only with `--sweep`; see [Sweep notes](#sweep-notes-and-reasons). |

Limits: CBOM 32 MiB, 100 000 components, 10 000 occurrences per component, 200 000 occurrences in total (all enforced while parsing; over a cap is exit 2), CBOM strings 256 characters, locations 4096 bytes / 64 components, 2 MiB per source file, 20 000 files and 64 MiB of source per language, 64 MiB of CBOM strings copied into rows. Java only: brace / parenthesis nesting 256 per file, 50 000 members per file, qualified type names 4096 bytes each and 4 MiB per file, package and import names 1024 bytes, 64 MiB of type names for the whole project, worklists 100 000 entries, directory depth 64; config files 2 MiB each, 16 MiB and 20 000 files in total. `--sweep` only: 50 000 sweep rows, 200 000 tokens per file, 64 MiB of retained lexer data, 200 000 constants / 16 MiB (see [Sweep](#sweep---sweep-java-only)). Only the first 16 `metadata.tools` entries, 64 `cryptoFunctions` and 1024 `dependsOn` refs per entry are read (dropped `dependencies` are reported as `cbom_dependencies_truncated`). Skipped directories, Python walk: `.git` and `__pycache__` silently; `.venv`, `venv`, `node_modules` and `site-packages` mark the project not fully analyzed (`skipped_directory`). Java walk: `<root>/.git` silently; `node_modules`, `.gradle`, `.idea` and a `.git` below the root mark it not fully analyzed; `target/` and `build/` are walked. Source files are opened without following symlinks, must be regular files, and must be the file the walk saw.

Path mapping: CBOMkit prefixes locations with the scanner's workspace directory name (`ws/app/keys.py` for `<root>/app/keys.py`). The full relative path is tried first, then each suffix with leading components stripped; the first existing regular file wins. Dropping more than one component adds `path_suffix_stripped:<n>`. Each distinct location is mapped once.

Terminal output: control, bidi and format characters (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069, U+FEFF, U+2028, U+2029) are shown as `?`, and every column is at most 60 characters (clipped with `…`). The receipt keeps the values.

### Receipt `vettalon.cbom-check/2`

```text
schema, tool_version, generated_at (RFC 3339 UTC),
cbom {sha256 (raw bytes), spec_version, tool, notes[] (only when non-empty)},
root_tree_sha256, analysis, policy, entries,
project {py_files, java_files, languages[], dynamic_dispatch_detected, reflection_detected,
         not_observed_blocked[]},
rows [{bom_ref, name, asset_type, algorithm, quantum_vulnerable, file, line, symbol,
       enclosing_function, label, reasons[], chain[], file_sha256}],
sweep [{file, line, api, algorithm, mode, padding, key_bits, provider,
        quantum_vulnerable, in_cbom, label, reasons[]}]   (only with --sweep),
summary {total_rows, by_label, by_quantum_vulnerable}, receipt_sha256
```

- `root_tree_sha256`: SHA-256 over, for each analyzed `.py` and `.java` file sorted together by relative path, `"<relative path>\0<file sha256 hex>\n"`.
- `project`: `py_files` / `java_files` count analyzed files; `languages` lists the languages with at least one analyzed file (`java`, `python`); `dynamic_dispatch_detected` is the Python dynamic-dispatch flag and `reflection_detected` the Java reflection flag; `not_observed_blocked` has one `python:<why>` / `java:<why>` entry per language whose rows cannot be `not_observed` (empty when neither is blocked).
- Java rows: `enclosing_function` is `Outer.Inner.method`, `Type.<init>` (constructor), `Type.<clinit>` (static initializer), `Type.<init-block>` or `Type.<field-init>`; each `chain` entry is `path:Type.member`, or `--entry <spec>` for a chain that starts at an `--entry`.
- `sweep`: present only with `--sweep` (an empty array when nothing was found); `summary` counts `rows` only. See [Sweep](#sweep---sweep-java-only).
- `receipt_sha256`: SHA-256 of the canonical JSON of the receipt without `receipt_sha256` and `generated_at`, `sweep` included when present. Canonical JSON = the receipt as a `serde_json::Value`, every object's keys sorted recursively, serialized compactly (no whitespace). The implementation streams exactly these bytes into the hasher (one top-level field or one row at a time) instead of building the whole tree; a serialization error is exit 2, never a hash of empty input.
- `quantum_vulnerable` (per algorithm, from NIST IR 8547 final, 2026-10-27): `true` for RSA, ECDSA/EC*, EdDSA, DH/ECDH, DSA, MQV; `false` for hashes and symmetric `ae`/`block-cipher` with a key of at least 128 bits; `null` for everything else, including post-quantum algorithms. A `related-crypto-material` row takes it from the algorithm it depends on in the CBOM's `dependencies`.
- `analysis` is always `name-based static, over-approximate, not execution evidence`; `policy` is `not_observed is not proof of absence; no VEX is emitted`.

### Sweep (`--sweep`, Java only)

An independent list of Java crypto call sites, found by name in the `.java` files the Java analysis already lexed and parsed (no file is read twice, no Java is compiled or run). It is written as `sweep[]` and never adds, removes or changes an occurrence row or its label. Only Java is swept: a project with no analyzed `.java` file gets `sweep: []` and the note `sweep_java_only`.

What is detected:

- `getInstance(` on `Cipher`, `MessageDigest`, `Signature`, `KeyPairGenerator`, `KeyGenerator`, `SecretKeyFactory`, `Mac`, `KeyAgreement`, `KeyFactory`, `KEM`, `AlgorithmParameters`, `AlgorithmParameterGenerator`, `SecureRandom` and `KeyStore`, also fully qualified (`javax.crypto.Cipher.getInstance(`). The first argument is the algorithm, the second the provider.
- Constructors `new SecretKeySpec(` (second argument is the algorithm), `new GCMParameterSpec(` (mode `GCM`), `new IvParameterSpec(`, `new PBEKeySpec(` (fourth argument is `key_bits`), `new ECGenParameterSpec(` (first argument is the algorithm, e.g. `secp256r1`) and `new RSAKeyGenParameterSpec(` (algorithm `RSA`, first argument is `key_bits`).
- Key sizes: `.init(<int>)` or `.initialize(<int>)` (optionally with a second argument) on the variable that was assigned a `KeyGenerator` / `KeyPairGenerator` `getInstance` result, in the same method or constructor body; the latest such assignment wins. Only integer literals count; a factory call not assigned to a variable gets no key size.
- BouncyCastle lightweight classes, only in files with an `org.bouncycastle.` import: `new X(` or `X.newInstance(` for a fixed list of engines, digests, MACs, signers, key-pair generators, agreements and block-cipher modes (`AESEngine`, `ChaCha7539Engine`, `RSAEngine`, `SHA256Digest`, `HMac`, `ECDSASigner`, `Ed25519Signer`, `MLKEMKeyPairGenerator`, `MLDSASigner`, `SLHDSASigner`, `GCMBlockCipher`, ...). The algorithm (or mode) comes from that list. `Security.addProvider(new BouncyCastleProvider())` only adds a note.

The algorithm argument is taken from a string literal, a `static final String` constant in the same file, or `Type.NAME` naming a constant in another project file, following chains of up to 4 references and folding `+` concatenations of up to 16 literal parts and 256 characters. A constant declared twice under the same type and name counts as unknown. Anything else (a variable, a method call, a parameter) gives `algorithm: null` with reason `algorithm_not_constant`. For `Cipher` only, the value is split as `algorithm/mode/padding`; other factories keep the whole string (`SHA-512/256`). A `Cipher` whose algorithm is a bare `AES`, `DES` or `DESede` gets `jca_default_mode_ecb_possible`, since providers usually default those to ECB.

Row fields:

| Field | Meaning |
|---|---|
| `file`, `line` | Repository-relative path and the line of the class name in the call. |
| `api` | `<Class>.getInstance`, `new <Spec>`, or `bc:<Class>` for BouncyCastle. |
| `algorithm`, `mode`, `padding` | As resolved above; `null` when not known. Values are clipped to 256 characters. |
| `key_bits` | From the key-size rules above; otherwise `null`. |
| `provider` | The second `getInstance` argument when it resolves to a constant string; otherwise `null` (a provider object such as `new BouncyCastleProvider()` gives `null`). |
| `quantum_vulnerable` | The same NIST IR 8547 classification as for rows, applied to the row's algorithm (a `Cipher` row as a block cipher, a `MessageDigest` row as a hash, `key_bits` as the key size); `null` when `algorithm` is `null`. |
| `in_cbom` | See below. |
| `label` | The usage label the Java analysis gives that line, by the same rules as an occurrence row (`reachable`, `not_observed`, `unknown`). Its reasons are not copied. |
| `reasons` | `algorithm_not_constant`, `jca_default_mode_ecb_possible`, `cbom_location_only_match`, `cbom_value_clipped:budget`. |

`in_cbom` is `true` only when a CBOM occurrence that mapped to the same file and line has the same normalised algorithm family and a compatible primitive kind. Families come from a fixed table (AES, 3DES, DES, ChaCha20, RSA, ECDSA, ECDH, EdDSA, EC, DH, DSA, MD5, SHA-1, SHA-2, SHA-3, HMAC, PBKDF2, ML-KEM, ML-DSA, SLH-DSA; `SHA256withRSA` is RSA, `secp256r1` is EC); a name that matches none is compared by its full uppercase spelling. Kinds: the sweep row's kind follows its API (cipher, signature, digest, MAC, key agreement, KEM, key generation, other) and the occurrence's kind its CBOM `primitive`; the kinds must be equal, unless one side's kind is other or unknown, in which case any kind matches but only for a family from the table. A row with `algorithm: null` is never `in_cbom`. When a CBOM occurrence sits on the same file and line but the family or kind does not match, the row stays `false` with reason `cbom_location_only_match`.

`in_cbom: false` means "no matching CBOM occurrence at that line", not "the CBOM is wrong": the CBOM tool may report the asset on a different line from the call, under a name in another family, or at a location that did not map to a file under `--root`.

#### Sweep notes and reasons

Sweep notes go into `cbom.notes`, like the other document-level notes:

| Note | Meaning |
|---|---|
| `sweep_java_only` | No `.java` file was analyzed; `sweep` is empty. Python is never swept. |
| `sweep_truncated` | The sweep is incomplete: the 50 000-row cap was reached and at least one more call matched, or a file was skipped or cut short by a cap below. |
| `sweep_constants_limit_exceeded` | The project-wide constant table hit its cap (200 000 declarations or 16 MiB). Collection stops and every constant reference is left unresolved (`algorithm_not_constant`), because a dropped declaration could duplicate a kept one; direct literals still resolve. |
| `sweep:<file>:sweep_memory_limit_exceeded` | Keeping this file's lexer output would pass the 64 MiB project-wide sweep budget; the file is not swept (also `sweep_truncated`). |
| `sweep:<file>:sweep_token_limit_exceeded` | The file has more than 200 000 tokens; it is not swept (also `sweep:<file>:sweep_truncated` and `sweep_truncated`). |
| `sweep:<file>:nesting_too_deep`, `sweep:<file>:unbalanced_braces`, `sweep:<file>:source_size_limit_exceeded` | The sweep's own bracket scan or size check failed; the file gives no rows. |
| `sweep:<file>:literals_truncated` | The file has more than 100 000 string literals; later ones were not recorded, so calls using them may get `algorithm_not_constant` (also `sweep_truncated`). |
| `sweep:<file>:<parse reason>` | The Java analysis marked the file a parse ambiguity (the reason it gives); the file is not swept. |
| `sweep:<file>:bouncycastle_provider_registered` | The file calls `Security.addProvider(new BouncyCastleProvider())`. Information only. |
| `cbom_value_clipped:budget` | The shared row-string budget ran out while sweep rows were written (see below). |

Files the Java walk skipped (over 2 MiB, not UTF-8, unreadable, over the file or source caps) have no sweep data and no `sweep:` note; they show up in `project.not_observed_blocked`.

Limits: at most 50 000 rows per receipt, 200 000 tokens per file, 64 MiB of retained lexer data for the whole project (blanked code, the literal table and decoded literal strings), and 200 000 constant declarations / 16 MiB of constant data. Every sweep string (`file`, `api`, `algorithm`, `mode`, `padding`, `provider`, `label`, `reasons`, and the notes) is charged to the same 64 MiB row-string budget as occurrence rows; once it runs out, longer values are clipped to 32 characters and the row gets `cbom_value_clipped:budget`. Sweep rows are part of the hashed receipt.

What it cannot find: it is a name-based inventory, not proof of what the code uses. It misses calls made through reflection or a wrapper the list does not name, algorithm strings that are not constants (these rows exist but have `algorithm: null`), crypto in Kotlin, Scala or other JVM sources, crypto that lives only in dependencies or bytecode, and BouncyCastle classes outside the fixed list or in files without an `org.bouncycastle.` import. It does not follow a generator or key object across methods or fields, and a `Cipher` row never has `key_bits`. An empty `sweep` does not mean the project uses no crypto.

## Explanation

**Policy.** This mirrors the status and VEX policy of the Go reachability experiment: `not_observed` never means unreachable or safe, and `cbom-check` never emits VEX, in particular never `not_affected`. Every row is `unknown` rather than guessed when a file is missing, outside the root, unreadable, not UTF-8, too large, or the line is out of range; when the enclosing function or class has a decorator outside the allowlist, or has any decorator where the result would otherwise be `not_observed`; when dynamic dispatch could reach it; when the function name is referenced in any way; in Java, when the member or an enclosing type is annotated, reflection is used anywhere, or the method may override a library type's method; and on any parse ambiguity. When unsure, the label is `unknown`, never `not_observed`.

**Limits.**

- Name-based only: no types, no call-site resolution, no data flow. Edges over-approximate (two functions with the same name are one node), so `reachable` is a weak claim; the other direction is guarded by the unknown triggers.
- Python and Java only. Occurrences in any other file are `unknown` (`unsupported_language:<ext>`); Kotlin, Scala, Groovy and other JVM sources inside the root also mark the Java side not fully analyzed.
- No dynamic dispatch or reflection handling: any project-wide use makes undecided rows of that language `unknown` instead of being modelled.
- Attribute calls are not resolved: `m = keys; m.f()` or `obj.f()` makes no edge to a function `f`, so it cannot make `f` `reachable`; it does count as a reference, so `f` is `unknown`, not `not_observed`.
- Not modelled, so `not_observed` can be wrong: framework registration without decorators and without any textual reference to the name (decorated functions are never `not_observed`, so a registering decorator is covered; the shadowing rule still decides the reason), console-script / `pyproject` entry points, test discovery (`test_*`), and anything outside `.py` files (other file types, compiled modules; symlinked files are not followed, which marks the project not fully analyzed). Use `--entry` for those.
- Methods are never `reachable`; an undecorated method nobody references textually can be `not_observed` (a decorated one is `unknown`).
- Dynamic-dispatch, reflection and reflective-library detection are heuristic word lists, not complete: a mechanism whose name is not on a list is not detected and can make `not_observed` wrong.
- Java: framework entry points (servlets, Spring beans, JUnit tests, annotation processors) are not modelled. Most of them carry an annotation, import a listed library or are named in a config file, and so give `unknown`; the rest need `--entry`. Lambda and anonymous-class bodies belong to their enclosing member, so their calls are attributed to it.
- The receipt is unsigned (like the other Vettalon receipts): the hash detects accidental change, not tampering by someone who can rewrite the file.
- It is not a PQC scanner and does not judge the CBOM's completeness. CBOMkit missed the RSA-PSS `sign()` call in the Python fixture; by default `cbom-check` does not look for assets the CBOM omits, in Python or in Java. `--sweep` lists Java JCA / BouncyCastle calls found by name, so a row with `in_cbom: false` can point at a Java call the CBOM may have missed; it does not cover Python, Kotlin, Scala, reflection, non-constant algorithm strings or bytecode-only dependencies, and it is not a complete inventory (see [Sweep](#sweep---sweep-java-only)).
- Accuracy is not measured yet. `benchmarks/cbom-accuracy/` holds self-written cases with real CBOMkit outputs, but the labels are an unreviewed draft, so there are no results to quote.
