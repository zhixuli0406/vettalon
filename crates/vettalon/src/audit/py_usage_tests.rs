use super::*;

fn verdict(sources: &[(&str, &str)], rel: &str, line: u32) -> Verdict {
    let p = Project::from_sources(sources);
    let r = p.reach(&[]).unwrap();
    p.classify(&r, rel, line)
}

fn reasons(v: &Verdict) -> Vec<&str> {
    v.reasons.iter().map(String::as_str).collect()
}

#[test]
fn top_level_occurrence_is_reachable() {
    let v = verdict(&[("a.py", "import os\nk = rsa.gen()\n")], "a.py", 2);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(reasons(&v), ["module_top_level"]);
    assert_eq!(v.enclosing_function, None);
}

#[test]
fn main_block_chain() {
    let src = "def helper():\n    return rsa.gen()\n\n\ndef main():\n    helper()\n\n\nif __name__ == \"__main__\":\n    main()\n";
    let v = verdict(&[("a.py", src)], "a.py", 2);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(v.chain, ["a.py:<__main__>", "a.py:main", "a.py:helper"]);
    // the call inside the main block itself is `main_block`
    let v = verdict(&[("a.py", src)], "a.py", 10);
    assert_eq!(reasons(&v), ["main_block"]);
}

#[test]
fn unreferenced_function_is_not_observed() {
    let src = "def unused():\n    return rsa.gen()\n";
    let v = verdict(&[("a.py", src)], "a.py", 2);
    assert_eq!(v.label, Label::NotObserved);
    assert_eq!(v.enclosing_function.as_deref(), Some("unused"));
}

#[test]
fn decorated_is_unknown() {
    let src = "@app.route('/x')\ndef view():\n    return rsa.gen()\n";
    let v = verdict(&[("a.py", src)], "a.py", 3);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["enclosing_decorated"]);
    // even when a chain exists
    let src = "@wrap\ndef f():\n    return 1\n\nf()\n";
    assert_eq!(verdict(&[("a.py", src)], "a.py", 3).label, Label::Unknown);
}

#[test]
fn dynamic_dispatch_anywhere_is_unknown() {
    let f = "def unused():\n    return rsa.gen()\n";
    let other = "def run(name):\n    return getattr(mod, name)()\n";
    let v = verdict(&[("a.py", f), ("b.py", other)], "a.py", 2);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["dynamic_dispatch_in_project"]);
    let triggers = [
        "__import__('x')",
        "importlib.import_module('x')",
        "eval('1')",
        "exec('1')",
        "globals()['f']",
    ];
    for trigger in triggers {
        let other = format!("import os\nx = {trigger}\n");
        let v = verdict(&[("a.py", f), ("b.py", other.as_str())], "a.py", 2);
        assert_eq!(v.label, Label::Unknown, "{trigger}");
    }
    // `literal_eval(` is not `eval(`
    let other = "x = ast.literal_eval('1')\n";
    assert_eq!(
        verdict(&[("a.py", f), ("b.py", other)], "a.py", 2).label,
        Label::NotObserved
    );
}

#[test]
fn allowlisted_decorators_keep_the_normal_rules() {
    // @staticmethod, never referenced: a decorated block is never not_observed
    let class = "class K:\n    @staticmethod\n    def make():\n        return rsa.gen()\n";
    let v = verdict(&[("a.py", class)], "a.py", 4);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["enclosing_decorated"]);
    assert_eq!(v.enclosing_function.as_deref(), Some("K.make"));
    // referenced through the class: the method rule gives unknown
    let user = "def go():\n    K.make()\n\n\ngo()\n";
    let v = verdict(&[("a.py", class), ("b.py", user)], "a.py", 4);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["method_attribute_call_exists"]);
    // a @staticmethod-decorated plain function, referenced without an entry path
    let src =
        "@staticmethod\ndef helper():\n    return rsa.gen()\n\n\ndef unused():\n    helper()\n";
    let v = verdict(&[("a.py", src)], "a.py", 3);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["referenced_but_no_entry_path"]);
    // @lru_cache(maxsize=1) called from __main__ is reachable
    let src = "from functools import lru_cache\n\n\n@lru_cache(maxsize=1)\ndef load():\n    return rsa.gen()\n\n\nif __name__ == \"__main__\":\n    load()\n";
    let v = verdict(&[("a.py", src)], "a.py", 6);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(v.chain, ["a.py:<__main__>", "a.py:load"]);
    // a property setter falls through to the method rules
    let src = "class K:\n    @property\n    def x(self):\n        x = 1\n        return x\n\n    @x.setter\n    def x(self, v):\n        rsa.gen()\n";
    let v = verdict(&[("a.py", src)], "a.py", 9);
    assert_eq!(reasons(&v), ["method_referenced_not_modeled"]);
    // @dataclass(...) on a class: its body is module top level
    let src =
        "import dataclasses\n@dataclasses.dataclass(frozen=True)\nclass C:\n    k = rsa.gen()\n";
    let v = verdict(&[("a.py", src)], "a.py", 4);
    assert_eq!(reasons(&v), ["module_top_level"]);
    for deco in [
        "staticmethod",
        "classmethod",
        "property",
        "abc.abstractmethod",
        "functools.lru_cache",
        "functools.lru_cache(maxsize=None, typed=True)",
        "lru_cache()",
        "cache",
        "functools.cached_property",
        "functools.wraps(fn)",
        "wraps(fn)",
        "typing.override",
        "overload",
    ] {
        let src = format!(
            "import abc, functools, typing\n@{deco}\ndef unused():\n    return rsa.gen()\n"
        );
        let v = verdict(&[("a.py", src.as_str())], "a.py", 4);
        assert_eq!(v.label, Label::Unknown, "{deco}");
        assert_eq!(reasons(&v), ["enclosing_decorated"], "{deco}");
    }
}

#[test]
fn other_decorators_stay_unknown() {
    for deco in [
        "app.route('/x')",
        "app.route(\"/x\", methods=[\"GET\"])",
        "register",
        "lru_cache(maxsize=size())",
        "functools.wraps(register(fn))",
        "wraps",
        "cache(1)",
        "property(fget)",
        "dataclass",
        "a.b.setter",
        "name.deleter",
        "router.getter",
        "(lambda f: f)",
    ] {
        let src = format!("@{deco}\ndef unused():\n    return rsa.gen()\n");
        let v = verdict(&[("a.py", src.as_str())], "a.py", 3);
        assert_eq!(v.label, Label::Unknown, "{deco}");
        assert_eq!(reasons(&v), ["enclosing_decorated"], "{deco}");
    }
    // one registering decorator in a stack is enough, above or below
    for stack in [
        "@staticmethod\n    @app.route('/x')",
        "@app.route('/x')\n    @staticmethod",
    ] {
        let src = format!("class K:\n    {stack}\n    def make():\n        return rsa.gen()\n");
        let v = verdict(&[("a.py", src.as_str())], "a.py", 5);
        assert_eq!(reasons(&v), ["enclosing_decorated"], "{stack}");
    }
}

/// The label of `handler`'s body: `prelude`, then `@deco` on `def handler()`.
fn decorated_handler(prelude: &str, deco: &str) -> Verdict {
    let src = format!("{prelude}\n@{deco}\ndef handler():\n    return rsa.gen()\n");
    let line = src.lines().count() as u32;
    verdict(&[("app.py", src.as_str())], "app.py", line)
}

#[test]
fn shadowed_allowlist_decorators_are_unknown() {
    let registry = "REG = {}\n\n\ndef cache(f):\n    REG[f.__name__] = f\n    return f\n\n\ndef run(key):\n    return REG[key]()\n";
    for (prelude, deco, name) in [
        (registry, "cache", "cache"),
        (
            "import registry\ncache = registry.register",
            "cache",
            "cache",
        ),
        ("from app.reg import register as cache", "cache", "cache"),
        ("from x import override", "override", "override"),
        ("property = something", "property", "property"),
        (
            "import functools as ft\nft = registry",
            "ft.cache",
            "ft.cache",
        ),
        (
            "import functools\nfunctools.cache = reg",
            "functools.cache",
            "functools.cache",
        ),
        (
            "import registry as functools",
            "functools.cache",
            "functools.cache",
        ),
        ("import abc", "typing.override", "typing.override"),
        ("import cache", "cache", "cache"),
        ("from functools import wraps as cache", "cache", "cache"),
        ("from .functools import cache", "cache", "cache"),
        ("from reg import *", "cache", "cache"),
        ("for wraps in hooks:\n    pass", "wraps(fn)", "wraps"),
        (
            "with reg() as lru_cache:\n    pass",
            "lru_cache(maxsize=1)",
            "lru_cache",
        ),
        (
            "try:\n    pass\nexcept E as abstractmethod:\n    pass",
            "abstractmethod",
            "abstractmethod",
        ),
        (
            "def f():\n    global staticmethod\n    staticmethod = reg",
            "staticmethod",
            "staticmethod",
        ),
        ("x = (classmethod := reg)", "classmethod", "classmethod"),
        (
            "y = f\"{(cached_property := reg)}\"",
            "cached_property",
            "cached_property",
        ),
        ("a, *overload = reg", "overload", "overload"),
        ("x = 1; cache += reg", "cache", "cache"),
        ("def make(cache):\n    pass", "cache", "cache"),
        ("class cache:\n    pass", "cache", "cache"),
    ] {
        let v = decorated_handler(prelude, deco);
        assert_eq!(v.label, Label::Unknown, "{prelude} / {deco}");
        let want = format!("enclosing_decorated:shadowed_allowlist:{name}");
        assert_eq!(reasons(&v), [want.as_str()], "{prelude} / {deco}");
    }
    // a binding in another file disables the entry project-wide
    let v = verdict(
        &[
            ("app.py", "@cache\ndef handler():\n    return rsa.gen()\n"),
            ("reg.py", "cache = registry.register\n"),
        ],
        "app.py",
        3,
    );
    assert_eq!(
        reasons(&v),
        ["enclosing_decorated:shadowed_allowlist:cache"]
    );
    // a project file named like a canonical module shadows it
    let v = verdict(
        &[
            (
                "app.py",
                "import functools\n@functools.cache\ndef handler():\n    return rsa.gen()\n",
            ),
            ("functools.py", "x = 1\n"),
        ],
        "app.py",
        4,
    );
    assert_eq!(
        reasons(&v),
        ["enclosing_decorated:shadowed_allowlist:functools.cache"]
    );
}

#[test]
fn genuine_allowlist_decorators_stay_benign() {
    for (prelude, deco) in [
        ("from functools import lru_cache", "lru_cache(maxsize=1)"),
        ("import functools", "functools.cache"),
        ("import functools as ft", "ft.cache"),
        ("import functools.x", "functools.lru_cache"),
        ("from typing import override", "override"),
        (
            "from typing_extensions import override as override",
            "override",
        ),
        ("import typing_extensions as te", "te.overload"),
        ("from abc import ABC, abstractmethod", "abstractmethod"),
        ("from functools import *", "cache"),
        (
            "x = f(cache=1, property=2)\nif a == cache:\n    pass",
            "cache",
        ),
        ("", "property"),
    ] {
        let v = decorated_handler(prelude, deco);
        assert_eq!(v.label, Label::Unknown, "{prelude} / {deco}");
        assert_eq!(reasons(&v), ["enclosing_decorated"], "{prelude} / {deco}");
    }
    let src = "from dataclasses import dataclass\n\n\n@dataclass(frozen=True)\nclass C:\n    k = rsa.gen()\n";
    let v = verdict(&[("a.py", src)], "a.py", 6);
    assert_eq!(reasons(&v), ["module_top_level"]);
}

#[test]
fn property_accessors_need_a_benign_property_in_the_same_class() {
    let body = "        rsa.gen()\n";
    let label = |class: &str| {
        let src = format!("{class}{body}");
        let line = src.lines().count() as u32;
        verdict(&[("a.py", src.as_str())], "a.py", line)
    };
    // property -> setter -> deleter: benign, the method rules apply
    let ok = "class K:\n    @property\n    def x(self):\n        return 1\n\n    @x.setter\n    def x(self, v):\n        pass\n\n    def other(self):\n        x = 2\n\n    @x.deleter\n    def x(self):\n";
    assert_eq!(reasons(&label(ok)), ["method_referenced_not_modeled"]);
    for class in [
        // no property at all / accessor of a non-property / on a router
        "class K:\n    @x.setter\n    def x(self, v):\n",
        "class K:\n    def x(self):\n        pass\n\n    @x.setter\n    def x(self, v):\n",
        "import router\nclass K:\n    @router.getter\n    def x(self):\n",
        // rebound between the property and the accessor
        "class K:\n    @property\n    def x(self):\n        pass\n    x = registry\n    @x.getter\n    def x(self):\n",
        "class K:\n    @property\n    def x(self):\n        pass\n    if True:\n        x = registry\n    @x.getter\n    def x(self):\n",
        "class K:\n    @property\n    def x(self):\n        pass\n    from reg import x\n    @x.getter\n    def x(self):\n",
        // the property is in another class / registered too
        "class A:\n    @property\n    def x(self):\n        pass\nclass K:\n    @x.setter\n    def x(self, v):\n",
        "class K:\n    @property\n    @app.route('/x')\n    def x(self):\n        pass\n    @x.setter\n    def x(self, v):\n",
    ] {
        let v = label(class);
        assert_eq!(v.label, Label::Unknown, "{class}");
        assert_eq!(reasons(&v), ["enclosing_decorated"], "{class}");
    }
    // `property` itself shadowed
    let shadowed = format!("property = registry\n{ok}");
    assert_eq!(label(shadowed.as_str()).label, Label::Unknown);
    let src = "property = registry\nclass K:\n    @property\n    def x(self):\n        rsa.gen()\n";
    let v = verdict(&[("a.py", src)], "a.py", 5);
    assert_eq!(
        reasons(&v),
        ["enclosing_decorated:shadowed_allowlist:property"]
    );
}

#[test]
fn introspection_words_block_not_observed() {
    for src in [
        "c = len.__self__.compile(src, \"\", \"exec\")\nc\n",
        "def f():\n    pass\n\n\nf.__globals__[\"han\" + \"dler\"]()\n",
        "import sys\nsys._getframe().f_globals[\"make\" + \"_key\"]()\n",
        "import inspect\ninspect.currentframe()\n",
        "from types import FunctionType\n",
        "x = g.__code__\n",
        "x = g.__wrapped__\n",
        "x = object.__subclasses__()\n",
    ] {
        let v = make_key_label(src);
        assert_eq!(v.label, Label::Unknown, "{src}");
        assert_eq!(reasons(&v), ["dynamic_dispatch_in_project"], "{src}");
    }
}

#[test]
fn leading_bom_does_not_hide_line_one() {
    let src = "\u{feff}@(lambda f: (f(), f)[1])\ndef legacy():\n    pass\n";
    let v = verdict(&[("a.py", src)], "a.py", 3);
    assert_ne!(v.label, Label::NotObserved);
    assert_eq!(reasons(&v), ["enclosing_decorated"]);
    assert_eq!(v.enclosing_function.as_deref(), Some("legacy"));
    // the file hash is over the original bytes, BOM included
    let p = Project::from_sources(&[("a.py", src)]);
    let want = sha256_hex(src.as_bytes());
    assert_eq!(p.file_sha256("a.py"), Some(want.as_str()));
    // a line-1 `def` opens its block
    let src = "\u{feff}def f():\n    return rsa.gen()\n\n\nf()\n";
    let v = verdict(&[("a.py", src)], "a.py", 2);
    assert_eq!(v.enclosing_function.as_deref(), Some("f"));
    assert_eq!(reasons(&v), ["name_based_chain_from_entry"]);
    // a BOM before a non-UTF-8 coding cookie is still ambiguous
    let v = make_key_label("\u{feff}# -*- coding: latin-1 -*-\nx = 1\n");
    assert_eq!(
        reasons(&v),
        ["project_not_fully_analyzed:non_utf8_coding_cookie"]
    );
    // only one BOM is dropped: a second one counts as non-ASCII code
    let v = make_key_label("\u{feff}\u{feff}x = 1\n");
    assert_eq!(v.label, Label::Unknown);
}

#[test]
fn attribute_compile_is_not_dynamic_dispatch() {
    for src in [
        "import re\nP = re.compile('a')\n",
        "p = re . compile('a')\n",
        "p = re.\\\n    compile('a')\n",
        "x = pattern.compile\n",
    ] {
        assert_eq!(make_key_label(src).label, Label::NotObserved, "{src}");
    }
    for src in [
        "from re import compile\n",
        "x = compile('1', 'f', 'exec')\n",
        "c = (compile)\n",
        "x = f\"{compile}\"\n",
        "import re\nP = re.compile('a')\nc = compile\n",
    ] {
        let v = make_key_label(src);
        assert_eq!(reasons(&v), ["dynamic_dispatch_in_project"], "{src}");
    }
}

#[test]
fn dunder_all_is_unknown() {
    let src = "__all__ = [\"unused\"]\n\n\ndef unused():\n    return rsa.gen()\n";
    let v = verdict(&[("a.py", src)], "a.py", 5);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["name_in_dunder_all"]);
}

#[test]
fn method_with_and_without_attribute_call() {
    let class = "class K:\n    def make(self):\n        return rsa.gen()\n";
    let v = verdict(&[("a.py", class)], "a.py", 3);
    assert_eq!(v.label, Label::NotObserved);
    assert_eq!(v.enclosing_function.as_deref(), Some("K.make"));
    let user = "def go(k):\n    k.make()\n\ngo(1)\n";
    let v = verdict(&[("a.py", class), ("b.py", user)], "a.py", 3);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["method_attribute_call_exists"]);
}

#[test]
fn dunder_method_is_unknown() {
    let src = "class K:\n    def __init__(self):\n        self.k = rsa.gen()\n";
    let v = verdict(&[("a.py", src)], "a.py", 3);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["dunder_name_implicit_call"]);
}

#[test]
fn aliased_import_counts() {
    let a = "def f():\n    return rsa.gen()\n";
    let b = "from a import f as g\n\n\ndef k():\n    g()\n\n\nk()\n";
    let v = verdict(&[("a.py", a), ("b.py", b)], "a.py", 2);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(v.chain, ["b.py:<module>", "b.py:k", "a.py:f"]);
    // imported (even aliased) but never called: referenced, no path
    let b = "from a import f as g\n";
    let v = verdict(&[("a.py", a), ("b.py", b)], "a.py", 2);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["referenced_but_no_entry_path"]);
}

#[test]
fn comment_and_string_references_do_not_count() {
    let a = "def f():\n    return rsa.gen()\n";
    let b =
        "# f()\nx = \"f()\"\ny = '''\nf()\n'''\n\n\ndef doc():\n    \"\"\"call f() here\"\"\"\n";
    let v = verdict(&[("a.py", a), ("b.py", b)], "a.py", 2);
    assert_eq!(v.label, Label::NotObserved);
    // but an f-string expression is code
    let b = "x = f\"{f()}\"\n";
    assert_ne!(
        verdict(&[("a.py", a), ("b.py", b)], "a.py", 2).label,
        Label::NotObserved
    );
}

#[test]
fn referenced_but_no_entry_path_is_unknown() {
    let src = "def f():\n    return rsa.gen()\n\n\ndef g():\n    f()\n";
    let v = verdict(&[("a.py", src)], "a.py", 2);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["referenced_but_no_entry_path"]);
    assert_eq!(
        verdict(&[("a.py", src)], "a.py", 6).label,
        Label::NotObserved
    );
}

#[test]
fn attribute_call_on_object_is_a_reference_but_no_edge() {
    // `AESGCM(key).encrypt(...)` makes no edge to the module function
    // `encrypt`, but it is a textual reference: `unknown`, never
    // `not_observed`. `keys.encrypt(...)` on an imported module is an edge.
    let a = "def encrypt(d):\n    return 1\n\n\nx = AESGCM(k).encrypt(d)\n";
    let v = verdict(&[("a.py", a)], "a.py", 2);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["referenced_but_no_entry_path"]);
    let b = "import a\n\n\ndef go():\n    a.encrypt(1)\n\n\ngo()\n";
    assert_eq!(
        verdict(&[("a.py", a), ("b.py", b)], "a.py", 2).label,
        Label::Reachable
    );
}

#[test]
fn module_alias_through_a_variable_is_unknown() {
    let keys = "def make_key():\n    return rsa.gen()\n";
    let main = "import keys\n\n\ndef go():\n    m = keys\n    m.make_key()\n\n\ngo()\n";
    let v = verdict(&[("keys.py", keys), ("main.py", main)], "keys.py", 2);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["referenced_but_no_entry_path"]);
}

const MAKE_KEY: &str = "def make_key():\n    return rsa.gen()\n";

/// The label of `keys.py:2` (`make_key`'s body) next to `other`.
fn make_key_label(other: &str) -> Verdict {
    verdict(&[("keys.py", MAKE_KEY), ("other.py", other)], "keys.py", 2)
}

#[test]
fn dynamic_dispatch_bare_words_block_not_observed() {
    assert_eq!(make_key_label("x = 1\n").label, Label::NotObserved);
    let v = make_key_label("ga = getattr\nx = ga(m, 'make_' + 'key')()\n");
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["dynamic_dispatch_in_project"]);
    for src in [
        "setattr(m, 'x', 1)\n",
        "f = compile\n",
        "v = vars\n",
        "d = m.__dict__\n",
        "x = sys.modules\n",
        "x = sys \\\n    .modules\n",
        "from operator import attrgetter\n",
        "from operator import methodcaller as mc\n",
        "from inspect import getmembers\n",
        "class A:\n    def __getattr__(self, n):\n        return 1\n",
        "o.__getattribute__\n",
        "g = globals\n",
        "l = locals\n",
        "x = f\"{getattr}\"\n",
        "x = t\"{eval}\"\n",
    ] {
        assert_eq!(make_key_label(src).label, Label::Unknown, "{src}");
    }
    // words inside plain strings and comments do not count
    let v = make_key_label("x = 'getattr eval'  # sys.modules\n");
    assert_eq!(v.label, Label::NotObserved);
}

#[test]
fn fstring_contents_are_code_never_docstrings() {
    for other in [
        "f\"\"\"{make_key()}\"\"\"\n",
        "def g():\n    f\"\"\"{make_key()}\"\"\"\n",
        "x = F'{make_key()}'\n",
        "x = rf'{make_key()}'\n",
        "x = f'''\n{make_key()}\n'''\n",
    ] {
        assert_ne!(make_key_label(other).label, Label::NotObserved, "{other}");
    }
    // at module top the reference is an edge
    let v = make_key_label("f\"\"\"{make_key()}\"\"\"\n");
    assert_eq!(v.label, Label::Reachable);
}

#[test]
fn tstring_contents_are_code() {
    for other in [
        "x = t\"{make_key()}\"\n",
        "x = T'{make_key()}'\n",
        "x = rt\"\"\"{make_key()}\"\"\"\n",
        "x = Tr'{make_key()}'\n",
        "t\"\"\"{make_key()}\"\"\"\n",
    ] {
        assert_ne!(make_key_label(other).label, Label::NotObserved, "{other}");
    }
}

#[test]
fn nested_same_quote_fstring_does_not_hide_a_call() {
    for other in [
        "x = f\"{d[\"a\"]} {make_key()}\"\n",
        "x = f\"{d[\"#\"]} {make_key()}\"\n",
        "x = f'{d['a']:>{w}} {make_key()}'\n",
        "x = f\"{x:'^10} {make_key()}\"\n",
        "x = f\"{f\"{f\"{1}\"}\"} {make_key()}\"\n",
    ] {
        assert_ne!(make_key_label(other).label, Label::NotObserved, "{other}");
    }
}

#[test]
fn multi_line_fstring_cannot_fake_a_def() {
    // Text inside a triple-quoted f-string must not open a block that
    // swallows the real function's body.
    let src =
        "def real():\n    x = f\"\"\"\ndef fake():\n    \"\"\"\n    key = rsa.gen()\n\n\nreal()\n";
    let v = verdict(&[("a.py", src)], "a.py", 5);
    assert_eq!(v.enclosing_function.as_deref(), Some("real"));
    assert_eq!(v.label, Label::Reachable);
}

#[test]
fn non_ascii_identifier_blocks_not_observed() {
    // fullwidth `ｍ` is NFKC-normalised to `m`: this calls make_key
    let v = make_key_label("x = \u{ff4d}ake_key()\n");
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(
        reasons(&v),
        ["project_not_fully_analyzed:non_ascii_identifier_possible"]
    );
    let v = make_key_label("x = f\"{\u{ff4d}ake_key()}\"\n");
    assert_eq!(v.label, Label::Unknown);
    // non-ASCII in strings, f-string text and comments is fine
    let v = make_key_label("x = 'caf\u{e9}'  # na\u{ef}ve\ny = f\"\u{e9}{x}\"\n");
    assert_eq!(v.label, Label::NotObserved);
    // a leading BOM is not code
    let v = make_key_label("\u{feff}x = 1\n");
    assert_eq!(v.label, Label::NotObserved);
}

#[test]
fn lone_cr_blocks_not_observed() {
    let v = make_key_label("x = 1\rmake_key()\n");
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(
        reasons(&v),
        ["project_not_fully_analyzed:lone_cr_line_ending"]
    );
    // CRLF is an ordinary line ending
    assert_eq!(
        make_key_label("x = 1\r\ny = 2\r\n").label,
        Label::NotObserved
    );
}

#[test]
fn non_utf8_coding_cookie_blocks_not_observed() {
    let v = make_key_label("# -*- coding: utf-7 -*-\nx = 1\n");
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(
        reasons(&v),
        ["project_not_fully_analyzed:non_utf8_coding_cookie"]
    );
    let v = make_key_label("#!/usr/bin/env python\n# vim: set fileencoding=latin-1 :\n");
    assert_eq!(v.label, Label::Unknown);
    for ok in [
        "# -*- coding: utf-8 -*-\nx = 1\n",
        "# coding=UTF8\n",
        "# vim: set fileencoding=utf_8 :\n",
        "#!/bin/python\n# coding: utf-8-sig\n",
    ] {
        assert_eq!(make_key_label(ok).label, Label::NotObserved, "{ok}");
    }
}

#[test]
fn skipped_directories_block_not_observed() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path().canonicalize().unwrap();
    std::fs::write(root.join("keys.py"), MAKE_KEY).unwrap();
    std::fs::create_dir_all(root.join(".git")).unwrap();
    std::fs::create_dir_all(root.join("__pycache__")).unwrap();
    std::fs::write(root.join("__pycache__/x.py"), "make_key()\n").unwrap();
    let label = |p: &Project| {
        let r = p.reach(&[]).unwrap();
        p.classify(&r, "keys.py", 2)
    };
    // `.git` / `__pycache__` are skipped silently
    assert_eq!(label(&Project::load(&root)).label, Label::NotObserved);
    std::fs::create_dir_all(root.join("venv/lib")).unwrap();
    std::fs::write(root.join("venv/lib/use.py"), "make_key()\n").unwrap();
    let v = label(&Project::load(&root));
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(
        reasons(&v),
        ["project_not_fully_analyzed:skipped_directory"]
    );
}

#[cfg(unix)]
#[test]
fn read_capped_refuses_symlinks_and_swapped_files() {
    let t = tempfile::tempdir().unwrap();
    let real = t.path().join("real.py");
    std::fs::write(&real, "x = 1\n").unwrap();
    let link = t.path().join("link.py");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(read_capped(&link, 100, None).is_err());
    let id = file_id(&std::fs::symlink_metadata(&real).unwrap());
    assert_eq!(
        read_capped(&real, 100, id).unwrap().as_deref(),
        Some(&b"x = 1\n"[..])
    );
    assert!(read_capped(&real, 100, Some((0, 0))).is_err());
    assert_eq!(read_capped(&real, 3, id).unwrap(), None);
}

#[test]
fn bfs_expands_each_name_once_and_keeps_the_first_chain() {
    // many callers of the same name: same result, first chain kept
    let mut src = String::from("def target():\n    return rsa.gen()\n\n\n");
    for i in 0..200 {
        src.push_str(&format!("def c{i}():\n    target()\n    target()\n\n\n"));
    }
    src.push_str("c7()\nc3()\n");
    let v = verdict(&[("a.py", src.as_str())], "a.py", 2);
    assert_eq!(v.label, Label::Reachable);
    // `c7()` is the first module-level call, so BFS reaches target via c7
    assert_eq!(v.chain, ["a.py:<module>", "a.py:c7", "a.py:target"]);
}

#[test]
fn duplicate_aliases_are_deduplicated() {
    let a = "def f():\n    return rsa.gen()\n";
    let b = "from a import f as g\nfrom a import f as g\nfrom a import f as f\n\n\ndef k():\n    g()\n\n\nk()\n";
    let p = Project::from_sources(&[("a.py", a), ("b.py", b)]);
    assert_eq!(p.alias["g"].len(), 1);
    let fi = p.index["b.py"];
    let k = p.files[fi]
        .blocks
        .iter()
        .position(|b| b.name == "k")
        .unwrap();
    let refs = &p.files[fi].refs[&(k as u32)];
    assert_eq!(refs.len(), 2, "{refs:?}"); // `g` and its target `f`, once each
    let r = p.reach(&[]).unwrap();
    assert_eq!(p.classify(&r, "a.py", 2).label, Label::Reachable);
}

#[test]
fn multiline_header_keeps_body_inside_function() {
    let src = "def f(\n    a,\n    b,\n):\n    return rsa.gen()\n";
    let v = verdict(&[("a.py", src)], "a.py", 5);
    assert_eq!(v.enclosing_function.as_deref(), Some("f"));
    assert_eq!(v.label, Label::NotObserved);
}

#[test]
fn explicit_entry_makes_function_reachable() {
    let src = "def handler():\n    return rsa.gen()\n";
    let p = Project::from_sources(&[("pkg/app.py", src)]);
    let r = p.reach(&["pkg.app:handler".to_string()]).unwrap();
    let v = p.classify(&r, "pkg/app.py", 2);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(v.chain, ["--entry pkg.app:handler", "pkg/app.py:handler"]);
    assert!(p.reach(&["pkg.app:nope".to_string()]).is_err());
    assert!(p.reach(&["nocolon".to_string()]).is_err());
}

#[test]
fn fail_closed_cases() {
    let p = Project::from_sources(&[("a.py", "def f():\n    pass\n")]);
    let r = p.reach(&[]).unwrap();
    assert_eq!(reasons(&p.classify(&r, "a.py", 9)), ["line_out_of_range"]);
    assert_eq!(reasons(&p.classify(&r, "a.py", 0)), ["line_out_of_range"]);
    assert_eq!(reasons(&p.classify(&r, "a.txt", 1)), ["file_not_analyzed"]);
    assert_eq!(reasons(&p.classify(&r, "b.py", 1)), ["file_not_analyzed"]);
    // an unparsable file blocks `not_observed` project-wide
    let p = Project::from_sources(&[
        ("a.py", "def f():\n    pass\n"),
        ("b.py", "x = '''never closed\n"),
    ]);
    let r = p.reach(&[]).unwrap();
    assert_eq!(p.classify(&r, "a.py", 2).label, Label::Unknown);
    assert_eq!(reasons(&p.classify(&r, "b.py", 1)), ["parse_ambiguity"]);
}

#[test]
fn star_import_fails_closed() {
    let a = "def f():\n    return rsa.gen()\n";
    let b = "from a import *\n";
    let v = verdict(&[("a.py", a), ("b.py", b)], "a.py", 2);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["star_import_may_expose"]);
}

#[test]
fn tree_hash_is_stable_and_content_sensitive() {
    let a = Project::from_sources(&[("a.py", "x = 1\n"), ("b.py", "y = 2\n")]);
    let b = Project::from_sources(&[("b.py", "y = 2\n"), ("a.py", "x = 1\n")]);
    let c = Project::from_sources(&[("a.py", "x = 1\n"), ("b.py", "y = 3\n")]);
    assert_eq!(a.tree_sha256(), b.tree_sha256());
    assert_ne!(a.tree_sha256(), c.tree_sha256());
}

#[test]
fn lexer_views_keep_lines_and_fstrings() {
    let s = "a = 'x f()'\nb = f'{g()}'\nc = \"\"\"l1\nl2\"\"\"\n# c h()\nd = \"#\" + k()\n";
    let lx = lex(s).unwrap();
    for view in [&lx.code, &lx.structure, &lx.refs] {
        assert_eq!(view.chars().count(), s.chars().count());
        assert_eq!(view.lines().count(), s.lines().count());
        assert!(!view.contains("h()"));
        assert!(view.contains("k()"));
    }
    assert!(!lx.refs.contains("x f()"));
    assert!(lx.refs.contains("g()"));
    assert!(!lx.structure.contains("g()"));
    assert!(lx.code.contains("x f()"));
    assert_eq!(lx.in_string_eol, [false, false, true, false, false, false]);
    assert!(lex("a = 'oops\n").is_none());
    assert!(lex("a = f'{oops'\n").is_none());
    // nesting deeper than the cap fails closed instead of recursing
    let deep = format!("x = {}1{}\n", "f'{".repeat(40), "}'".repeat(40));
    assert!(lex(&deep).is_none());
}
