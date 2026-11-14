use super::super::{Label, Project, Verdict};

fn verdict(sources: &[(&str, &str)], rel: &str, line: u32) -> Verdict {
    let p = Project::from_sources(sources);
    let r = p.reach(&[]).unwrap();
    p.classify(&r, rel, line)
}

fn reasons(v: &Verdict) -> Vec<&str> {
    v.reasons.iter().map(String::as_str).collect()
}

const REGISTRY: &str = "REG = []\n\n\ndef register(f):\n    REG.append(f)\n    return f\n";

/// Body line of `handler`, which nothing in the project mentions by name.
fn handler_line(src: &str) -> u32 {
    src.lines().count() as u32
}

#[test]
fn spoofed_allowlist_decorators_are_never_not_observed() {
    let handler = "def handler():\n    return rsa.gen()\n";
    // callable arguments to lru_cache / dataclass
    for (head, deco) in [
        ("import functools\n", "@functools.lru_cache(register)\n"),
        (
            "from functools import lru_cache\n",
            "@lru_cache(maxsize=register)\n",
        ),
    ] {
        let src = format!("{head}{deco}{handler}");
        let v = verdict(
            &[("app.py", src.as_str()), ("reg.py", REGISTRY)],
            "app.py",
            handler_line(&src),
        );
        assert_eq!(v.label, Label::Unknown, "{deco}");
        assert_eq!(reasons(&v), ["enclosing_decorated"], "{deco}");
    }
    // a decorated class: its methods are never not_observed either
    let src = "from dataclasses import dataclass\n\n\n@dataclass(Reg)\nclass C:\n    def m(self):\n        return rsa.gen()\n";
    let v = verdict(&[("app.py", src), ("reg.py", REGISTRY)], "app.py", 7);
    assert_eq!(v.label, Label::Unknown);
    assert_eq!(reasons(&v), ["enclosing_decorated"]);
    // a binding of `cache` hidden behind a one-line block header
    let src = format!("def cache(f): import os\n\n\n@cache\n{handler}");
    let v = verdict(&[("app.py", src.as_str())], "app.py", handler_line(&src));
    assert_eq!(v.label, Label::Unknown);
    // attribute rebinding in another file
    let app = format!("import functools\n\n\n@functools.cache\n{handler}");
    let other = "import functools as ft\nft.cache = register\n";
    let v = verdict(
        &[
            ("app.py", app.as_str()),
            ("b.py", other),
            ("reg.py", REGISTRY),
        ],
        "app.py",
        handler_line(&app),
    );
    assert_eq!(v.label, Label::Unknown);
    // `with ... as ft.cache`
    let src = format!(
        "from contextlib import nullcontext\nwith nullcontext(register) as ft.cache:\n    pass\nfrom functools import cache\n\n\n@cache\n{handler}"
    );
    let v = verdict(
        &[("app.py", src.as_str()), ("reg.py", REGISTRY)],
        "app.py",
        handler_line(&src),
    );
    assert_eq!(v.label, Label::Unknown);
}

#[test]
fn benign_decorator_still_allows_a_name_based_chain() {
    let src = "from functools import lru_cache\n\n\n@lru_cache(maxsize=1)\ndef load():\n    return rsa.gen()\n\n\nif __name__ == \"__main__\":\n    load()\n";
    let v = verdict(&[("a.py", src)], "a.py", 6);
    assert_eq!(v.label, Label::Reachable);
    assert_eq!(v.chain, ["a.py:<__main__>", "a.py:load"]);
}

#[test]
fn new_dynamic_words_block_not_observed() {
    let target = "def make_key():\n    return rsa.gen()\n";
    for other in [
        "class A(metaclass=M):\n    pass\n",
        "x = gc.get_objects()\n",
        "x = pickle.loads(b)\n",
        "import ctypes\n",
        "o = f.__annotations__\n",
        "logging.config.dictConfig(c)\n",
    ] {
        let v = verdict(&[("keys.py", target), ("other.py", other)], "keys.py", 2);
        assert_eq!(v.label, Label::Unknown, "{other}");
        assert_eq!(reasons(&v), ["dynamic_dispatch_in_project"], "{other}");
    }
}

#[test]
fn many_accessor_decorators_finish() {
    let mut src = String::from("class K:\n");
    for _ in 0..5_000 {
        src.push_str("    @undefined.setter\n    def m(self, v):\n        pass\n");
    }
    let line = src.lines().count() as u32;
    let v = verdict(&[("a.py", src.as_str())], "a.py", line);
    assert_eq!(v.label, Label::Unknown);
}
