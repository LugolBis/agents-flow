use regex::Regex;
use std::sync::LazyLock;

pub(super) const IGNORED: &[&str] = &[
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    "env",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    "target",
    ".idea",
    ".vscode",
    ".ruff_cache",
    ".next",
    ".gradle",
    "vendor",
];

pub(super) const LANGS: &[(&str, &str)] = &[
    (".py", "Python"),
    (".js", "JavaScript"),
    (".ts", "TypeScript"),
    (".tsx", "TypeScript"),
    (".jsx", "JavaScript"),
    (".java", "Java"),
    (".kt", "Kotlin"),
    (".go", "Go"),
    (".rs", "Rust"),
    (".c", "C"),
    (".h", "C/C++"),
    (".cpp", "C++"),
    (".cs", "C#"),
    (".rb", "Ruby"),
    (".php", "PHP"),
    (".swift", "Swift"),
    (".sh", "Shell"),
    (".sql", "SQL"),
    (".html", "HTML"),
    (".css", "CSS"),
    (".md", "Markdown"),
    (".yml", "YAML"),
    (".yaml", "YAML"),
    (".json", "JSON"),
    (".jsonc", "JSONC"),
    (".toml", "TOML"),
];

pub(super) const MANIFESTS: &[&str] = &[
    "pyproject.toml",
    "setup.py",
    "setup.cfg",
    "requirements.txt",
    "Pipfile",
    "package.json",
    "Cargo.toml",
    "go.mod",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "composer.json",
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "Makefile",
    "tox.ini",
    ".gitignore",
];

pub(super) const FRAMEWORKS: &[(&str, &str)] = &[
    ("django", "Django"),
    ("flask", "Flask"),
    ("fastapi", "FastAPI"),
    ("crewai", "CrewAI"),
    ("pytest", "pytest"),
    ("pydantic", "Pydantic"),
    ("react", "React"),
    ("vue", "Vue"),
    ("next", "Next.js"),
    ("express", "Express"),
    ("angular", "Angular"),
    ("jest", "Jest"),
    ("svelte", "Svelte"),
];

pub(super) const MAX_FILES: usize = 5000;

pub(super) static DEP_SPLIT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[<>=!~ ;\[]").unwrap());

pub(super) static TEST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:(?:test_.*|.*_test)\.py|.*\.(?:test|spec)\.[jt]sx?)$").unwrap()
});

pub(super) static RE_IMPORT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*import\s+(.+)$").unwrap());

pub(super) static RE_FROM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*from\s+(\.*)([A-Za-z_][\w.]*)?\s+import\s+(.+)$").unwrap());

pub(super) static RE_CLASS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*class\s+[A-Za-z_]").unwrap());

pub(super) static RE_DEF: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\s*(?:async\s+)?def\s+[A-Za-z_]").unwrap());
