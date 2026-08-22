from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess

import pytest

from experiments.local_campaign.generate import (
    BINDINGS_SCHEMA,
    EXTERNAL_BINDINGS,
    package_controller_set,
    render_controller_set,
)
from experiments.pytest_tmp_cleanup import (
    CleanupRefusal,
    clean_owned_pytest_tmp_root,
    make_directories_user_cleanable,
)


ROOT = Path(__file__).parents[2]
TEMPLATES = ROOT / "experiments" / "local_campaign" / "templates"


@pytest.fixture(autouse=True)
def _make_retained_pytest_artifacts_user_cleanable(tmp_path: Path) -> Iterator[None]:
    """pytest keeps failed tmp trees; leave immutable-install fixtures removable."""
    yield
    if os.name == "posix" and tmp_path.exists() and not tmp_path.is_symlink():
        make_directories_user_cleanable(tmp_path)


@pytest.mark.skipif(os.name != "posix", reason="permission cleanup is POSIX-specific")
def test_permission_finalizer_restores_only_fixture_tree_without_following_links(
    tmp_path: Path,
) -> None:
    root = tmp_path / "immutable-fixture"
    protected = root / "generation" / "controller.sh"
    protected.parent.mkdir(parents=True)
    protected.write_text("fixture", encoding="utf-8")
    outside = tmp_path / "outside-target"
    outside.write_text("outside", encoding="utf-8")
    (root / "generation" / "outside-link").symlink_to(outside)
    protected.chmod(0o400)
    protected.parent.chmod(0o500)
    root.chmod(0o500)
    outside.chmod(0o400)

    make_directories_user_cleanable(root)

    assert protected.stat().st_mode & 0o777 == 0o400
    assert protected.parent.stat().st_mode & stat.S_IRWXU == stat.S_IRWXU
    assert root.stat().st_mode & stat.S_IRWXU == stat.S_IRWXU
    assert outside.stat().st_mode & 0o777 == 0o400


@pytest.mark.skipif(os.name != "posix", reason="fd-safe cleanup is POSIX-specific")
def test_fd_safe_pytest_cleanup_removes_only_the_expected_owned_tree(tmp_path: Path) -> None:
    root = tmp_path / "pytest-of-fixture"
    immutable = root / "generation" / "controller.sh"
    immutable.parent.mkdir(parents=True)
    immutable.write_text("fixture", encoding="utf-8")
    outside = tmp_path / "outside-target"
    outside.write_text("outside", encoding="utf-8")
    (root / "generation" / "outside-link").symlink_to(outside)
    immutable.parent.chmod(0o500)
    root.chmod(0o500)
    outside.chmod(0o400)

    clean_owned_pytest_tmp_root(root, expected_root=root)

    assert not root.exists()
    assert not root.is_symlink()
    assert outside.read_text(encoding="utf-8") == "outside"
    assert outside.stat().st_mode & 0o777 == 0o400


@pytest.mark.skipif(os.name != "posix", reason="fd-safe cleanup is POSIX-specific")
def test_fd_safe_pytest_cleanup_refuses_a_wrong_or_symlinked_root(tmp_path: Path) -> None:
    actual = tmp_path / "pytest-of-fixture"
    actual.mkdir()
    wrong = tmp_path / "other-root"
    with pytest.raises(CleanupRefusal, match="unexpected pytest temp root"):
        clean_owned_pytest_tmp_root(actual, expected_root=wrong)

    outside = tmp_path / "outside-directory"
    outside.mkdir()
    symlinked = tmp_path / "pytest-of-symlink"
    symlinked.symlink_to(outside, target_is_directory=True)
    with pytest.raises(CleanupRefusal, match="symlinked pytest temp root"):
        clean_owned_pytest_tmp_root(symlinked, expected_root=symlinked)
    assert outside.is_dir()


def _posix_path(path: Path) -> str:
    resolved = Path(os.path.abspath(path))
    if os.name != "nt":
        return str(resolved)
    drive = resolved.drive.rstrip(":").lower()
    tail = resolved.as_posix().split(":", 1)[1].lstrip("/")
    return f"/{drive}/{tail}"


def _binding_values(active: Path, commit: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in EXTERNAL_BINDINGS:
        if key == "EXPECTED_COMMIT":
            values[key] = commit
        elif key == "CONTROLLER_INSTALL_ROOT":
            values[key] = _posix_path(active)
        elif key == "PHASE3_DOWNLOADED_BYTES":
            values[key] = "0"
        elif key.endswith("_BYTES"):
            values[key] = "1"
        elif key.endswith("SHA256"):
            values[key] = "2" * 64
        elif key.endswith("_TAG"):
            values[key] = "20260822T120000Z"
        elif key.endswith(("_PATH", "_ROOT")):
            values[key] = f"/bound/{key.lower()}"
        elif key.endswith("_NAME"):
            values[key] = f"fixture-{key.lower()}"
        elif key.endswith("_REASON"):
            values[key] = "fixture_reason"
        else:  # pragma: no cover - the explicit binding schema must stay typed
            raise AssertionError(f"atomic installer fixture has no value rule for {key}")
    return values


@dataclass(frozen=True)
class _Package:
    output: Path
    installer: Path
    verifier: Path
    archive_sha256: str
    generation_name: str


def _build_package(base: Path, commit: str, slot: str) -> _Package:
    active = base / ".ura-controller-active"
    bindings = base / f"bindings-{slot}.json"
    bindings.write_text(
        json.dumps(
            {
                "schema": BINDINGS_SCHEMA,
                "values": _binding_values(active, commit),
            }
        ),
        encoding="utf-8",
    )
    output = base / f"package-{slot}"
    render_controller_set(bindings, output)
    record = package_controller_set(bindings, output)
    short = commit[:7]
    archive = record["archive"]
    assert isinstance(archive, dict)
    archive_sha256 = str(archive["sha256"])
    archive_name = str(archive["name"])
    shutil.copyfile(output / archive_name, base / archive_name)
    return _Package(
        output=output,
        installer=output / f"install_controller_set_{short}.sh",
        verifier=output / f"verify_controllers_{short}.sh",
        archive_sha256=archive_sha256,
        generation_name=f"{short}-{archive_sha256}",
    )


@dataclass(frozen=True)
class _ShellHost:
    bash: str
    path: str
    environment: dict[str, str]


def _require_posix_installer_host(tmp_path: Path) -> _ShellHost:
    bash = shutil.which("bash")
    environment: dict[str, str] = {}
    if os.name == "nt":
        git_bash = Path("C:/Program Files/Git/bin/bash.exe")
        if git_bash.is_file():
            bash = str(git_bash)
    if bash is None:
        pytest.skip("bash is unavailable")
    if os.name == "nt":
        environment["MSYS"] = "winsymlinks:nativestrict"
    path_probe = subprocess.run(
        [bash, "-lc", 'printf %s "$PATH"'],
        env={**os.environ, **environment},
        capture_output=True,
        text=True,
        check=False,
    )
    if path_probe.returncode != 0 or not path_probe.stdout:
        pytest.skip("bash PATH is unavailable")
    shell_path = path_probe.stdout
    required = ("awk", "cmp", "find", "mktemp", "sha256sum", "stat", "tar")
    probe = subprocess.run(
        [bash, "-c", "for tool; do command -v \"$tool\" >/dev/null || exit 1; done", "--", *required],
        env={**os.environ, **environment, "PATH": shell_path},
        capture_output=True,
        text=True,
        check=False,
    )
    if probe.returncode != 0:
        pytest.skip("atomic controller installer prerequisites are unavailable")
    flock_probe = subprocess.run(
        [bash, "-c", "command -v flock >/dev/null"],
        env={**os.environ, **environment, "PATH": shell_path},
        capture_output=True,
        text=True,
        check=False,
    )
    if flock_probe.returncode != 0:
        # Git for Windows has the needed GNU filesystem tools but omits flock.
        # These tests are single-process interruption tests; lock acquisition is
        # separately mutation-guarded in the rendered templates.
        helpers = tmp_path / "host-bin"
        helpers.mkdir()
        flock = helpers / "flock"
        flock.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
        flock.chmod(0o700)
        shell_path = f"{_posix_path(helpers)}:{shell_path}"
    target = tmp_path / "symlink-target"
    link = tmp_path / "symlink-probe"
    symlink_probe = subprocess.run(
        [bash, "-c", 'printf probe > "$1" && ln -s "${1##*/}" "$2" && test -L "$2"', "--", _posix_path(target), _posix_path(link)],
        env={**os.environ, **environment, "PATH": shell_path},
        capture_output=True,
        text=True,
        check=False,
    )
    if symlink_probe.returncode != 0 or not link.is_symlink():
        pytest.skip("native symlink semantics are unavailable")
    return _ShellHost(bash=bash, path=shell_path, environment=environment)


def _run_installer(
    host: _ShellHost,
    package: _Package,
    home: Path,
    *,
    path: str | None = None,
    interrupt: str | None = None,
) -> subprocess.CompletedProcess[str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("URA_") and key not in {"HOME", "HF_TOKEN"}
    }
    env.update(host.environment)
    env["HOME"] = _posix_path(home)
    env["PATH"] = host.path
    if path is not None:
        env["PATH"] = path
    if interrupt is not None:
        env["URA_TEST_INTERRUPT"] = interrupt
    argv = [host.bash, str(package.installer)]
    if path is not None:
        # Git Bash prepends /usr/bin after importing PATH. Assign inside the
        # shell so the interruption wrapper wins command resolution.
        argv = [
            host.bash,
            "-c",
            'PATH="$1"; export PATH; source "$2"',
            "--",
            path,
            _posix_path(package.installer),
        ]
    return subprocess.run(
        argv,
        cwd=home.parent,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )


def _install_home(base: Path) -> Path:
    home = base / "operator-home"
    home.mkdir()
    (home / ".ura_campaign_env").write_text("", encoding="utf-8")
    return home


def _active_target(base: Path) -> str | None:
    active = base / ".ura-controller-active"
    return os.readlink(active).replace("\\", "/") if active.is_symlink() else None


def _interrupting_path(base: Path, host: _ShellHost) -> str:
    resolved_mv = subprocess.run(
        [host.bash, "-c", "command -v mv"],
        env={**os.environ, **host.environment, "PATH": host.path},
        capture_output=True,
        text=True,
        check=True,
    )
    real_mv = resolved_mv.stdout.strip()
    assert real_mv
    wrappers = base / "interrupt-bin"
    wrappers.mkdir()
    wrapper = wrappers / "mv"
    wrapper.write_text(
        """#!/usr/bin/env bash
set -eu
real_mv='__REAL_MV__'
stage_move=0
active_move=0
for argument in "$@"; do
  case "$argument" in
    */.stage-*) stage_move=1 ;;
    */.ura-controller-active.next.*|*/.ura-controller-active) active_move=1 ;;
  esac
done
case "${URA_TEST_INTERRUPT-}" in
  stage-before)
    if [ "$stage_move" = 1 ]; then kill -KILL "$PPID"; exit 137; fi ;;
  active-before)
    if [ "$active_move" = 1 ]; then kill -KILL "$PPID"; exit 137; fi ;;
  active-after)
    if [ "$active_move" = 1 ]; then
      "$real_mv" "$@"
      result=$?
      kill -KILL "$PPID"
      exit "$result"
    fi ;;
esac
exec "$real_mv" "$@"
""".replace("__REAL_MV__", real_mv),
        encoding="utf-8",
    )
    wrapper.chmod(0o700)
    return f"{_posix_path(wrappers)}:{host.path}"


def test_templates_use_one_atomic_active_generation() -> None:
    installer = (TEMPLATES / "install_controller_set.sh.in").read_text(encoding="utf-8")
    verifier = (TEMPLATES / "verify_controller_set.sh.in").read_text(encoding="utf-8")
    local_readme = (ROOT / "experiments" / "local_campaign" / "README.md").read_text(
        encoding="utf-8"
    )
    runbook = (ROOT / "experiments" / "RUN_AND_RETURN.md").read_text(encoding="utf-8")

    assert 'GENERATION_NAME="$COMMIT_SHORT-$ARCHIVE_SHA256"' in installer
    assert 'flock -x 9' in installer
    assert 'validate_generation "$GENERATION"' in installer
    assert 'mv -Tf -- "$active_next" "$ACTIVE"' in installer
    assert installer.index('validate_generation "$GENERATION"') < installer.index(
        'mv -Tf -- "$active_next" "$ACTIVE"'
    )
    assert 'install -m 700 -- "$STAGE/$name"' not in installer
    assert '@@CONTROLLER_INSTALL_ROOT@@/$name' not in installer
    assert 'flock -s 9' in verifier
    assert 'readonly CONTROLLER_ROOT="$INSTALL_BASE/$ACTIVE_TARGET"' in verifier
    assert 'active controller generation changed during verification' in verifier
    assert "/home/ura/.ura-controller-active" in local_readme
    assert "one atomic active-symlink rename" in local_readme
    assert "bash ~/.ura-controller-active/verify_controllers_<new7>.sh" in runbook
    assert "bash ~/.ura-controller-active/launch_chain_<new7>.sh" in runbook
    assert "opened Linux script descriptor" in runbook
    assert runbook.count("`~/controller-set-<new7>.tar`") == 2
    assert "`~/.controller-set-<new7>.tar`" not in runbook
    vulnerable = (
        "phase3_guard1b_acquire_fit.sh.in",
        "launch_chain.sh.in",
        "launch_phase5_sequence.sh.in",
        "phase5_sequence_after_core.sh.in",
        "launch_gate5_sequence.sh.in",
        "gate5_after_phase5_sequence.sh.in",
        "launch_phase6_sequence.sh.in",
        "phase6_sequence.sh.in",
        "launch_phase7_watcher.sh.in",
        "phase7_after_phase6_sequence.sh.in",
        "phase8_human_audit.sh.in",
    )
    for name in vulnerable:
        source = (TEMPLATES / name).read_text(encoding="utf-8")
        if name == "phase3_guard1b_acquire_fit.sh.in":
            assert "opened_controller_script" in source
            assert 'script="$(opened_controller_script)"' in source
        else:
            assert "pin_controller_generation" in source
            assert "URA_CONTROLLER_GENERATION_ROOT" in source
        assert "@@CONTROLLER_INSTALL_ROOT@@/" not in source


def test_packaged_controllers_bind_internal_launches_to_the_pinned_generation(
    tmp_path: Path,
) -> None:
    base = tmp_path / "controller-base"
    base.mkdir()
    package = _build_package(base, "1" * 40, "one")
    launch_chain = (package.output / "launch_chain_1111111.sh").read_text(
        encoding="utf-8"
    )

    active = _posix_path(base / ".ura-controller-active")
    assert active not in launch_chain
    assert "bash $URA_CONTROLLER_GENERATION_ROOT/launch_phase5_sequence.sh" in launch_chain
    phase5 = (package.output / "phase5_sequence_after_core.sh").read_text(
        encoding="utf-8"
    )
    assert '$URA_CONTROLLER_GENERATION_ROOT/phase5_core_projections.sh' in phase5
    installer = package.installer.read_text(encoding="utf-8")
    assert 'readonly ARCHIVE="$INSTALL_BASE/controller-set-1111111.tar"' in installer
    assert active in installer


def test_running_launcher_stays_on_opened_generation_when_active_switches(
    tmp_path: Path,
) -> None:
    host = _require_posix_installer_host(tmp_path)
    resolved_sha = subprocess.run(
        [host.bash, "-c", "command -v sha256sum"],
        env={**os.environ, **host.environment, "PATH": host.path},
        capture_output=True,
        text=True,
        check=True,
    )
    real_sha256sum = resolved_sha.stdout.strip()
    if not real_sha256sum:
        pytest.skip("sha256sum is unavailable")

    commit = "1" * 40
    short = commit[:7]
    base = tmp_path / "controller-base"
    generations = base / ".ura-controller-generations"
    generations.mkdir(parents=True)
    active = base / ".ura-controller-active"
    archive_a = "a" * 64
    archive_b = "b" * 64
    generation_a = generations / f"{short}-{archive_a}"
    generation_b = generations / f"{short}-{archive_b}"
    generation_a.mkdir()
    generation_b.mkdir()

    child_a = b"#!/usr/bin/env bash\nprintf 'GENERATION=A\\n'\n"
    child_b = b"#!/usr/bin/env bash\nprintf 'GENERATION=B\\n'\n"
    child_name = "phase5_sequence_after_core.sh"
    (generation_a / child_name).write_bytes(child_a)
    (generation_b / child_name).write_bytes(child_b)
    child_a_sha = hashlib.sha256(child_a).hexdigest()

    template = (TEMPLATES / "launch_phase5_sequence.sh.in").read_text(
        encoding="utf-8"
    )
    launcher = (
        template.replace("@@EXPECTED_COMMIT@@", commit)
        .replace("@@COMMIT_SHORT@@", short)
        .replace("@@SHA:phase5_sequence_after_core.sh@@", child_a_sha)
        .replace("@@PHASE5_SEQUENCE_TAG@@", "20260822T120000Z")
    )
    assert "@@" not in launcher
    (generation_a / "launch_phase5_sequence.sh").write_text(
        launcher, encoding="utf-8"
    )
    (generation_b / "launch_phase5_sequence.sh").write_text(
        launcher.replace(child_a_sha, hashlib.sha256(child_b).hexdigest()),
        encoding="utf-8",
    )

    for generation, archive_sha in (
        (generation_a, archive_a),
        (generation_b, archive_b),
    ):
        (generation / ".ura-controller-generation.tsv").write_text(
            "schema\tura-controller-generation/1\n"
            f"expected_commit\t{commit}\n"
            f"archive_sha256\t{archive_sha}\n",
            encoding="ascii",
        )
    active_target_a = f".ura-controller-generations/{generation_a.name}"
    link_result = subprocess.run(
        [host.bash, "-c", 'ln -s "$1" "$2"', "--", active_target_a, _posix_path(active)],
        env={**os.environ, **host.environment, "PATH": host.path},
        capture_output=True,
        text=True,
        check=False,
    )
    assert link_result.returncode == 0, link_result.stdout + link_result.stderr

    home = tmp_path / "home"
    home.mkdir()
    (home / ".ura_campaign_env").write_text("", encoding="utf-8")
    bash_env = tmp_path / "bash-env"
    bash_env.write_text(
        """sha256sum() {
  '__REAL_SHA__' "$@"
  if [ ! -e "$SWITCH_SENTINEL" ]; then
    : > "$SWITCH_SENTINEL"
    local next="$SWITCH_ACTIVE.next.$$"
    ln -s "$SWITCH_TARGET" "$next"
    mv -Tf -- "$next" "$SWITCH_ACTIVE"
  fi
}
tmux() {
  printf '%s\n' "$@" > "$TMUX_CAPTURE"
}
""".replace("__REAL_SHA__", real_sha256sum),
        encoding="utf-8",
    )

    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"HOME", "URA_CONTROLLER_GENERATION_ROOT"}
    }
    env.update(
        **host.environment,
        BASH_ENV=_posix_path(bash_env),
        HOME=_posix_path(home),
        PATH=host.path,
        SWITCH_ACTIVE=_posix_path(active),
        SWITCH_TARGET=f".ura-controller-generations/{generation_b.name}",
        SWITCH_SENTINEL=_posix_path(tmp_path / "switched"),
    )
    result = subprocess.run(
        [host.bash, _posix_path(active / "launch_phase5_sequence.sh")],
        cwd=base,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout == "GENERATION=A\n"
    assert _active_target(base) == f".ura-controller-generations/{generation_b.name}"


@pytest.mark.skipif(
    os.name != "posix",
    reason="Phase 3 live retarget regression requires native Linux path semantics",
)
def test_phase3_tmux_reexec_stays_on_the_opened_generation(tmp_path: Path) -> None:
    host = _require_posix_installer_host(tmp_path)
    commit = "1" * 40
    short = commit[:7]
    base = tmp_path / "controller-base"
    generations = base / ".ura-controller-generations"
    generations.mkdir(parents=True)
    active = base / ".ura-controller-active"
    archive_a = "a" * 64
    archive_b = "b" * 64
    generation_a = generations / f"{short}-{archive_a}"
    generation_b = generations / f"{short}-{archive_b}"
    generation_a.mkdir()
    generation_b.mkdir()

    phase3_name = "phase3_guard1b_acquire_fit.sh"
    phase3_template = (TEMPLATES / f"{phase3_name}.in").read_text(encoding="utf-8")
    phase3_a = (
        phase3_template.replace("@@EXPECTED_COMMIT@@", commit)
        .replace("@@COMMIT_SHORT@@", short)
        .replace("@@PHASE3_GUARD_TAG@@", "20260822T120000Z")
    )
    phase3_b = phase3_a.replace("20260822T120000Z", "20260822T120001Z")
    (generation_a / phase3_name).write_text(phase3_a, encoding="utf-8")
    (generation_b / phase3_name).write_text(phase3_b, encoding="utf-8")

    for generation, archive_sha in (
        (generation_a, archive_a),
        (generation_b, archive_b),
    ):
        (generation / ".ura-controller-generation.tsv").write_text(
            "schema\tura-controller-generation/1\n"
            f"expected_commit\t{commit}\n"
            f"archive_sha256\t{archive_sha}\n",
            encoding="ascii",
        )
    active.symlink_to(Path(".ura-controller-generations") / generation_a.name)

    phase3_switch = tmp_path / "phase3-switched"
    work = tmp_path / "work"
    work.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    campaign_env = home / ".ura_campaign_env"
    campaign_env.write_text(
        f"export URA_WORK='{_posix_path(work)}'\n"
        f"if [ ! -e '{_posix_path(phase3_switch)}' ]; then\n"
        f"  : > '{_posix_path(phase3_switch)}'\n"
        f"  ln -s '.ura-controller-generations/{generation_b.name}' '{_posix_path(active)}.next'\n"
        f"  mv -Tf -- '{_posix_path(active)}.next' '{_posix_path(active)}'\n"
        "fi\n",
        encoding="utf-8",
    )
    tmux_capture = tmp_path / "tmux-argv.txt"
    bash_env = tmp_path / "bash-env"
    bash_env.write_text(
        """tmux() {
  printf '%s\n' "$@" > "$TMUX_CAPTURE"
}
""",
        encoding="utf-8",
    )
    phase3_env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"HOME", "URA_CONTROLLER_GENERATION_ROOT"}
    }
    phase3_env.update(
        **host.environment,
        BASH_ENV=_posix_path(bash_env),
        HOME=_posix_path(home),
        PATH=host.path,
        TMUX_CAPTURE=_posix_path(tmux_capture),
    )
    phase3_result = subprocess.run(
        [host.bash, _posix_path(active / phase3_name)],
        cwd=base,
        env=phase3_env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert phase3_result.returncode == 0, phase3_result.stdout + phase3_result.stderr
    launched = tmux_capture.read_text(encoding="utf-8")
    assert _posix_path(generation_a / phase3_name) in launched
    assert _posix_path(generation_b / phase3_name) not in launched
    assert _active_target(base) == f".ura-controller-generations/{generation_b.name}"


def test_exact_rerun_is_idempotent_and_foreign_generation_never_activates(
    tmp_path: Path,
) -> None:
    host = _require_posix_installer_host(tmp_path)
    base = tmp_path / "controller-base"
    base.mkdir()
    home = _install_home(base)
    first = _build_package(base, "1" * 40, "one")

    installed = _run_installer(host, first, home)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    expected_first = f".ura-controller-generations/{first.generation_name}"
    assert _active_target(base) == expected_first
    first_generation = base / ".ura-controller-generations" / first.generation_name
    assert first_generation.is_dir() and not first_generation.is_symlink()
    assert len(tuple(first_generation.iterdir())) == 27

    rerun = _run_installer(host, first, home)
    assert rerun.returncode == 0, rerun.stdout + rerun.stderr
    assert _active_target(base) == expected_first

    second = _build_package(base, "2" * 40, "two")
    foreign = base / ".ura-controller-generations" / second.generation_name
    foreign.mkdir()
    (foreign / "foreign-file").write_text("foreign", encoding="utf-8")
    refused = _run_installer(host, second, home)
    assert refused.returncode != 0
    assert "controller inventory" in refused.stderr
    assert _active_target(base) == expected_first
    assert (foreign / "foreign-file").read_text(encoding="utf-8") == "foreign"


@pytest.mark.skipif(
    os.name != "posix",
    reason="SIGKILL interruption requires reliable POSIX parent-process identity",
)
def test_interruption_before_or_after_the_switch_recovers_without_a_mixed_set(
    tmp_path: Path,
) -> None:
    host = _require_posix_installer_host(tmp_path)
    base = tmp_path / "controller-base"
    base.mkdir()
    home = _install_home(base)
    wrapped_path = _interrupting_path(base, host)

    first = _build_package(base, "1" * 40, "one")
    assert _run_installer(host, first, home).returncode == 0
    first_target = _active_target(base)

    second = _build_package(base, "2" * 40, "two")
    stopped_stage = _run_installer(
        host, second, home, path=wrapped_path, interrupt="stage-before"
    )
    assert stopped_stage.returncode != 0
    assert _active_target(base) == first_target
    stages = tuple((base / ".ura-controller-generations").glob(".stage-*"))
    assert stages
    recovered_stage = _run_installer(host, second, home)
    assert recovered_stage.returncode == 0, recovered_stage.stdout + recovered_stage.stderr
    second_target = f".ura-controller-generations/{second.generation_name}"
    assert _active_target(base) == second_target

    third = _build_package(base, "3" * 40, "three")
    stopped_before_switch = _run_installer(
        host, third, home, path=wrapped_path, interrupt="active-before"
    )
    assert stopped_before_switch.returncode != 0
    assert _active_target(base) == second_target
    assert (base / ".ura-controller-generations" / third.generation_name).is_dir()
    recovered_switch = _run_installer(host, third, home)
    assert recovered_switch.returncode == 0, recovered_switch.stdout + recovered_switch.stderr
    third_target = f".ura-controller-generations/{third.generation_name}"
    assert _active_target(base) == third_target

    fourth = _build_package(base, "4" * 40, "four")
    stopped_after_switch = _run_installer(
        host, fourth, home, path=wrapped_path, interrupt="active-after"
    )
    assert stopped_after_switch.returncode != 0
    fourth_target = f".ura-controller-generations/{fourth.generation_name}"
    assert _active_target(base) == fourth_target
    recovered_after_switch = _run_installer(host, fourth, home)
    assert recovered_after_switch.returncode == 0, (
        recovered_after_switch.stdout + recovered_after_switch.stderr
    )
    assert _active_target(base) == fourth_target


def test_verifier_rejects_generation_drift_before_external_campaign_checks(
    tmp_path: Path,
) -> None:
    host = _require_posix_installer_host(tmp_path)
    base = tmp_path / "controller-base"
    base.mkdir()
    home = _install_home(base)
    package = _build_package(base, "1" * 40, "one")
    installed = _run_installer(host, package, home)
    assert installed.returncode == 0, installed.stdout + installed.stderr

    generation = base / ".ura-controller-generations" / package.generation_name
    controller = generation / "phase5_core_projections.sh"
    generation.chmod(0o700)
    controller.chmod(0o600)
    controller.write_bytes(controller.read_bytes() + b"# generation drift\n")

    result = subprocess.run(
        [host.bash, str(package.verifier)],
        cwd=base,
        env={
            **os.environ,
            **host.environment,
            "HOME": _posix_path(home),
            "PATH": host.path,
        },
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode != 0
    assert "controller byte count differs" in result.stderr
