"""Desktop notification when the agent finishes an investigation.

macOS only. Three layers, best-effort, never fatal:

1. a banner (``display notification``) — always fires, non-blocking
2. a sound (``afplay``) — makes the completion noticeable without looking
3. a clickable dialog — the analyst clicks "Open Report" and the Markdown
   report opens in the default application

The dialog is launched in a detached process so the agent's watch loop is
never blocked by the analyst taking their time to dismiss it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

SOUND_CANDIDATES = (
    "/System/Library/Sounds/Glass.aiff",
    "/System/Library/Sounds/Ping.aiff",
    "/System/Library/Sounds/Basso.aiff",
)


def _applescript_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _run_detached(script: str) -> None:
    """Run an AppleScript in a detached process so it cannot block the agent."""
    try:
        handle = tempfile.NamedTemporaryFile(
            "w", suffix=".applescript", delete=False, encoding="utf-8"
        )
        with handle as fh:
            fh.write(script)
        path = handle.name
        subprocess.Popen(
            ["osascript", path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        pass


def notify_banner(title: str, message: str) -> bool:
    """Show a non-blocking macOS notification banner."""
    if not shutil.which("osascript"):
        return False
    script = (
        f'display notification "{_applescript_escape(message)}" '
        f'with title "{_applescript_escape(title)}" subtitle "Agentic SOC"'
    )
    try:
        result = subprocess.run(
            ["osascript", "-e", script],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=15,
        )
        return result.returncode == 0
    except Exception:
        return False


def notify_sound() -> bool:
    """Play the completion sound."""
    if not shutil.which("afplay"):
        return False
    for candidate in SOUND_CANDIDATES:
        if os.path.exists(candidate):
            try:
                subprocess.Popen(
                    ["afplay", candidate],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                return True
            except Exception:
                return False
    return False


def build_clickable_script(
    title: str,
    message: str,
    report_path: Optional[Path],
    reveal_label: str = "Reveal in Finder",
    html_path: Optional[Path] = None,
) -> str:
    """Build the AppleScript for the clickable report dialog.

    Kept separate from the launch so it can be syntax-checked in tests.
    "Open Report" prefers ``html_path`` (browser-friendly) when supplied.
    """
    path = str(report_path) if report_path else ""
    open_path = str(html_path) if html_path else path
    if path:
        buttons = f'{{"Open Report", "{reveal_label}"}}'
        default_button = '"Open Report"'
        # NOTE: every embedded quote must be escaped, including the ones in
        # the instruction text, or the AppleScript string literal breaks.
        body = "\n\n".join([
            _applescript_escape(message),
            _applescript_escape(path),
            _applescript_escape(
                f'Click "Open Report" to view it, or "{reveal_label}" to locate it.'
            ),
        ])
        action = (
            'if button returned of r is "Open Report" then\n'
            f'  do shell script "open " & quoted form of openPath\n'
            "else\n"
            f'  do shell script "open -R " & quoted form of reportPath\n'
            "end if"
        )
    else:
        buttons = '{"OK"}'
        default_button = '"OK"'
        body = _applescript_escape(message)
        action = ""

    return f'''
set reportPath to "{_applescript_escape(path)}"
set openPath to "{_applescript_escape(open_path)}"
try
    set r to display dialog "{body}" buttons {buttons} default button {default_button} with title "{_applescript_escape(title)}" with icon note
    {action}
on error errMsg
    log errMsg
end try
    '''


def notify_clickable(
    title: str,
    message: str,
    report_path: Optional[Path],
    reveal_label: str = "Reveal in Finder",
    html_path: Optional[Path] = None,
) -> bool:
    """Show a dialog whose buttons open (or reveal) the generated report.

    ``html_path`` (when present) is what "Open Report" launches, because the
    HTML report opens in the browser and reads well on screen; the Markdown
    report is still the primary artifact for git and for reviewers.
    """
    if not shutil.which("osascript"):
        return False
    _run_detached(
        build_clickable_script(title, message, report_path, reveal_label, html_path)
    )
    return True


def notify_report_ready(
    title: str,
    message: str,
    report_path: Optional[Path],
    sound: bool = True,
    clickable: bool = True,
    html_path: Optional[Path] = None,
) -> None:
    """Full completion notification: banner + optional sound + optional dialog."""
    notify_banner(title, message)
    if sound:
        notify_sound()
    if clickable and report_path:
        notify_clickable(title, message, Path(report_path), html_path=html_path)


def notify_failure(title: str, message: str) -> None:
    notify_banner(title, message)
