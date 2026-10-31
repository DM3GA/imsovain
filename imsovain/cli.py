"""Command line for the vanity key generator."""

from __future__ import annotations

import os
import sys
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, as_completed, wait

import click

from imsovain.engine import attempt_key, window_seconds
from imsovain.packets import user_id_bytes
from imsovain.pattern import describe, parse_filter


def _report(result) -> None:
    rate = result.checked / result.seconds if result.seconds else 0.0
    print(
        f"checked {result.checked} SHA-1 digests in {result.seconds:.2f}s ({rate:.0f}/s)",
        flush=True,
    )
    if result.fingerprint:
        print(f"found {result.fingerprint} created {result.created} -> {result.path}", flush=True)


@click.command()
@click.option(
    "--threads",
    "-t",
    type=click.IntRange(1, None),
    default=os.cpu_count() or 1,
    show_default=True,
    help="Parallel key attempts.",
)
@click.option(
    "--outdir",
    "-o",
    type=click.Path(file_okay=False),
    required=True,
    help="Directory for unencrypted secret keys.",
)
@click.option(
    "--max-time-days",
    "-m",
    type=click.IntRange(1, None),
    default=365,
    show_default=True,
    help="How far before now the creation time may move, in days.",
)
@click.option(
    "--leading",
    "-l",
    type=click.IntRange(1, 8),
    default=None,
    help="Repeat filter only: how many identical doubled-nibble bytes the key id must open with. Required for repeat.",
)
@click.option(
    "--filter",
    "-f",
    "filter_name",
    default="repeat",
    show_default=True,
    help=(
        "Key-id filter. repeat uses --leading. run, word, speak, and short are "
        "memorable prefixes (00112233, DEADBEEF, C0FFEE, C0DE, and their kin). "
        "A hex string such as C0DE or 0x00112233 is one exact prefix."
    ),
)
@click.option(
    "--uid",
    "-u",
    type=str,
    required=True,
    help="User id bound to every key, for example 'Name <name@example.com>'.",
)
@click.option(
    "--exit-after-found",
    "-x",
    is_flag=True,
    help="Stop after writing one matching key.",
)
@click.option(
    "--opencl",
    is_flag=True,
    help="Hash creation times on an OpenCL GPU. Without this flag, every search stays on the CPU.",
)
def main(
    threads: int,
    outdir: str,
    max_time_days: int,
    leading: int | None,
    filter_name: str,
    uid: str,
    exit_after_found: bool,
    opencl: bool,
) -> None:
    """Search creation timestamps until an Ed25519 fingerprint matches."""
    try:
        user_id_bytes(uid)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--uid") from exc
    try:
        filt = parse_filter(filter_name, leading)
    except ValueError as exc:
        hint = "--leading" if "leading" in str(exc) else "--filter"
        raise click.BadParameter(str(exc), param_hint=hint) from exc
    try:
        max_iter = window_seconds(max_time_days)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--max-time-days") from exc
    if opencl:
        from imsovain.accel_proc import opencl_device

        try:
            device = opencl_device()
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc
        print(f"opencl {device}", flush=True)
    outdir = os.path.abspath(outdir)
    # The keys are unencrypted. A new directory is private to its owner.
    os.makedirs(outdir, mode=0o700, exist_ok=True)
    print(f"filter {describe(filt)}", flush=True)
    worker_args = (outdir, uid, max_iter, filt, opencl)

    interrupted = False
    with ThreadPoolExecutor(max_workers=threads) as pool:
        pending = set()
        try:
            while True:
                while len(pending) < threads:
                    pending.add(pool.submit(attempt_key, *worker_args))
                finished, pending = wait(pending, return_when=FIRST_COMPLETED)
                results = [job.result() for job in finished]
                for result in results:
                    _report(result)
                if exit_after_found and any(result.fingerprint for result in results):
                    break
        except KeyboardInterrupt:
            interrupted = True
            print("stopping once the running searches finish", file=sys.stderr, flush=True)
        # A scan cannot be cancelled once it runs, and one that is still
        # running may write a key. Report those keys too.
        try:
            for job in as_completed(pending):
                _report(job.result())
        except KeyboardInterrupt:
            interrupted = True
    if interrupted:
        print("stopped", file=sys.stderr)
        sys.exit(130)
