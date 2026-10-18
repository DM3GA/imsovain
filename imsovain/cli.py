"""Command line for the vanity key generator."""

from __future__ import annotations

import os
import sys
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

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
    default=250,
    show_default=True,
    help="How far before now the creation time may move, in days.",
)
@click.option(
    "--leading",
    "-l",
    type=click.IntRange(1, 8),
    default=6,
    show_default=True,
    help="Repeat filter only: identical doubled-nibble bytes at the start of the key id.",
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
    leading: int,
    filter_name: str,
    uid: str,
    exit_after_found: bool,
    opencl: bool,
) -> None:
    """Search creation timestamps until an Ed25519 fingerprint matches."""
    user_id_bytes(uid)
    try:
        filt = parse_filter(filter_name, leading)
    except ValueError as exc:
        raise click.BadParameter(str(exc), param_hint="--filter") from exc
    outdir = os.path.abspath(outdir)
    os.makedirs(outdir, exist_ok=True)
    max_iter = window_seconds(max_time_days)
    if opencl:
        from imsovain.accel_proc import opencl_device

        try:
            device = opencl_device()
        except RuntimeError as exc:
            raise click.ClickException(str(exc)) from exc
        print(f"opencl {device}", flush=True)
    print(f"filter {describe(filt)}", flush=True)
    worker_args = (outdir, uid, max_iter, filt, opencl)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        pending = set()
        try:
            while True:
                while len(pending) < threads:
                    pending.add(pool.submit(attempt_key, *worker_args))
                finished, pending = wait(pending, timeout=0.05, return_when=FIRST_COMPLETED)
                found = False
                for job in finished:
                    result = job.result()
                    _report(result)
                    if result.fingerprint:
                        found = True
                if found and exit_after_found:
                    return
        except KeyboardInterrupt:
            print("stopped", file=sys.stderr)
            sys.exit(130)
