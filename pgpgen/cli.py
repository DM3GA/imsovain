"""Command line for the vanity key generator."""

from __future__ import annotations

import multiprocessing as mp
import os
import sys
import time

import click

from pgpgen.engine import attempt_key, window_seconds
from pgpgen.packets import user_id_bytes


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
    help="Key id must open with this many identical doubled-nibble bytes.",
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
    "--accelerate-with",
    "-a",
    type=click.Path(exists=True, dir_okay=False),
    required=True,
    help="OpenSSL search program.",
)
def main(
    threads: int,
    outdir: str,
    max_time_days: int,
    leading: int,
    uid: str,
    exit_after_found: bool,
    accelerate_with: str,
) -> None:
    """Search creation timestamps until an Ed25519 fingerprint matches."""
    user_id_bytes(uid)
    outdir = os.path.abspath(outdir)
    os.makedirs(outdir, exist_ok=True)
    max_iter = window_seconds(max_time_days)
    binary = os.path.abspath(accelerate_with)
    worker_args = (binary, outdir, uid, max_iter, leading)

    context = mp.get_context("fork")
    with context.Pool(threads) as pool:
        pending: list = []
        try:
            while True:
                while len(pending) < threads:
                    pending.append(pool.apply_async(attempt_key, worker_args))
                still = []
                found = False
                for job in pending:
                    if not job.ready():
                        still.append(job)
                        continue
                    result = job.get()
                    _report(result)
                    if result.fingerprint:
                        found = True
                pending = still
                if found and exit_after_found:
                    pool.terminate()
                    return
                if pending:
                    time.sleep(0.05)
        except KeyboardInterrupt:
            pool.terminate()
            print("stopped", file=sys.stderr)
            sys.exit(130)
