import asyncio
import sys

from .cli import parse_args, run


def main(argv=None):
    args = parse_args(argv)
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        sys.stdout.write(
            "\nStopped by user. Browser profile and captured data are preserved.\n"
        )
        sys.stdout.flush()


if __name__ == "__main__":
    main()