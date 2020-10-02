import sys
from webssh._version import __version__, __version_info__


__author__ = 'Shengdun Hua <webmaster0115@gmail.com>'

if sys.platform == 'win32' and sys.version_info.major == 3 and \
        sys.version_info.minor >= 8:
    import asyncio
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
