import asyncio
import signal

import asyncssh


async def main():
    await asyncssh.listen("", 22, server_host_keys=["ssh_host_ed25519_key"])
    stop = asyncio.Event()
    asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, stop.set)
    await stop.wait()


asyncio.run(main())
