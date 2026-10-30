import asyncio

import asyncssh


async def main():
    await asyncssh.listen("", 22, server_host_keys=["ssh_host_ed25519_key"])
    await asyncio.Event().wait()


asyncio.run(main())
