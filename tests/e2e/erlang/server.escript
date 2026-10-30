#!/usr/bin/env escript

main(_) ->
    {ok, _} = application:ensure_all_started(ssh),
    {ok, _} = ssh:daemon(22, [
        {system_dir, "/etc/ssh-erlang"},
        {pwdfun, fun(_, _) -> false end}
    ]),
    receive after infinity -> ok end.
