from app import CommandSpec

CommandSpec(name="/resume", handler="resume_command", remote_invocable=True)


def session_key(platform, chat, thread, sender):
    return f"{platform}:{chat}:{thread}:{sender}"


def resume_command(backend, session_id):
    return backend.load_by_id(session_id)
