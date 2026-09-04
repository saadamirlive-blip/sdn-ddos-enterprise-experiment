import eventlet.wsgi

if not hasattr(eventlet.wsgi, "ALREADY_HANDLED"):
    eventlet.wsgi.ALREADY_HANDLED = object()

from ryu.cmd.manager import main


if __name__ == "__main__":
    main()
