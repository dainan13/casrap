#!/usr/bin/env python3
"""
casrap command line tool
"""
__author__ = "xupengzhuo"
__version__ = "0.0.1"
__date__ = "2023/04/13"

import argparse
import logging
from logging.config import dictConfig
import sys
import os
import re
import shutil
import json
import datetime
import itertools
import subprocess
import textwrap
import uuid

#: The dictionary, passed to :class:`logging.config.dictConfig`,
#: is used to setup your logging formatters, handlers, and loggers
#: For details, see https://docs.python.org/3.4/library/logging.config.html#configuration-dictionary-schema
DEFAULT_LOGGING_DICT = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "standard": {"format": "[%(levelname)s] %(message)s"},
    },
    "handlers": {
        "default": {
            "level": "NOTSET",  # will be set later
            "formatter": "standard",
            "class": "logging.StreamHandler",
        },
    },
    "loggers": {
        __name__: {
            "handlers": ["default"],
            "level": "NOTSET",
            # 'propagate': True
        }
    },
}

SERVICES_CONF = "/usr/lib/casrap/services"
VASSALS_CONF = "/etc/uwsgi/conf.d"
VASSALS_LOG = "/var/log/uwsgi"

CURRENT_PATH = os.getcwd()
#: Map verbosity level (int) to log level
LOGLEVELS = {
    None: logging.WARNING,
    0: logging.ERROR,
    1: logging.WARNING,
    2: logging.INFO,
    3: logging.DEBUG,
}  # 0
#: Instantiate our logger
log = logging.getLogger(__name__)

#: Use best practice from Hitchhiker's Guide
#: see https://docs.python-guide.org/writing/logging/#logging-in-a-library
log.addHandler(logging.NullHandler())


def _avaliable_port():
    import socket

    s = socket.socket()
    s.bind(("", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def uwsgiconf():
    _app_name = input("input your service app name: ")
    if not all(map(str.isalpha, _app_name.split("_"))):
        cli_exit("illegal service app name")

    if not os.path.exists(os.path.join(CURRENT_PATH, f"{_app_name}.py")):
        cli_exit(f"{_app_name}.py not found in current directory")

    _grp_name = input("input your service group name: ")
    if not all(map(str.isalpha, _grp_name.split("_"))):
        cli_exit("illegal service group name")

    _p = _avaliable_port()
    _port = input(f"input your port number(press the enter key to use {_p})): ")

    if not _port:
        _port = _p
    else:
        if not _port.isdigit or int(_port) > 65535 or int(_port) < 1024:
            cli_exit("invaliid port number")

    if not os.path.exists(os.path.join(SERVICES_CONF, _grp_name)):
        os.mkdir(os.path.join(SERVICES_CONF, _grp_name))

    _cfg_file = os.path.join(SERVICES_CONF, _grp_name, f"{_app_name}.json")
    if os.path.exists(_cfg_file):
        cli_exit("already existed")

    with open(_cfg_file, "w") as fp:
        json.dump(
            {
                "uwsgi": {
                    "name": _app_name,
                    "http": f":{_port}",
                    "chdir": CURRENT_PATH,
                    "wsgi-file": os.path.join(CURRENT_PATH, f"{_app_name}.py"),
                },
            },
            fp,
            indent=4,
        )


def casrapconfig():
    _system_code = input("input your system code:")
    if not _system_code.isalnum():
        cli_exit("illegal input")

    with open("/etc/casrap/config.json", "w") as fp:
        json.dump(
            {
                "system": {
                    "code": _system_code,
                    "key": str(uuid.uuid4()),
                    "create_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "tracking": {},
                },
                "platform": {},
                "application": {},
                "role": {},
                "menu": {},
                "api": {},
                "apidebug": {},
                "service": {},
                "apimap": {},
            },
            fp,
            indent=4,
        )


def cli_exit(msg, code=-1):
    log.error(msg)
    exit(code)


class cmd:
    def __init__(self) -> None:
        if not os.path.exists(VASSALS_CONF):
            cli_exit("uWSGI has not been installed")

        if not os.path.exists(SERVICES_CONF):
            cli_exit("casrap has not been installed")

        self.running_services = [os.path.splitext(f)[0] for f in os.listdir(VASSALS_CONF)]
        # self.existed_services = [os.path.splitext(f)[0] for f in itertools.chain(*[files for _, _, files in os.walk(self.SERVICES_CONF)])]

        self.existed_services = {}
        self.grouped_services = {}
        for d in os.listdir(SERVICES_CONF):
            for f in os.listdir(os.path.join(SERVICES_CONF, d)):
                self.existed_services[os.path.splitext(f)[0]] = (d, os.path.join(SERVICES_CONF, d), f)

                if d in self.grouped_services:
                    self.grouped_services[d].append(os.path.splitext(f)[0])
                else:
                    self.grouped_services[d] = [os.path.splitext(f)[0]]

    def check(self, svc, g):
        if g:
            gs = []
            for g, s in self.grouped_services.items():
                if g in svc:
                    gs.extend(s)
            svc = gs
            if not svc:
                cli_exit("no service matched")
        else:
            if svc == ["all"]:
                svc = self.existed_services.keys()
            elif not set(svc).issubset(set(self.existed_services)):
                cli_exit("service not existed")
        return svc

    def do_list(self, group):
        g = [("GROUPS", "SERVICES", "RUNNING")]
        s = [("GROUPS", "SERVICE", "RUNNING")]

        for d in os.listdir(SERVICES_CONF):
            g_s_cnt = 0
            g_rs_cnt = 0
            for f in os.listdir(os.path.join(SERVICES_CONF, d)):
                f = os.path.splitext(f)[0]
                g_s_cnt += 1
                if f in self.running_services:
                    g_rs_cnt += 1
                    s.append((d, f, "true"))
                else:
                    s.append((d, f, "false"))
            g.append((d, g_s_cnt, g_rs_cnt))

        for r in g if group else s:
            print("\t".join(["{0: <24}".format(str(_r)) for _r in r]))

    def do_show(self, svc, group):
        svc = self.check(svc, group)

        for s in svc:
            with open(os.path.join(self.existed_services[s][1], self.existed_services[s][2])) as fp:
                print("-" * 32)
                print(fp.read())
                print("-" * 32)

    def do_up(self, svc, group):
        svc = self.check(svc, group)

        for s in svc:
            if s in self.running_services:
                continue

            svc_path = os.path.join(self.existed_services.get(s)[1], self.existed_services.get(s)[2])
            os.system(f"ln -s {svc_path} {os.path.join(VASSALS_CONF, os.path.basename(svc_path))}")

    def do_down(self, svc, group):
        svc = self.check(svc, group)

        for s in svc:
            if s not in self.running_services:
                continue
            svc_path = os.path.join(self.existed_services.get(s)[1], self.existed_services.get(s)[2])
            os.system(f"rm {os.path.join(VASSALS_CONF, os.path.basename(svc_path))}")

    def do_re(self, svc, group):
        svc = self.check(svc, group)

        for s in svc:
            if s not in self.running_services:
                continue
            svc_path = os.path.join(self.existed_services.get(s)[1], self.existed_services.get(s)[2])
            os.system(f"touch {os.path.join(VASSALS_CONF, os.path.basename(svc_path))}")

    def do_log(self, svc, group, follow):
        svc = self.check(svc, group)

        l = []
        for s in svc:
            l.append(os.path.join(VASSALS_LOG, f"{s}.log"))

        os.system(f"tail {'-f' if follow else ''} {' '.join(l)}")

    def do_gen(self, content):
        if content == "uwsgiconf":
            uwsgiconf()
        elif content == "casrapconf":
            casrapconfig()


class codes_cmd:
    pass


def parsecli(
    cliargs=None,
) -> argparse.Namespace:
    """Parse CLI with :class:`argparse.ArgumentParser` and return parsed result

    :param cliargs: Arguments to parse or None (=use sys.argv)
    :return: parsed CLI result
    """
    parser = argparse.ArgumentParser(description=__doc__, epilog="...")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity level")
    parser.add_argument("--version", action="version", version="%(prog)s " + __version__)
    subparsers = parser.add_subparsers(required=True, dest="command")
    cmd_list = subparsers.add_parser("list", help="list services", usage="cascli list <-g>")
    cmd_list.add_argument(
        "-g",
        "--group",
        help="by grouping view",
        default=False,
        dest="group",
        action="store_true",
    )

    cmd_show = subparsers.add_parser("show", help="show <svc>", usage="cascli show <svc>|<group>...")
    cmd_show.add_argument("svc", help="using `all` represent all services ", nargs="+")
    cmd_show.add_argument(
        "-g",
        "--group",
        help="apply to all services under a group",
        default=False,
        action="store_true",
    )

    cmd_up = subparsers.add_parser("up", help="up <svc>", usage="cascli up <svc>...")
    cmd_up.add_argument("svc", help="using `all` represent all services", nargs="+")
    cmd_up.add_argument(
        "-g",
        "--group",
        help="apply to all services under a group",
        default=False,
        action="store_true",
    )

    cmd_down = subparsers.add_parser("down", help="down <svc>", usage="cascli down <svc>...")
    cmd_down.add_argument("svc", help="using `all` represent all services", nargs="+")
    cmd_down.add_argument(
        "-g",
        "--group",
        help="apply to all services under a group",
        default=False,
        action="store_true",
    )

    cmd_re = subparsers.add_parser("re", help="re <svc>", usage="cascli re <svc>...")
    cmd_re.add_argument("svc", help="using `all` represent all services", nargs="+")
    cmd_re.add_argument(
        "-g",
        "--group",
        help="apply to all services under a group",
        default=False,
        action="store_true",
    )

    cmd_log = subparsers.add_parser("log", help="log <svc>", usage="cascli log <svc>...")
    cmd_log.add_argument("svc", help="using `all` represent all services", nargs="+")
    cmd_log.add_argument(
        "-g",
        "--group",
        help="apply to all services under a group",
        default=False,
        action="store_true",
    )
    cmd_log.add_argument(
        "-f",
        "--follow",
        help="follow or not",
        default=False,
        dest="follow",
        action="store_true",
    )

    cmd_dbg = subparsers.add_parser("dbg", help="dbg <svc>", usage="cascli dbg <svc>...")
    cmd_dbg.add_argument("svc", help="using `all` represent all services", nargs="+")

    cmd_gen = subparsers.add_parser("gen", help="gen <content> ...", usage="cascli gen <content>...")
    cmd_gen.add_argument("content", help="the content you want", choices=["uwsgiconf", "casrapconf"])

    args = parser.parse_args(args=cliargs)
    return args


def proc(args):
    c = cmd()
    log.debug(args)
    match args.command:
        case "list":
            c.do_list(args.group)
        case "show":
            c.do_show(args.svc, args.group)
        case "new":
            c.do_new()
        ######################
        case "up":
            c.do_up(args.svc, args.group)
        case "down":
            c.do_down(args.svc, args.group)
        case "re":
            c.do_re(args.svc, args.group)
        case "log":
            c.do_log(args.svc, args.group, args.follow)
        case "dbg":
            c.do_re(args.svc, False)
            c.do_log(args.svc, False, True)
        case "gen":
            c.do_gen(args.content)
        case _:
            pass


def main(cliargs=None) -> int:
    dictConfig(DEFAULT_LOGGING_DICT)

    try:
        args = parsecli(cliargs)
        log.setLevel(LOGLEVELS.get(args.verbose, logging.INFO))

        proc(args)
        log.debug("CLI result: %s", args)
        return 0

    # List possible exceptions here and return error codes
    except Exception as error:  # FIXME: add a more specific exception here!
        log.fatal(error)
        # raise
        # Use whatever return code is appropriate for your specific exception
        return 10


if __name__ == "__main__":
    sys.exit(main())
