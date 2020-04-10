# -*- coding: utf-8 -*-
"""
DNUTS
=====
Distributed network utilities tests

Thinks to do:
1. Add source information to all tests results
"""
from __future__ import absolute_import

# Import python libs
import logging
import sys, traceback
import datetime  # needit for timestamp in iso format
import time  # needit to calculate elapsed time for each check
from platform import system

# Import third party modules
try:
    import requests
    from threading import Thread

    HAS_LIBS = True
except ImportError:
    HAS_LIBS = False
    log.error("Failed to import requests module, make usre it is installed")
log = logging.getLogger(__name__)

__virtualname__ = "dnuts"
__proxyenabled__ = ["*"]


def __virtual__():
    """
    Only load this execution module if all libraries installed.
    """
    if HAS_LIBS:
        return __virtualname__
    return (False, " DNUTS failed to impoert all libraries.")


def _get_time():
    """
    Helper function to get current time
    """
    if "LINUX" in system().upper():
        return time.time()
    elif "WINDOWS" in system().upper():
        return time.clock()


def _run_threads(job_threads, max, timeout):
    running_threads = []
    for thread in job_threads:
        while True:
            if _checkThreads(running_threads, max=max) == True:
                thread.start()
                running_threads.append(thread)
                break
    # join remaining threads:
    [thread.join(timeout=timeout * 3) for thread in running_threads]


def _checkThreads(running_threads, max=10):
    running = 0
    for thread in running_threads:
        if thread.isAlive():
            running += 1
        else:
            running -= 1
            running_threads.remove(thread)
    if running < max:
        return True
    return False


def _get_timestamp():
    class UTC(datetime.tzinfo):
        def utcoffset(self, dt):
            return datetime.timedelta(0)

        def tzname(self, dt):
            return "UTC"

        def dst(self, dt):
            return datetime.timedelta(0)

    utc = UTC()
    timestamp = datetime.datetime.now(utc).isoformat()
    return timestamp


def _send_alert(check_type, target, data):
    tag = "dnuts/{check_type}/check/alert/{target}".format(check_type=check_type, target=target)
    __salt__["event.send"](tag=tag, data=data)


def _get_kwargs(**kwargs):
    ret = {
        "ret": {"out": [], "result": True},
        "source": kwargs.get("__pub_tgt", ""),  # get minion id
        "timeout": kwargs.get("timeout", 1),  # 1s
        "threads": kwargs.get("threads", 10),
        "timestamp": kwargs.get("timestamp", _get_timestamp()),
        "group": kwargs.get("group", ""),
        "alert": kwargs.get("alert", False),
        "checks": kwargs.get("checks", 1),  # one check per target
        "interval": kwargs.get("interval", 0.01),  # 10ms interval between checks
    }
    return ret


def _calculate_stats(check_result):
    """
    Helper function to calculate
     - average, min and max rtt
     - success and loss scores
     - jitter
    """
    # add rtt and jitter
    check_result["rtt_min"] = 0.0
    check_result["rtt_max"] = 0.0
    check_result["jitter"] = 0.0
    if check_result["success"] != 0:
        check_result["rtt_min"] = round(min(check_result["rtt"]), 6)
        check_result["rtt_max"] = round(max(check_result["rtt"]), 6)
        diffs = []
        for i in range(0, len(check_result["rtt"]), 2):
            try:
                diffs.append(abs(check_result["rtt"][i + 1] - check_result["rtt"][i]))
            except IndexError:
                break
        if diffs:
            check_result["jitter"] = round(sum(diffs) / len(diffs), 6)
        check_result["rtt"] = round(sum(check_result["rtt"]) / len(check_result["rtt"]), 6)
    # calculate success and loss percentages
    check_result["success"] = (check_result["success"] / check_result["checks"]) * 100
    check_result["loss"] = 100 - check_result["success"]
    return check_result


def http(*args, **kwargs):
    import requests

    """
    Function to test http/https connectivity using requests module
    by sending GET requests to provided URLs.
    
    kwargs timeout
        Seconds to wait to establish connection and get response, default 1 second
    kwargs verify
        Boolean to disable SSL certificate verification, default true
        
    Returns::
        {
            "minion": {
                "result": true, 
                "out": {
                    "http://gith1ubb.com": {
                        "comment": "ERROR, connection timeout. Timeout interval 1s.",
                        "status_code": -1, 
                        "success": false,
                        "rtt": 0
                    }, 
                    "timestamp": "Tue Nov 23 13:23:50 2019", 
                    "http://google.com": {
                        "comment":  "",
                        "status_code": 200, 
                        "success": true,
                        "rtt": 0.01543
                    }, 
                    "timestamp_ns": 15741896487830.438646
                }
            }
        }

    CLI Example:
    .. code-block:: bash
        salt "*" dnuts.http https://google.com
        salt "*" dnuts.http https://google.com http://github.com
        salt "*" dnuts.http https://google.com http://github.com timeout=10 verify=False
    """

    def run_http_check_thread(
        url, ret, timeout, source, timestamp, group, alert, checks, interval, **kwargs
    ):
        check_result = {
            "status_code": 0,
            "success": 0,
            "rtt": [],
            "comment": "",
            "target": url,
            "checks": checks,
            "check_type": "HTTP",
            "source": source,
            "@timestamp": timestamp,
            "group": group,
        }
        # run checks
        for i in range(0, checks):
            try:
                response = requests.get(url, timeout=timeout)
                if response.status_code == 200:
                    check_result["success"] += 1
                check_result["status_code"] = response.status_code
                check_result["rtt"].append(response.elapsed.total_seconds())
            except requests.exceptions.Timeout:
                check_result["comment"] = "ERROR, connection timeout. Timeout {}s.".format(timeout)
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                check_result["comment"] = "Unhandled requests error, url: {}\n\n{}".format(
                    url, "".join(traceback.format_exception(exc_type, exc_value, exc_traceback)),
                )
            time.sleep(interval)
        # add check stats
        check_result = _calculate_stats(check_result)
        # sent alert if requested to do so
        if check_result["success"] == 0 and alert is True:
            _send_alert(check_type="HTTP", target=url, data=check_result)
        # save thread run results
        ret["out"].append(check_result)

    # initialize variables
    check_kwargs = _get_kwargs(**kwargs)
    # create threads objects
    job_threads = [
        Thread(target=run_http_check_thread, kwargs=dict(url=url, **check_kwargs),) for url in args
    ]
    # run threads
    log.info(
        "Running {len} HTTP connection checks in {threads} threads, {checks} check(s) per target, with {interval}s interval and {timeout}s timeout".format(
            len=len(job_threads), **check_kwargs
        )
    )
    _run_threads(
        job_threads,
        max=check_kwargs["threads"],
        timeout=check_kwargs["timeout"] * 2 * check_kwargs["checks"],
    )
    log.info("Checks completed")

    return check_kwargs["ret"]


def tcp(*targets, **kwargs):
    """
    Function to run TCP connection checks to provided targets
    
    :param targets: List of tuples (address, port) to run testing against
    :param timeout: Seconds to timeout connection after
    :param count: Number of connection tests to do
    :param threads: Maximum number of threads to run
    :param interval: interval in seconds to wait between checks
    
    :return: A dictionary of results
    
    CLI Example:
    .. code-block:: bash
    
        salt "*"
        
    Output Example:
    .. code-block:: python
    
        sampleoutputhere
    
    """
    import socket

    def run_tcp_check_thread(
        target, ret, checks, interval, timeout, source, timestamp, group, alert, **kwargs
    ):
        target_id = "{}:{}".format(target[0], target[1])
        check_result = {
            "success": 0,
            "checks": checks,
            "rtt": [],
            "comment": "",
            "check_type": "TCP",
            "source": source,
            "target": target_id,
            "@timestamp": timestamp,
            "group": group,
        }
        # try to resolve target name to IP:
        try:
            target_address = socket.gethostbyname(target[0])
        except socket.gaierror:
            check_result[
                "comment"
            ] += "ERROR, TCP connection check, DNS resolution failed for target - {}".format(target)
            ret["out"].append(check_result)
            return
        # run checks
        for i in range(0, checks):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                t1 = _get_time()
                s.connect((target_address, target[1]))
                check_result["rtt"].append(_get_time() - t1)
                check_result["success"] += 1
                s.close()
            except socket.timeout:
                check_result[
                    "comment"
                ] += "Check {}, ERROR, socket connection timeout after {}s, target - {}, address - {}\n".format(
                    i, timeout, target, target_address
                )
            except ValueError:
                check_result[
                    "comment"
                ] += "Check {}, ERROR, wrong target format - {}, should be 'target:port'\n".format(
                    i, ":".join(target)
                )
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                check_result[
                    "comment"
                ] += "Check {}, ERROR: Unhandled socket error, target - {}\n\n{}\n".format(
                    i, target, "".join(traceback.format_exception(exc_type, exc_value, exc_traceback)),
                )
            time.sleep(interval)
        # add check stats
        check_result = _calculate_stats(check_result)
        # sent alert if requested to do so
        if check_result["success"] == 0 and alert is True:
            _send_alert(check_type="TCP", target=target_id, data=check_result)
        # save thread run results
        ret["out"].append(check_result)

    # initialize variables
    check_kwargs = _get_kwargs(**kwargs)
    job_threads = []
    # create threads objects
    for target in targets:
        target = target.strip()
        # check port 80 by default
        if not ":" in target:
            target = (
                target,
                80,
            )
        # transform target string in tuple of (address, port,)
        else:
            target_port = target.split(":")[-1]
            target_without_port = target.rstrip(":" + target_port)
            target = (
                target_without_port,
                int(target_port),
            )
        job_threads.append(
            Thread(target=run_tcp_check_thread, kwargs=dict(target=target, **check_kwargs),)
        )
    # run threads
    log.info(
        "Running {len} TCP connection checks in {threads} threads, {checks} check(s) per target, with {interval}s interval and {timeout}s timeout".format(
            len=len(job_threads), **check_kwargs
        )
    )
    _run_threads(
        job_threads,
        max=check_kwargs["threads"],
        timeout=check_kwargs["timeout"] * 2 * check_kwargs["checks"],
    )
    log.info("Checks completed")

    return check_kwargs["ret"]


def ping(*targets, **kwargs):
    """
    Function to run ICMP checks to provided targets. 
    
    **Prerequisities**
    Python scapy library and tcpdump (required by scapy) need to be installed on the minion.
    
    :param targets: List of targets to run testing against
    :param timeout: Seconds to wait for ICMP reply after
    :param checks: Number of checks to do
    :param threads: Maximum number of threads to run
    :param interval: interval in seconds between checks
    
    :return: A dictionary of results
    
    CLI Example:
    .. code-block:: bash
    
        salt "*"
        
    Output Example:
    .. code-block:: python
    
        sampleoutputhere
    
    """
    from scapy.sendrecv import srp
    from scapy.layers.all import Ether, IP, ICMP
    import socket  # need sockets for DNS resolution

    def run_ping_checks_scapy(
        target, ret, checks, interval, timeout, source, timestamp, group, alert, **kwargs
    ):
        check_result = {
            "success": 0,
            "checks": checks,
            "rtt": [],
            "comment": "",
            "target": target,
            "check_type": "PING",
            "source": source,  # add minion id
            "@timestamp": timestamp,
            "group": group,
        }
        # try to resolve target name to IP:
        try:
            target_address = socket.gethostbyname(target)
        except socket.gaierror:
            check_result[
                "comment"
            ] += "ERROR, PING connection check, DNS resolution failed for target - {}".format(target)
            ret["out"].append(check_result)
            return
        # do ICMP checks
        for i in range(checks):
            try:
                packet = Ether() / IP(dst=target_address) / ICMP()
                ans, unans = srp(packet, filter="icmp", verbose=0, timeout=timeout)
                if len(ans) != 0:
                    rx = ans[0][1]
                    tx = ans[0][0]
                    check_result["rtt"].append(abs(rx.time - tx.sent_time))
                    check_result["success"] += 1
                elif len(unans) != 0:
                    check_result[
                        "comment"
                    ] += "Check {}, ERROR, no ICMP reply, timeout - {}s, target - {}, address - {}\n".format(
                        i, timeout, target, target_address
                    )
            except:
                exc_type, exc_value, exc_traceback = sys.exc_info()
                check_result[
                    "comment"
                ] += "Check {}, ERROR: Unhandled scapy error, target - {}, target_address - {}\n\n{}\n".format(
                    i,
                    target,
                    target_address,
                    "".join(traceback.format_exception(exc_type, exc_value, exc_traceback)),
                )
            time.sleep(interval)
        # add check stats
        check_result = _calculate_stats(check_result)
        # sent alert on failure if requested to do so
        if check_result["success"] == 0 and alert is True:
            _send_alert(check_type="PING", target=target, data=check_result)
        # save thread run results
        ret["out"].append(check_result)

    # initialize variables
    check_kwargs = _get_kwargs(**kwargs)
    # create threads objects
    job_threads = [
        Thread(target=run_ping_checks_scapy, kwargs=dict(target=target.strip(), **check_kwargs),)
        for target in targets
    ]
    # run threads
    log.info(
        "Running {len} ICMP connection checks in {threads} threads, {checks} check(s) per target, with {interval}s interval and {timeout}s timeout".format(
            len=len(job_threads), **check_kwargs
        )
    )
    _run_threads(
        job_threads,
        max=check_kwargs["threads"],
        timeout=check_kwargs["timeout"] * 2 * check_kwargs["checks"],
    )
    log.info("PING Checks completed")

    return check_kwargs["ret"]


def ccmd(*targets, **kwargs):
    """
    Concurrent Commands to Multiple Destinations checks, allows to runany unix shell command
    against given target and return success/failure status code
    
    :param targets: List of target dictionaries to run testing against
    :param timeout: Seconds to wait for check thread to complete, multiplied by 3
    :param checks: Number of checks to do
    :param threads: Maximum number of threads to run
    :param interval: interval in seconds between checks
    
    Each targetin targets list should be a dictionary of below format:

    .. code-block:: bash
        
        {
            target: 8.8.8.8   
            description: "google dns ping"
            command: "ping -c 1 {target}" 
        }
        
    Example::
    
        salt minion_1 dnuts.ccmd '{target: 8.8.8.8, command: "ping -c 1 -W 1 {target}"}' '{target: "bbc.com", command: "ping -c 1 -W 1 {target}"}'
        
    Returns::
    
        minion_1:
            ----------
            out:
                |_
                  ----------
                  @timestamp:
                      2020-04-06T09:35:17.549247+00:00
                  check_type:
                      CCMD
                  checks:
                      1
                  command:
                      ping -c 1 -W 1 8.8.8.8
                  comment:
                  description:
                  group:
                  source:
                  success:
                      100
                  target:
                      8.8.8.8
                |_
                  ----------
                  @timestamp:
                      2020-04-06T09:35:17.549247+00:00
                  check_type:
                      CCMD
                  checks:
                      1
                  command:
                      ping -c 1 -W 1 bbc.com
                  comment:
                  description:
                  group:
                  source:
                  success:
                      100
                  target:
                      bbc.com
            result:
                True        
    """
    import subprocess

    def run_ccmd_checks(
        target, ret, checks, interval, source, timestamp, group, command, description, alert, **kwargs
    ):
        command = command.format(target=target)
        check_result = {
            "success": 0,
            "checks": checks,
            "comment": "",
            "target": target,
            "check_type": "CCMD",
            "rtt": 0.0,
            "source": source,
            "@timestamp": timestamp,
            "group": group,
            "description": description,
            "command": command,
        }
        command = [i.strip() for i in command.split(" ") if i.strip()]
        # do CCMD checks
        for i in range(checks):
            try:
                result = subprocess.check_output(command, stderr=subprocess.STDOUT)
                result = result.decode(encoding="utf-8")
                if (
                    "Destination net unreachable" in result
                    or "TTL expired in transit" in result
                    or "Destination host unreachable" in result
                ):
                    continue
                else:
                    check_result["success"] += 1
            except:
                check_result[
                    "comment"
                ] += "CCMD Check {}, ERROR in subprocess, command '{}' failed or returned non zero status code\n".format(
                    i, str(command)
                )
            time.sleep(interval)
        # calculate success and loss percentages
        check_result["success"] = (check_result["success"] / checks) * 100
        check_result["loss"] = 100 - check_result["success"]
        # sent alert if requested to do so
        if check_result["success"] == 0 and alert is True:
            _send_alert(check_type="CCMD", target=target, data=check_result)
        # save thread run results
        ret["out"].append(check_result)

    # initialize variables
    check_kwargs = _get_kwargs(**kwargs)
    # create threads objects
    job_threads = []
    for target_dict in targets:
        if not target_dict.get("command") or not target_dict.get("target"):
            log.error(
                "dnuts.ccmd: no 'command' or 'target' argument found for target - {}".format(target)
            )
            continue
        job_threads.append(
            Thread(
                target=run_ccmd_checks,
                kwargs=dict(
                    target=target_dict["target"].strip(),
                    command=target_dict["command"].strip(),
                    description=target_dict.get("description", "").strip(),
                    **check_kwargs
                ),
            )
        )
    # run threads
    log.info(
        "Running {len} CCMD connection checks in {threads} threads, {checks} check(s) per target, with {interval}s interval and {timeout}s timeout".format(
            len=len(job_threads), **check_kwargs
        )
    )
    _run_threads(
        job_threads,
        max=check_kwargs["threads"],
        timeout=check_kwargs["timeout"] * 2 * check_kwargs["checks"],
    )
    log.info("CCMD Checks completed")

    return check_kwargs["ret"]


def multicheck(*args, **kwargs):
    """
    Function to run checks agains targets.
    
    :param targets: dictionary with targets lists, each target dictionary must have "targets" list
        and "check_type" defined, in addition to that additional kwargs can be specified.
    :param returner_name: Supported returners - "elasticsearch", if specified, will return each check item 
        result to elasticsearch as a separate document to store within salt-dnut_multicheck-v1 index
        or using index name supplied. 
    :param index: string, default - salt-dnut_multicheck-v1, name of index to store data in elasticsearch
        when using elasticsearch returner
             
    Sample targets dictionary:
    .. code-block:: python
    
       {
        "returner_name": "elasticsearch",
        "internet_checks": [
                {
                    "targets": ["bbc.com"],
                    "check_type": "PING",
                    "checks": 5,
                    "threads": 10,
                    "alert": True
                },
                {
                    "targets": ["bbc.com", "google.com:443"],
                    "check_type": "TCP",
                    "checks": 10,
                    "threads": 5
                },
                {
                    "targets": ["http://bbc.com", "http://google.com"],
                    "check_type": "HTTP"
                }
            ]
        }
        
    :return: A list of dictionaries of test results

    .. code-block:: python
    
        {'out': [{'@timestamp': '2020-04-01T07:13:41.491000+00:00',
                  'check_type': 'PING',
                  'checks': 5,
                  'comment': '',
                  'group': 'internet_checks',
                  'source': '',
                  'success': 100,
                  'target': 'bbc.com',
                  'rtt': 0.001978},
                 {'@timestamp': '2020-04-01T07:13:41.491000+00:00',
                  'check_type': 'TCP',
                  'checks': 10,
                  'comment': '',
                  'group': 'internet_checks',
                  'source': '',
                  'success': 100,
                  'target': ('bbc.com', 80),
                  'rtt': 0.001454},
                 {'@timestamp': '2020-04-01T07:13:41.491000+00:00',
                  'check_type': 'TCP',
                  'checks': 10,
                  'comment': '',
                  'group': 'internet_checks',
                  'source': '',
                  'success': 100,
                  'target': ('google.com', 443),
                  'rtt': 0.001391},
                 {'@timestamp': '2020-04-01T07:13:41.491000+00:00',
                  'check_type': 'HTTP',
                  'comment': '',
                  'group': 'internet_checks',
                  'source': '',
                  'status_code': 200,
                  'success': True,
                  'target': 'http://google.com',
                  'rtt': 0.175887},
                 {'@timestamp': '2020-04-01T07:13:41.491000+00:00',
                  'check_type': 'HTTP',
                  'comment': '',
                  'group': 'internet_checks',
                  'source': '',
                  'status_code': 200,
                  'success': True,
                  'target': 'http://bbc.com',
                  'rtt': 0.343796}],
         'result': True}
        
    """
    ret = {"out": [], "result": True}
    # form shared data for check functions
    timestamp = _get_timestamp()
    source_name = kwargs.get("__pub_tgt", "")
    # iterate over targets and run checks
    for checks_group_name, targets_data in kwargs.items():
        # skip special variables
        if checks_group_name.startswith("_"):
            continue
        # do sanity checks on targets
        if not "targets" in targets_data:
            # its to skip as we might have valid kwargs such as "returner_name"
            continue
        # iterate over checks
        for check_data in targets_data:
            try:
                check_type = check_data.pop("check_type").lower()
                targets_list = check_data.pop("targets")
            except KeyError:
                log.error(
                    "dnuts.multicheck: no mandatory 'check_type' or 'targets' key defined in target data, for check groups - {}".format(
                        checks_group_name
                    )
                )
                continue
            check_data.update(
                {"timestamp": timestamp, "__pub_tgt": source_name, "group": checks_group_name,}
            )
            # run checks
            if check_type == "tcp":
                ret["out"] += tcp(*targets_list, **check_data)["out"]
            elif check_type == "http":
                ret["out"] += http(*targets_list, **check_data)["out"]
            elif check_type == "ping":
                ret["out"] += ping(*targets_list, **check_data)["out"]
            elif check_type == "ccmd":
                ret["out"] += ccmd(*targets_list, **check_data)["out"]
    # process returners
    if kwargs.get("returner_name", "").lower() == "elasticsearch":
        import salt.utils.json

        index = kwargs.get("index", "salt-dnuts_multicheck-v1")
        for item in ret["out"]:
            post_result = __salt__["elasticsearch.document_create"](
                index=index, doc_type="default", body=salt.utils.json.dumps(item)
            )
    return ret
