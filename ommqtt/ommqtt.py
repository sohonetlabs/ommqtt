#!/usr/bin/env python

"""
    Based off the skeleton plugin for rsyslog
    and
    https://github.com/czanik/syslog-ng-mqtt-dest/blob/master/mqtt_dest.py


    in rsyslog.conf

    module(load="omprog")
    action(type="omprog" template="json_syslog" binary="/home/foo/ommqtt/ommqtt.py --topic syslog/ --port 1883 ")

"""

import argparse
import json
import logging
import os
import select
import sys
import syslog
import time
from urllib.parse import urlparse

import paho.mqtt.client as mqtt

# App logic global variables
mqtt_dest = None

mqtt_options = None

logger = logging.getLogger(__name__)


class MqttDestination(object):

    def __init__(self, host, port, topic, **options):

        try:
            self.port = int(port)
        except ValueError as err:
            logger.exception("init error")
            syslog.syslog("Init exception " + str(err))
            raise

        self.host = host
        self.username = options.get("username")
        self.password = options.get("password")
        self.topic = topic
        self.debug = int(options.get("debug", 0))
        self.qos = int(options.get("qos", 0))
        self.cert_path = options.get("cert_path")
        self.auth_path = options.get("auth_path")
        self.syslog_severity_threshold = int(options.get("severity", 7))
        self.inflight = options.get("inflight_max")
        self.open_wait = int(options.get("open_wait", 2))

        self._is_opened = False
        self.mqttc = mqtt.Client()

        if self.inflight:
            self.mqttc.max_inflight_messages_set(self.inflight)

        try:
            if self.cert_path:
                if not os.path.exists(self.cert_path):
                    syslog.syslog("Invalid cert path " + self.cert_path)
                    sys.exit(0)
                else:
                    self.mqttc.tls_set(
                        tls_version=2, ca_certs=self.cert_path
                    )
            if self.username and self.password:
                self.mqttc.username_pw_set(
                    self.username, self.password
                )
            elif self.auth_path:
                if not os.path.exists(self.auth_path):
                    syslog.syslog("Invalid auth path " + self.auth_path)
                    sys.exit(0)
                else:
                    with open(self.auth_path, "r") as f:
                        creds = json.load(f)
                        self.mqttc.username_pw_set(
                            creds["username"], creds["password"]
                        )

        except Exception as err:
            logger.exception("init error")
            syslog.syslog("Init exception " + str(err))
            raise

    def is_opened(self):
        return self._is_opened

    def open(self):
        try:
            self.mqttc.connect(self.host, self.port)
            # starts a background thread that calls loop and handles reconnection
            self.mqttc.loop_start()
            self._is_opened = True
        except Exception as err:
            logger.exception("open error")
            syslog.syslog("Open exception " + str(err))
            self._is_opened = False
            return False
        return True

    def close(self):
        self.mqttc.disconnect()
        self._is_opened = False

    def send(self, msg):
        # need to cope with case where we cannot connect to broker
        # we might be booting and unable to send the message yet
        if not self._is_opened:
            if not self.open():
                logger.exception("Could not send message %s, sleeping" % msg)
                # sleep to give the network a chance to come up.
                time.sleep(self.open_wait)
                return False

        if isinstance(msg["MESSAGE"], str):
            decoded_msg = msg["MESSAGE"].strip()
        else:
            decoded_msg = msg["MESSAGE"].decode("utf-8").strip()
        try:
            # parse the message and append the severity to the topic
            # see https://en.wikipedia.org/w/index.php?title=Syslog&section=4#Severity_level
            # use the number not the string
            # so we can have
            # /syslog/1
            # /syslog/6
            # as separate topics
            topic = self.topic
            severity = 7
            try:
                syslog_msg = json.loads(decoded_msg)
                sub_topic = syslog_msg["severity"]
                topic = self.topic + "/" + sub_topic
                severity = int(syslog_msg["severity"])
            except Exception as err:
                logger.exception("Send format exception %s" % msg)
                syslog.syslog("Send format exception " + str(err))
                return False
            # skip messages below severity threshold
            if severity <= self.syslog_severity_threshold:
                message = self.mqttc.publish(topic, decoded_msg, qos=self.qos)
                message.wait_for_publish()
        except Exception as err:
            logger.exception("Could not send message %s" % msg)
            syslog.syslog("Send exception " + str(err))
            self._is_opened = False
            return False
        return True


def on_init():
    global mqtt_dest
    global mqtt_options

    host = mqtt_options.pop("host")
    port = mqtt_options.pop("port")
    topic = mqtt_options.pop("topic")

    mqtt_dest = MqttDestination(
        host, port, topic, **mqtt_options
    )
    mqtt_dest.open()
    syslog.syslog("OMMQTT init")


def on_receive(msgs):
    """This is the entry point where actual work needs to be done. It receives
       a list with all messages pulled from rsyslog. The list is of variable
       length, but contains all messages that are currently available. It is
       suggest NOT to use any further buffering, as we do not know when the
       next message will arrive. It may be in a nanosecond from now, but it
       may also be in three hours...
    """
    global mqtt_dest
    for msg in msgs:
        mqtt_dest.send({"MESSAGE": msg})


def on_exit():
    """ Do everything that is needed to finish processing (e.g.
        close files, handles, disconnect from systems...). This is
        being called immediately before exiting.
    """
    global mqtt_dest
    mqtt_dest.close()


"""
-------------------------------------------------------
This is plumbing that DOES NOT need to be CHANGED
-------------------------------------------------------
Implementor's note: Python seems to very agressively
buffer stdout. The end result was that rsyslog does not
receive the script's messages in a timely manner (sometimes
even never, probably due to races). To prevent this, we
flush stdout after we have done processing. This is especially
important once we get to the point where the plugin does
two-way conversations with rsyslog. Do NOT change this!
See also: https://github.com/rsyslog/rsyslog/issues/22
"""


def main():

    parser = argparse.ArgumentParser(description="rsyslog plugin to send to MQTT broker")

    parser.add_argument("-u", "--url",
                        help="MQTT broker url (mqtts://user:password@host:8883)",
                        default=None,
                        required=False)

    parser.add_argument("-b", "--broker",
                        help="MQTT broker",
                        default=None,
                        required=False)

    parser.add_argument("-p", "--port",
                        help="MQTT broker port",
                        default=None,
                        type=int,
                        required=False)

    parser.add_argument("-t", "--topic",
                        help="MQTT broker topic to post to",
                        default="test/syslog",
                        required=False)

    parser.add_argument("-q", "--qos",
                        help="MQTT qos",
                        default=2,
                        type=int,
                        required=False)

    parser.add_argument("-s", "--severity",
                        help="Maximium syslog severity to send",
                        default=7,
                        type=int,
                        required=False)

    parser.add_argument("-c", "--cert",
                        help="path to cert for the MQTT broker",
                        default=None,
                        required=False)

    parser.add_argument("-a", "--auth",
                        help="path to auth for the MQTT broker",
                        default=None,
                        required=False)

    parser.add_argument("-i", "--inflight",
                        help="Maximium in flight messages for MQTT",
                        default=100,
                        type=int,
                        required=False)

    parser.add_argument("--poll",
                        help="The number of seconds between polling for new messages from syslog",
                        default=0.75,
                        type=float,
                        required=False)

    parser.add_argument("-m", "--messages",
                        help="Max number of messages that are processed within one batch from syslog",
                        default=100,
                        type=int,
                        required=False)

    parser.add_argument("-w", "--openwait",
                        help="Time in seconds to wait if open fails,( usually network is not up yet)",
                        default=2,
                        type=int,
                        required=False)

    args = parser.parse_args()

    url = getattr(args, "url")
    host = getattr(args, "broker")
    port = getattr(args, "port")
    username = None
    password = None

    if url and (host or port):
        raise Exception("Specify url or specify host and port, not both")

    if url:
        mosquitto_url = urlparse(getattr(args, "url"))
        host = mosquitto_url.hostname
        port = mosquitto_url.port
        if mosquitto_url.username and mosquitto_url.password:
            username = mosquitto_url.username
            password = mosquitto_url.password
            if getattr(args, "auth"):
                warn = (
                    "OMMQTT warning "
                    "You have specified both a username:password "
                    "in the url AND an auth file, auth file %s "
                    "will be ignored" % getattr(args, "auth")
                )
                syslog.syslog(warn)
                logger.warning(warn)
    else:
        host = host if host else "localhost"
        port = port if port else 1883

    global mqtt_options
    mqtt_options = {
        "host": host,
        "port": port,
        "username": username,
        "password": password,
        "topic": getattr(args, "topic"),
        "qos": getattr(args, "qos"),
        "severity": getattr(args, "severity"),
        "cert_path": getattr(args, "cert"),
        "auth_path": getattr(args, "auth"),
        "inflight_max": getattr(args, "inflight"),
        "open_wait": getattr(args, "openwait"),
        "debug": 0
    }

    poll_period = getattr(args, "poll")
    max_at_once = getattr(args, "messages")
    syslog.syslog("OMMQTT start up {}:{} poll={} messages={}".format(host, port, poll_period, max_at_once))
    on_init()
    keep_running = 1
    while keep_running == 1:
        while keep_running and sys.stdin in select.select([sys.stdin], [], [], poll_period)[0]:
            msgs = []
            msgs_in_batch = 0
            while keep_running and sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                line = sys.stdin.readline()
                if line:
                    msgs.append(line)
                else:  # an empty line means stdin has been closed
                    keep_running = 0
                msgs_in_batch = msgs_in_batch + 1
                if msgs_in_batch >= max_at_once:
                    break
            if len(msgs) > 0:
                on_receive(msgs)
                try:
                    sys.stdout.flush()  # very important, Python buffers far too much!
                except Exception:
                    logger.exception("Could not flush sys.stdout")
    on_exit()


if __name__ == "__main__":
    main()
