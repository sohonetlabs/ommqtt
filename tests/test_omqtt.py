from unittest import mock

from ommqtt.ommqtt import MqttDestination, on_init, on_receive, on_exit, main
from ommqtt import ommqtt
import sys
import pytest
import json


def test_MqttDestination():
    mqttdestination = MqttDestination("host", "100", "topic")
    assert mqttdestination
    assert mqttdestination.host == "host"
    assert mqttdestination.port == 100
    assert mqttdestination.topic == "topic"
    assert mqttdestination._is_opened is False
    assert mqttdestination.debug == 0
    assert mqttdestination.qos == 0
    assert mqttdestination.mqttc
    assert mqttdestination.cert_path is None
    assert mqttdestination.auth_path is None
    assert mqttdestination.syslog_severity_threshold == 7
    assert not mqttdestination.is_opened()


@pytest.mark.parametrize("debug,expected_debug,qos,expected_qos", [
    ("1", 1, "1", 1),
    (None, 0, None, 0),
])
@pytest.mark.parametrize("cert_path,auth_path", [
    ("cert_path", "auth_path"),
    (None, None),
])
def test_MqttDestination_init(
    debug, expected_debug, qos, expected_qos, cert_path, auth_path,
    mocker
):
    mocker.patch("ommqtt.ommqtt.os")
    Client = mocker.patch("ommqtt.ommqtt.mqtt.Client")

    options = {
        "severity": "1",
        "inflight_max": 20
    }

    if debug:
        options["debug"] = debug

    if qos:
        options["qos"] = qos

    if cert_path:
        options["cert_path"] = cert_path

    if auth_path:
        options["auth_path"] = auth_path

    auth_data = json.dumps({"username": "username", "password": "password"})
    mock_open_data = mock.mock_open(read_data=auth_data)
    with mock.patch("builtins.open", mock_open_data):
        mqttdestination = MqttDestination("host", "100", "topic", **options)

    assert mqttdestination.host == "host"
    assert mqttdestination.port == 100
    assert mqttdestination.topic == "topic"
    assert mqttdestination._is_opened is False
    assert mqttdestination.debug == expected_debug
    assert mqttdestination.qos == expected_qos
    assert mqttdestination.cert_path == cert_path
    assert mqttdestination.auth_path == auth_path
    assert mqttdestination.syslog_severity_threshold == 1
    assert mqttdestination.mqttc is Client.return_value

    expected_mock_calls = [
        mock.call.max_inflight_messages_set(20)
    ]
    if cert_path:
        expected_mock_calls.append(
            mock.call.tls_set(ca_certs='cert_path', tls_version=2)
        )
    if auth_path:
        expected_mock_calls.append(
            mock.call.username_pw_set('username', 'password')
        )

    assert mqttdestination.mqttc.mock_calls == expected_mock_calls


def test_MqttDestination_init__no_cert_path(mocker):

    mocker.patch("ommqtt.ommqtt.os.path.exists", return_value=False)
    syslog = mocker.patch("ommqtt.ommqtt.syslog")

    options = {
        "severity": "1",
        "inflight_max": 20,
        "cert_path": "cert_path"
    }

    with pytest.raises(SystemExit):
        MqttDestination("host", "100", "topic", **options)

    assert syslog.syslog.mock_calls == [
        mock.call('Invalid cert path cert_path')
    ]


def test_MqttDestination_init__no_auth_path(
    mocker
):

    mocker.patch("ommqtt.ommqtt.os.path.exists", return_value=False)
    syslog = mocker.patch("ommqtt.ommqtt.syslog")

    options = {
        "severity": "1",
        "inflight_max": 20,
        "auth_path": "auth_path"
    }

    with pytest.raises(SystemExit):
        MqttDestination("host", "100", "topic", **options)

    assert syslog.syslog.mock_calls == [
        mock.call('Invalid auth path auth_path')
    ]


def test_MqttDestination_init__bad_port(mocker):
    syslog = mocker.patch("ommqtt.ommqtt.syslog")

    with pytest.raises(ValueError):
        MqttDestination("host", "BAD_PORT", "topic")

    assert syslog.syslog.mock_calls == [
        mock.call(
            "Init exception "
            "invalid literal for int() with base 10: 'BAD_PORT'"
        )
    ]


def test_MqttDestination_init__init_exception(mocker):
    syslog = mocker.patch("ommqtt.ommqtt.syslog")
    mocker.patch("ommqtt.ommqtt.os")
    mocker.patch(
        "ommqtt.ommqtt.mqtt.Client",
        return_value=mock.Mock(
            tls_set=mock.Mock(side_effect=Exception("test exception"))
        )
    )

    with pytest.raises(Exception):
        options = {"cert_path": "BAD"}
        MqttDestination("host", "100", "topic", **options)

    assert syslog.syslog.mock_calls == [
        mock.call("Init exception test exception")
    ]


def test_MqttDestination_open(mocker):
    mqttdestination = MqttDestination("host", "100", "topic")
    mqttdestination.mqttc = mock.Mock()

    assert mqttdestination.open()

    assert mqttdestination.is_opened()
    assert mqttdestination.mqttc.mock_calls == [
        mock.call.connect("host", 100),
        mock.call.loop_start()
    ]


def test_MqttDestination_open_Exception(mocker):
    syslog = mocker.patch("ommqtt.ommqtt.syslog")

    mqttdestination = MqttDestination("host", "100", "topic")
    mqttdestination.mqttc = mock.Mock(
        connect=mock.Mock(
            side_effect=Exception("test connect exception")
        )
    )

    assert not mqttdestination.open()

    assert not mqttdestination.is_opened()
    assert mqttdestination.mqttc.mock_calls == [
        mock.call.connect("host", 100),
    ]
    assert syslog.syslog.mock_calls == [
        mock.call('Open exception test connect exception')
    ]


def test_MqttDestination_close(mocker):
    mqttdestination = MqttDestination("host", "100", "topic")
    mqttdestination.mqttc = mock.Mock()

    mqttdestination.close()

    assert not mqttdestination.is_opened()
    assert mqttdestination.mqttc.mock_calls == [
        mock.call.disconnect(),
    ]


@pytest.mark.parametrize("msgdata, encode", [
    ({"severity": "1", "MESSAGE": "str_message"}, False),
    ({"severity": "1", "MESSAGE": "byte_message"}, True)
])
def test_MqttDestination_send(msgdata, encode, mocker):
    mqttdestination = MqttDestination("host", "100", "topic")
    mqttdestination.mqttc = mock.Mock()

    message = msgdata["MESSAGE"]
    if encode:
        mqttdestination.send({"MESSAGE": json.dumps(msgdata).encode('utf-8')})
    else:
        mqttdestination.send({"MESSAGE": json.dumps(msgdata)})

    assert mqttdestination.mqttc.mock_calls == [
        mock.call.publish(
            "topic/1", '{"severity": "1", "MESSAGE": "%s"}' % message,
            qos=0
        ),
        mock.call.publish().wait_for_publish()
    ]


def test_MqttDestination_send_msg_level_too_high(mocker):
    mqttdestination = MqttDestination("host", "100", "topic")
    mqttdestination.mqttc = mock.Mock()
    msgdata = {"severity": "8", "MESSAGE": "message8"}
    mqttdestination.send({"MESSAGE": json.dumps(msgdata).encode('utf-8')})

    # make sure message is not sent
    assert mqttdestination.mqttc.mock_calls == []


def test_MqttDestination_send_bad_json(mocker):
    syslog = mocker.patch("ommqtt.ommqtt.syslog")

    mqttdestination = MqttDestination("host", "100", "topic")
    mqttdestination.mqttc = mock.Mock()
    assert not mqttdestination.send(
        {"MESSAGE": "{"}
    )

    # make sure message is not sent
    assert mqttdestination.mqttc.mock_calls == []
    assert syslog.syslog.mock_calls == [
        mock.call(
            "Send format exception Expecting property name enclosed "
            "in double quotes: line 1 column 2 (char 1)"
        )
    ]


def test_MqttDestination_send_bad_publish(mocker):
    syslog = mocker.patch("ommqtt.ommqtt.syslog")

    mqttdestination = MqttDestination("host", "100", "topic")
    mqttdestination.mqttc = mock.Mock(
        publish=mock.Mock(
            side_effect=Exception("test publish exception")
        )
    )
    assert not mqttdestination.send({"MESSAGE": '{"severity": "1"}'})

    # make sure message is not sent
    assert mqttdestination.mqttc.mock_calls == [
        mock.call.publish("topic/1", '{"severity": "1"}', qos=0)
    ]
    assert syslog.syslog.mock_calls == [
        mock.call(
            "Send exception test publish exception"
        )
    ]


def test_on_init(mocker):
    MqttDestination = mocker.patch("ommqtt.ommqtt.MqttDestination")
    syslog = mocker.patch("ommqtt.ommqtt.syslog")
    ommqtt.mqtt_dest = None
    ommqtt.mqtt_options = {
        "host": "broker",
        "port": "port",
        "topic": "topic"
    }
    on_init()
    assert ommqtt.mqtt_dest is MqttDestination.return_value
    assert MqttDestination.mock_calls == [
        mock.call('broker', 'port', 'topic'),
        mock.call().open()
    ]
    assert syslog.mock_calls == [mock.call.syslog("OMMQTT init")]


def test_on_receive():
    ommqtt.mqtt_dest = mock.Mock()
    msg1 = mock.Mock()
    msg2 = mock.Mock()
    on_receive([msg1, msg2])
    assert ommqtt.mqtt_dest.send.mock_calls == [
        mock.call.send({"MESSAGE": msg1}),
        mock.call.send({"MESSAGE": msg2}),
    ]


def test_on_exit():
    ommqtt.mqtt_dest = mock.Mock()
    on_exit()
    assert ommqtt.mqtt_dest.mock_calls == [
        mock.call.close()
    ]


def test_main_single_messages(mocker):
    stdout = mocker.patch(
        'ommqtt.ommqtt.sys.stdout',
    )
    mocker.patch(
        'ommqtt.ommqtt.sys.stdin',
        readline=mock.Mock(
            side_effect=[
                'message1',
                'message2',
                ''
            ]
        )
    )
    mocker.patch(
        'ommqtt.ommqtt.select.select',
        return_value=[[sys.stdin]]
    )

    class Args:
        broker = "broker"
        port = "port"
        topic = "topic"
        qos = 1
        severity = 7
        cert = None
        auth = None
        inflight = 10
        messages = 1
        poll = 1

    mocker.patch(
        'ommqtt.ommqtt.argparse.ArgumentParser',
        return_value=mock.Mock(
            parse_args=mock.Mock(
                return_value=Args
            )
        )
    )
    syslog = mocker.patch('ommqtt.ommqtt.syslog')
    on_init = mocker.patch('ommqtt.ommqtt.on_init')
    on_receive = mocker.patch('ommqtt.ommqtt.on_receive')
    on_exit = mocker.patch('ommqtt.ommqtt.on_exit')

    main()

    assert syslog.mock_calls == [
        mock.call.syslog('OMMQTT start up poll=1 messages=1')
    ]
    assert on_init.mock_calls == [mock.call()]
    assert on_receive.mock_calls == [
        mock.call(['message1']),
        mock.call(['message2'])
    ]
    assert on_exit.mock_calls == [mock.call()]
    assert stdout.flush.mock_calls == [
        mock.call(), mock.call()
    ]


def test_main_multiple_messages(mocker):
    stdout = mocker.patch(
        'ommqtt.ommqtt.sys.stdout',
    )
    mocker.patch(
        'ommqtt.ommqtt.sys.stdin',
        readline=mock.Mock(
            side_effect=[
                'message1',
                'message2',
                'message3',
                'message4',
                'message5',
                ''
            ]
        )
    )
    mocker.patch(
        'ommqtt.ommqtt.select.select',
        return_value=[[sys.stdin]]
    )

    class Args:
        broker = "broker"
        port = "port"
        topic = "topic"
        qos = 1
        severity = 7
        cert = None
        auth = None
        inflight = 10
        messages = 2
        poll = 1

    mocker.patch(
        'ommqtt.ommqtt.argparse.ArgumentParser',
        return_value=mock.Mock(
            parse_args=mock.Mock(
                return_value=Args
            )
        )
    )
    syslog = mocker.patch('ommqtt.ommqtt.syslog')
    on_init = mocker.patch('ommqtt.ommqtt.on_init')
    on_receive = mocker.patch('ommqtt.ommqtt.on_receive')
    on_exit = mocker.patch('ommqtt.ommqtt.on_exit')

    main()

    assert syslog.mock_calls == [
        mock.call.syslog('OMMQTT start up poll=1 messages=2')
    ]
    assert on_init.mock_calls == [mock.call()]
    assert on_receive.mock_calls == [
        mock.call(['message1', 'message2']),
        mock.call(['message3', 'message4']),
        mock.call(['message5'])
    ]
    assert on_exit.mock_calls == [mock.call()]
    assert stdout.flush.mock_calls == [
        mock.call(), mock.call(), mock.call()
    ]


def test_main_no_messages(mocker):
    stdout = mocker.patch(
        'ommqtt.ommqtt.sys.stdout',
    )
    mocker.patch(
        'ommqtt.ommqtt.sys.stdin',
        readline=mock.Mock(
            return_value=''
        )
    )
    mocker.patch(
        'ommqtt.ommqtt.select.select',
        return_value=[[sys.stdin]]
    )

    class Args:
        broker = "broker"
        port = "port"
        topic = "topic"
        qos = 1
        severity = 7
        cert = None
        auth = None
        inflight = 10
        messages = 1
        poll = 1

    mocker.patch(
        'ommqtt.ommqtt.argparse.ArgumentParser',
        return_value=mock.Mock(
            parse_args=mock.Mock(
                return_value=Args
            )
        )
    )
    syslog = mocker.patch('ommqtt.ommqtt.syslog')
    on_init = mocker.patch('ommqtt.ommqtt.on_init')
    on_receive = mocker.patch('ommqtt.ommqtt.on_receive')
    on_exit = mocker.patch('ommqtt.ommqtt.on_exit')

    main()

    assert syslog.mock_calls == [
        mock.call.syslog('OMMQTT start up poll=1 messages=1')
    ]
    assert on_init.mock_calls == [mock.call()]
    assert on_receive.mock_calls == []
    assert on_exit.mock_calls == [mock.call()]
    assert stdout.flush.mock_calls == []


def test_main_no_stdin(mocker):
    mocker.patch(
        'ommqtt.ommqtt.sys.stdin',
        readline=mock.Mock(
            side_effect=[
                ''
            ]
        )
    )
    select = mocker.patch(
        'ommqtt.ommqtt.select.select',
        side_effect=[
            [[sys.stdin]],
            [[]],
            [[sys.stdin]],
            [[sys.stdin]]
        ]
    )

    class Args:
        broker = "broker"
        port = "port"
        topic = "topic"
        qos = 1
        severity = 7
        cert = None
        auth = None
        inflight = 10
        messages = 1
        poll = 1

    mocker.patch(
        'ommqtt.ommqtt.argparse.ArgumentParser',
        return_value=mock.Mock(
            parse_args=mock.Mock(
                return_value=Args
            )
        )
    )
    syslog = mocker.patch('ommqtt.ommqtt.syslog')
    mocker.patch('ommqtt.ommqtt.on_init')
    mocker.patch('ommqtt.ommqtt.on_receive')
    mocker.patch('ommqtt.ommqtt.on_exit')

    main()

    assert syslog.mock_calls == [
        mock.call.syslog('OMMQTT start up poll=1 messages=1')
    ]

    #assert select.mock_calls == []
    #assert False
