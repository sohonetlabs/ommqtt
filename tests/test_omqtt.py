from unittest import mock

from ommqtt.ommqtt import MqttDestination, on_init, on_receive, on_exit
from ommqtt import ommqtt


def test_MqttDestination():
    mqttdestination = MqttDestination()
    assert mqttdestination
    assert mqttdestination.host is None
    assert mqttdestination.port is None
    assert mqttdestination.topic is None
    assert mqttdestination._is_opened is False
    assert mqttdestination.debug == 0
    assert mqttdestination.qos == 0
    assert mqttdestination.mqttc
    assert mqttdestination.cert_path is None
    assert mqttdestination.auth_path is None
    assert mqttdestination.syslog_severity_threshold == 7


def test_on_init(mocker):
    MqttDestination = mocker.patch("ommqtt.ommqtt.MqttDestination")
    syslog = mocker.patch("ommqtt.ommqtt.syslog")
    ommqtt.mqtt_dest = None
    ommqtt.mqtt_options = mock.Mock()
    on_init()
    assert ommqtt.mqtt_dest is MqttDestination.return_value
    assert MqttDestination.return_value.mock_calls == [
        mock.call.init(ommqtt.mqtt_options),
        mock.call.open(),

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
