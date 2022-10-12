// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	gobgpLog "github.com/osrg/gobgp/v3/pkg/log"

	"github.com/sirupsen/logrus"
)

// implement github.com/osrg/gobgp/v3/pkg/log/Logger interface
type ServerLogger struct {
	l   logrus.FieldLogger
	asn uint32
}

func NewServerLogger(l logrus.FieldLogger, asn uint32) *ServerLogger {
	return &ServerLogger{
		l:   l,
		asn: asn,
	}
}

func (l *ServerLogger) Panic(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = "gobgp.BgpServerInstance"
	fields["subsys"] = "bgp-control-plane"
	l.l.WithFields(logrus.Fields(fields)).Panic(msg)
}

func (l *ServerLogger) Fatal(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = "gobgp.BgpServerInstance"
	fields["subsys"] = "bgp-control-plane"
	l.l.WithFields(logrus.Fields(fields)).Fatal(msg)
}

func (l *ServerLogger) Error(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = "gobgp.BgpServerInstance"
	fields["subsys"] = "bgp-control-plane"
	l.l.WithFields(logrus.Fields(fields)).Error(msg)
}

func (l *ServerLogger) Warn(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = "gobgp.BgpServerInstance"
	fields["subsys"] = "bgp-control-plane"
	l.l.WithFields(logrus.Fields(fields)).Warn(msg)
}

func (l *ServerLogger) Info(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = "gobgp.BgpServerInstance"
	fields["subsys"] = "bgp-control-plane"
	l.l.WithFields(logrus.Fields(fields)).Info(msg)
}

func (l *ServerLogger) Debug(msg string, fields gobgpLog.Fields) {
	fields["asn"] = l.asn
	fields["component"] = "gobgp.BgpServerInstance"
	fields["subsys"] = "bgp-control-plane"
	l.l.WithFields(logrus.Fields(fields)).Debug(msg)
}

func (l *ServerLogger) SetLevel(level gobgpLog.LogLevel) {}

func (l *ServerLogger) GetLevel() gobgpLog.LogLevel {
	return gobgpLog.LogLevel(logrus.DebugLevel)
}
