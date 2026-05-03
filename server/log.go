package smb2

import logrus "github.com/sirupsen/logrus"

var log logrus.FieldLogger = logrus.StandardLogger()

func SetLogger(logger logrus.FieldLogger) {
	if logger != nil {
		log = logger
	}
}
