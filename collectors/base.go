package collectors

import (
	"strconv"
	"strings"

	"github.com/vgrusdev/sap_metrics_exporter/config"
	"github.com/vgrusdev/sap_metrics_exporter/soap"
	"github.com/vgrusdev/sap_metrics_exporter/utils"
)

type BaseCollector struct {
	config     *config.Config
	soapClient *soap.Client
	logger     *utils.Logger
}

func NewBaseCollector(cfg *config.Config, soapClient *soap.Client) *BaseCollector {
	return &BaseCollector{
		config:     cfg,
		soapClient: soapClient,
		logger:     utils.NewLogger("collector"),
	}
}

func (c *BaseCollector) DetectPorts(instance soap.SAPInstance) (string, string) {
	dispatcherPort := c.detectDispatcherPort(instance)
	enqueuePort := c.detectEnqueuePort(instance, dispatcherPort)
	return dispatcherPort, enqueuePort
}

func (c *BaseCollector) detectDispatcherPort(instance soap.SAPInstance) string {
	if instance.HttpPort != "" && instance.HttpPort != "0" {
		return instance.HttpPort
	}

	instanceNum, err := strconv.Atoi(instance.InstanceNr)
	if err == nil {
		return strconv.Itoa(3200 + instanceNum)
	}

	return c.config.Port
}

func (c *BaseCollector) detectEnqueuePort(instance soap.SAPInstance, dispatcherPort string) string {
	if port, err := strconv.Atoi(dispatcherPort); err == nil {
		return strconv.Itoa(port + 1)
	}
	return c.config.Port
}

func (c *BaseCollector) GetInstanceType(features string) string {
	if strings.Contains(features, "J2EE") {
		return "JAVA"
	}
	return "ABAP"
}

func (c *BaseCollector) GetStatusValue(status, statusText string) (float64, string) {
	displayText := status
	if statusText != "" {
		displayText = statusText
	}

	statusValue := 0.0
	switch strings.ToUpper(status) {
	case "GREEN", "RUNNING":
		statusValue = 1.0
	case "YELLOW", "WARNING", "STARTING":
		statusValue = 0.5
	case "GRAY", "RED", "STOPPED":
		statusValue = 0.0
	}

	return statusValue, displayText
}
