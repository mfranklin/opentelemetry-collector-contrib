// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package k8sattributesprocessor // import "github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor"

import (
	"context"
	"fmt"
	"strconv"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	conventions "go.opentelemetry.io/collector/semconv/v1.8.0"
	"go.uber.org/zap"

	"github.com/open-telemetry/opentelemetry-collector-contrib/internal/k8sconfig"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor/internal/kube"
)

const (
	clientIPLabelName string = "ip"
)

type kubernetesprocessor struct {
	cfg                      component.Config
	options                  []option
	telemetrySettings        component.TelemetrySettings
	logger                   *zap.Logger
	apiConfig                k8sconfig.APIConfig
	kc                       kube.Client
	passthroughMode          bool
	rules                    kube.ExtractionRules
	filters                  kube.Filters
	podResourceAssociations  []kube.Association
	podDatapointAssociations []kube.Association
	podIgnore                kube.Excludes
}

func (kp *kubernetesprocessor) initKubeClient(logger *zap.Logger, kubeClient kube.ClientProvider) error {
	if kubeClient == nil {
		kubeClient = kube.New
	}
	if !kp.passthroughMode {
		kc, err := kubeClient(logger, kp.apiConfig, kp.rules, kp.filters, append(kp.podResourceAssociations, kp.podDatapointAssociations...), kp.podIgnore, nil, nil, nil, nil)
		if err != nil {
			return err
		}
		kp.kc = kc
	}
	return nil
}

func (kp *kubernetesprocessor) Start(_ context.Context, _ component.Host) error {
	allOptions := append(createProcessorOpts(kp.cfg), kp.options...)

	for _, opt := range allOptions {
		if err := opt(kp); err != nil {
			kp.telemetrySettings.ReportStatus(component.NewFatalErrorEvent(err))
			return nil
		}
	}

	// This might have been set by an option already
	if kp.kc == nil {
		err := kp.initKubeClient(kp.logger, kubeClientProvider)
		if err != nil {
			kp.telemetrySettings.ReportStatus(component.NewFatalErrorEvent(err))
			return nil
		}
	}
	if !kp.passthroughMode {
		go kp.kc.Start()
	}
	return nil
}

func (kp *kubernetesprocessor) Shutdown(context.Context) error {
	if kp.kc == nil {
		return nil
	}
	if !kp.passthroughMode {
		kp.kc.Stop()
	}
	return nil
}

// processTraces process traces and add k8s metadata using resource IP or incoming IP as pod origin.
func (kp *kubernetesprocessor) processTraces(ctx context.Context, td ptrace.Traces) (ptrace.Traces, error) {
	rss := td.ResourceSpans()
	for i := 0; i < rss.Len(); i++ {
		kp.processResource(ctx, rss.At(i).Resource())
	}

	return td, nil
}

// processMetrics process metrics and add k8s metadata using resource IP, hostname or incoming IP as pod origin.
func (kp *kubernetesprocessor) processMetrics(ctx context.Context, md pmetric.Metrics) (pmetric.Metrics, error) {
	rm := md.ResourceMetrics()
	for i := 0; i < rm.Len(); i++ {
		resource := rm.At(i)
		// Do not run resources if there are only pod datapoint associations, but do run them if
		// resource associations are set or both resource and datapoints are empty
		if len(kp.podResourceAssociations) > 0 || len(kp.podDatapointAssociations) == 0 {
			kp.processResource(ctx, resource.Resource())
		}
		kp.processResourceDatapoints(ctx, resource.ScopeMetrics())
	}

	return md, nil
}

// processLogs process logs and add k8s metadata using resource IP, hostname or incoming IP as pod origin.
func (kp *kubernetesprocessor) processLogs(ctx context.Context, ld plog.Logs) (plog.Logs, error) {
	rl := ld.ResourceLogs()
	for i := 0; i < rl.Len(); i++ {
		kp.processResource(ctx, rl.At(i).Resource())
	}

	return ld, nil
}

// processResource adds Pod metadata tags to resource based on pod association configuration
func (kp *kubernetesprocessor) processResource(ctx context.Context, resource pcommon.Resource) {
	podIdentifierValue := extractPodID(ctx, resource.Attributes(), kp.podResourceAssociations)
	kp.logger.Debug("evaluating pod identifier", zap.Any("value", podIdentifierValue))

	for i := range podIdentifierValue {
		if podIdentifierValue[i].Source.From == kube.ConnectionSource && podIdentifierValue[i].Value != "" {
			if _, found := resource.Attributes().Get(kube.K8sIPLabelName); !found {
				resource.Attributes().PutStr(kube.K8sIPLabelName, podIdentifierValue[i].Value)
			}
			break
		}
	}
	if kp.passthroughMode {
		return
	}

	kp.processAttributes(resource.Attributes(), podIdentifierValue)
}

func (kp *kubernetesprocessor) processResourceDatapoints(ctx context.Context, metrics pmetric.ScopeMetricsSlice) {
	for i := 0; i < metrics.Len(); i++ {
		scopeMetrics := metrics.At(i).Metrics()
		for j := 0; j < scopeMetrics.Len(); j++ {
			scopeMetric := scopeMetrics.At(j)
			switch scopeMetric.Type() {
			case pmetric.MetricTypeGauge:
				datapoints := scopeMetric.Gauge().DataPoints()
				for k := 0; k < datapoints.Len(); k++ {
					kp.processDatapointAssociations(ctx, datapoints.At(k).Attributes())
				}
			case pmetric.MetricTypeHistogram:
				datapoints := scopeMetric.Histogram().DataPoints()
				for k := 0; k < datapoints.Len(); k++ {
					kp.processDatapointAssociations(ctx, datapoints.At(k).Attributes())
				}
			case pmetric.MetricTypeExponentialHistogram:
				datapoints := scopeMetric.ExponentialHistogram().DataPoints()
				for k := 0; k < datapoints.Len(); k++ {
					kp.processDatapointAssociations(ctx, datapoints.At(k).Attributes())
				}
			case pmetric.MetricTypeSum:
				datapoints := scopeMetric.Sum().DataPoints()
				for k := 0; k < datapoints.Len(); k++ {
					kp.processDatapointAssociations(ctx, datapoints.At(k).Attributes())
				}
			case pmetric.MetricTypeSummary:
				datapoints := scopeMetric.Summary().DataPoints()
				for k := 0; k < datapoints.Len(); k++ {
					kp.processDatapointAssociations(ctx, datapoints.At(k).Attributes())
				}
			case pmetric.MetricTypeEmpty:
				kp.logger.Warn("Found empty metric type", zap.String("name", scopeMetric.Name()))
			}
		}
	}
}

func (kp *kubernetesprocessor) processDatapointAssociations(ctx context.Context, attributes pcommon.Map) {
	podIdentifierValue := extractPodID(ctx, attributes, kp.podDatapointAssociations)
	kp.logger.Debug("evaluating pod identifier for datapoint", zap.Any("value", podIdentifierValue))
	kp.processAttributes(attributes, podIdentifierValue)
}

func (kp *kubernetesprocessor) processAttributes(attributes pcommon.Map, podIdentifierValue kube.PodIdentifier) {
	var pod *kube.Pod
	if podIdentifierValue.IsNotEmpty() {
		var podFound bool
		if pod, podFound = kp.kc.GetPod(podIdentifierValue); podFound {
			kp.logger.Debug("getting the pod", zap.Any("pod", pod))

			for key, val := range pod.Attributes {
				if _, found := attributes.Get(key); !found {
					attributes.PutStr(key, val)
				}
			}
			kp.addContainerAttributes(attributes, pod)
		}
	}

	namespace := getNamespace(pod, attributes)
	if namespace != "" {
		attrsToAdd := kp.getAttributesForPodsNamespace(namespace)
		for key, val := range attrsToAdd {
			if _, found := attributes.Get(key); !found {
				attributes.PutStr(key, val)
			}
		}
	}

	nodeName := getNodeName(pod, attributes)
	if nodeName != "" {
		attrsToAdd := kp.getAttributesForPodsNode(nodeName)
		for key, val := range attrsToAdd {
			if _, found := attributes.Get(key); !found {
				attributes.PutStr(key, val)
			}
		}
	}
}

func getNamespace(pod *kube.Pod, resAttrs pcommon.Map) string {
	if pod != nil && pod.Namespace != "" {
		return pod.Namespace
	}
	return stringAttributeFromMap(resAttrs, conventions.AttributeK8SNamespaceName)
}

func getNodeName(pod *kube.Pod, resAttrs pcommon.Map) string {
	if pod != nil && pod.NodeName != "" {
		return pod.NodeName
	}
	return stringAttributeFromMap(resAttrs, conventions.AttributeK8SNodeName)
}

// addContainerAttributes looks if pod has any container identifiers and adds additional container attributes
func (kp *kubernetesprocessor) addContainerAttributes(attrs pcommon.Map, pod *kube.Pod) {
	containerName := stringAttributeFromMap(attrs, conventions.AttributeK8SContainerName)
	containerID := stringAttributeFromMap(attrs, conventions.AttributeContainerID)
	var (
		containerSpec *kube.Container
		ok            bool
	)
	switch {
	case containerName != "":
		containerSpec, ok = pod.Containers.ByName[containerName]
		if !ok {
			return
		}
	case containerID != "":
		containerSpec, ok = pod.Containers.ByID[containerID]
		if !ok {
			return
		}
	default:
		return
	}
	if containerSpec.Name != "" {
		if _, found := attrs.Get(conventions.AttributeK8SContainerName); !found {
			attrs.PutStr(conventions.AttributeK8SContainerName, containerSpec.Name)
		}
	}
	if containerSpec.ImageName != "" {
		if _, found := attrs.Get(conventions.AttributeContainerImageName); !found {
			attrs.PutStr(conventions.AttributeContainerImageName, containerSpec.ImageName)
		}
	}
	if containerSpec.ImageTag != "" {
		if _, found := attrs.Get(conventions.AttributeContainerImageTag); !found {
			attrs.PutStr(conventions.AttributeContainerImageTag, containerSpec.ImageTag)
		}
	}
	// attempt to get container ID from restart count
	runID := -1
	runIDAttr, ok := attrs.Get(conventions.AttributeK8SContainerRestartCount)
	if ok {
		containerRunID, err := intFromAttribute(runIDAttr)
		if err != nil {
			kp.logger.Debug(err.Error())
		} else {
			runID = containerRunID
		}
	} else {
		// take the highest runID (restart count) which represents the currently running container in most cases
		for containerRunID := range containerSpec.Statuses {
			if containerRunID > runID {
				runID = containerRunID
			}
		}
	}
	if runID != -1 {
		if containerStatus, ok := containerSpec.Statuses[runID]; ok && containerStatus.ContainerID != "" {
			if _, found := attrs.Get(conventions.AttributeContainerID); !found {
				attrs.PutStr(conventions.AttributeContainerID, containerStatus.ContainerID)
			}
		}
	}
}

func (kp *kubernetesprocessor) getAttributesForPodsNamespace(namespace string) map[string]string {
	ns, ok := kp.kc.GetNamespace(namespace)
	if !ok {
		return nil
	}
	return ns.Attributes
}

func (kp *kubernetesprocessor) getAttributesForPodsNode(nodeName string) map[string]string {
	node, ok := kp.kc.GetNode(nodeName)
	if !ok {
		return nil
	}
	return node.Attributes
}

// intFromAttribute extracts int value from an attribute stored as string or int
func intFromAttribute(val pcommon.Value) (int, error) {
	switch val.Type() {
	case pcommon.ValueTypeInt:
		return int(val.Int()), nil
	case pcommon.ValueTypeStr:
		i, err := strconv.Atoi(val.Str())
		if err != nil {
			return 0, err
		}
		return i, nil
	case pcommon.ValueTypeEmpty, pcommon.ValueTypeDouble, pcommon.ValueTypeBool, pcommon.ValueTypeMap, pcommon.ValueTypeSlice, pcommon.ValueTypeBytes:
		fallthrough
	default:
		return 0, fmt.Errorf("wrong attribute type %v, expected int", val.Type())
	}
}
