{{- define "agentsafe.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "agentsafe.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "agentsafe.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "agentsafe.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/component: gateway
app.kubernetes.io/part-of: agentsafe
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "agentsafe.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agentsafe.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "agentsafe.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "agentsafe.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/* The image reference: by digest when one is pinned, by tag otherwise. */}}
{{- define "agentsafe.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) -}}
{{- end -}}
{{- end -}}

{{/* The upstream URL the runtime forwards to. */}}
{{- define "agentsafe.upstreamUrl" -}}
{{- if .Values.upstream.url -}}
{{- .Values.upstream.url -}}
{{- else -}}
{{- $namespace := .Values.upstream.namespace | default .Release.Namespace -}}
{{- printf "%s://%s.%s.svc:%d" .Values.upstream.scheme .Values.upstream.service $namespace (int .Values.upstream.port) -}}
{{- end -}}
{{- end -}}

{{/* The runtime's own spelling of the failure policy. */}}
{{- define "agentsafe.failurePolicy" -}}
{{- if eq .Values.gateway.failurePolicy "FailOpen" -}}failOpen{{- else -}}failClosed{{- end -}}
{{- end -}}
