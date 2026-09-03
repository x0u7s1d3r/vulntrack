{{/* Nom court du chart (surchargable) */}}
{{- define "vulntrack.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Nom complet : si le nom de release contient deja le nom du chart, on
     ne le duplique pas (evite "vulntrack-vulntrack") */}}
{{- define "vulntrack.fullname" -}}
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

{{/* Labels standards recommandes par Kubernetes */}}
{{- define "vulntrack.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{ include "vulntrack.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{/* Labels de selection : stables */}}
{{- define "vulntrack.selectorLabels" -}}
app.kubernetes.io/name: {{ include "vulntrack.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
