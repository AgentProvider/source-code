{{/* Chart name / fullname helpers */}}
{{- define "apd.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "apd.fullname" -}}
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

{{- define "apd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "apd.labels" -}}
helm.sh/chart: {{ include "apd.chart" . }}
{{ include "apd.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: aauth
{{- end -}}

{{- define "apd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "apd.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "apd.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "apd.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "apd.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}

{{/* Name of the Secret holding the signing keys (created or referenced). */}}
{{- define "apd.keysSecretName" -}}
{{- if .Values.keys.existingSecret -}}
{{- .Values.keys.existingSecret -}}
{{- else -}}
{{- printf "%s-keys" (include "apd.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/* Render the apd.json config from values + extraConfig. */}}
{{- define "apd.configJson" -}}
{{- $cfg := dict
  "issuer" .Values.issuer
  "listen" (printf "0.0.0.0:%d" (int .Values.service.port))
  "keys_file" "/etc/apd/keys/apd-keys.json"
  "agent_token_ttl_secs" .Values.config.agentTokenTtlSecs
  "signature_window_secs" .Values.config.signatureWindowSecs
  "allow_ps_override" .Values.config.allowPsOverride
  "insecure_dev_mode" .Values.config.insecureDevMode
-}}
{{- $enrollment := dict "methods" .Values.config.enrollment.methods -}}
{{- if .Values.config.enrollment.defaultPs }}{{- $_ := set $enrollment "default_ps" .Values.config.enrollment.defaultPs }}{{- end }}
{{- $_ := set $cfg "enrollment" $enrollment -}}
{{- $_ := set $cfg "events" (dict "enabled" .Values.config.events.enabled) -}}
{{- if .Values.config.auditLogFile }}{{- $_ := set $cfg "audit_log_file" .Values.config.auditLogFile }}{{- end }}
{{- $storage := dict -}}
{{- if eq .Values.storage.backend "redis" -}}
{{- $storage = dict "backend" "redis" "redis_addr" .Values.storage.redis.addr "key_prefix" .Values.storage.redis.keyPrefix -}}
{{- else if eq .Values.storage.backend "file" -}}
{{- $storage = dict "backend" "file" "path" .Values.storage.file.path -}}
{{- else -}}
{{- $storage = dict "backend" "memory" -}}
{{- end -}}
{{- $_ := set $cfg "storage" $storage -}}
{{- $merged := mergeOverwrite $cfg .Values.extraConfig -}}
{{- toPrettyJson $merged -}}
{{- end -}}
