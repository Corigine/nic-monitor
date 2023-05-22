#!/usr/bin/env bash
set -euo pipefail

#Tcp port to listen on for web interface and telemetry
TELEMETRY_LISTEN_PORT=10770
#Prometheus pull interval
SERVICE_MONITOR_INTERVAL="15s"
#nic monitor interval, the unit is second.
NIC_MONITORING_INTERVAL=30
#nic statstic interval, the unit is second.
STATS_MONITORING_INTERVAL=15

cat <<EOF > nic-monitor.yaml
---
apiVersion: v1
kind: Service
metadata:
  name: corigine-nic-monitor
  namespace: monitoring
  labels:
    app: corigine-nic-monitor
spec:
  clusterIP: None
  ports:
  - name: metrics
    port: $TELEMETRY_LISTEN_PORT
  selector:
    app: corigine-nic-monitor
---
apiVersion: monitoring.coreos.com/v1
kind: ServiceMonitor
metadata:
  name: corigine-nic-monitor
  namespace: monitoring
spec:
  endpoints:
    - bearerTokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
      interval: $SERVICE_MONITOR_INTERVAL
      port: metrics
  namespaceSelector:
    matchNames:
      - monitoring
  selector:
    matchLabels:
      app: corigine-nic-monitor
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: corigine-nic-monitor
  namespace: monitoring
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  labels:
    app: corigine-nic-monitor
  name: corigine-nic-monitor
rules:
- apiGroups:
  - ""
  resources:
  - pods
  verbs:
  - get
  - list
  - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: corigine-nic-monitor
roleRef:
  name: corigine-nic-monitor
  kind: ClusterRole
  apiGroup: rbac.authorization.k8s.io
subjects:
  - kind: ServiceAccount
    name: corigine-nic-monitor
    namespace: monitoring
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: corigine-nic-monitor
  namespace: monitoring
  annotations:
    kubernetes.io/description: |
      This daemon set launches the corigine nic monitor daemon.
spec:
  selector:
    matchLabels:
      app: corigine-nic-monitor
  template:
    metadata:
      labels:
        app: corigine-nic-monitor
    spec:
      containers:
      - args:
        - nic-monitor
        - --listen-port=$TELEMETRY_LISTEN_PORT
        - --interval=$NIC_MONITORING_INTERVAL
        - --stat-interval=$STATS_MONITORING_INTERVAL
        image: registry.cn-hangzhou.aliyuncs.com/corigine/nic-monitor:v1.0.0
        name: corigine-nic-monitor
        securityContext:
          runAsUser: 0
          privileged: true
        env:
          - name: NODE_NAME
            valueFrom:
              fieldRef:
                fieldPath: spec.nodeName
          - name: POD_IP
            valueFrom:
              fieldRef:
                fieldPath: status.podIP
        volumeMounts:
            - mountPath: /var/log/corigine-nic-monitor
              name: log-path
            - mountPath: /var/run
              name: cri-runtime-path
            - mountPath: /sys/kernel/debug
              name: debug-path
        resources:
          limits:
            cpu: 250m
            memory: 1024Mi
          requests:
            cpu: 102m
            memory: 512Mi
      serviceAccountName: corigine-nic-monitor
      hostNetwork: true
      hostPID: true
      nodeSelector:
        kubernetes.io/os: linux
      volumes:
        - name: log-path
          hostPath:
            path: /var/log/corigine-nic-monitor
        - name: cri-runtime-path
          hostPath:
            path: /var/run
        - name: debug-path
          hostPath:
            path: /sys/kernel/debug
  updateStrategy:
    rollingUpdate:
      maxUnavailable: 10%
    type: RollingUpdate
EOF

kubectl apply -f nic-monitor.yaml
kubectl rollout status daemonset/corigine-nic-monitor -n monitoring --timeout 60s

cat <<"EOF" > /usr/local/bin/kubectl-nic
#!/bin/bash
set -euo pipefail

MONITORING_NS=monitoring

showHelp(){
  echo "kubectl nic {subcommand} [option...]"
  echo "Available Subcommands:"
  echo "  flowdump {namespace/podname} [--srcip, --dstip, , --l4srcport, --l4dstport ] dump the ovs flow in corigine nic, can filter by option filed.  "
}

flowdump(){
  namespacedPod="$1"; shift
  namespace=$(echo "$namespacedPod" | cut -d "/" -f1)
  podName=$(echo "$namespacedPod" | cut -d "/" -f2)
  if [ "$podName" = "$namespacedPod" ]; then
    namespace="default"
  fi

  nodeName=$(kubectl get pod "$podName" -n "$namespace" -o jsonpath={.spec.nodeName})
  if [ -z "$nodeName" ]; then
    echo "Pod $namespacedPod not exists on any node"
    exit 1
  fi

  nicMonitor=$(kubectl get pod -n $MONITORING_NS -l app=corigine-nic-monitor -o 'jsonpath={.items[?(@.spec.nodeName=="'$nodeName'")].metadata.name}')
  kubectl exec "$nicMonitor" -n $MONITORING_NS -- flow dump --devname=$namespace/$podName "$@"
}

if [ $# -lt 1 ]; then
  showHelp
  exit 0
fi

subcommand="$1"; shift

case $subcommand in
  flowdump)
    flowdump "$@"
    ;;
  *)
    showHelp
    exit 1
    ;;
esac
EOF
chmod +x /usr/local/bin/kubectl-nic

