## Documentation

### 1. Overview
NANEX AGENT is an enterprise multi-agent framework designed for zero-trust security, federated data collaboration, and edge-optimized workloads. This document covers production-grade deployment for:

- Cloud-native (Kubernetes)
- Hybrid edge-cloud
- Bare-metal IoT/Edge

### 2. Prerequisites
### Infrastructure

| Environment | Requirements |
|------|------|
| Kubernetes | 1.24+ cluster with CNl plugin, Cert-Manager, and Prometheus    |
| Edge Devices | Operatorx86 64/ARM64 with 2GB+ RAM, TLS 1.3 SuppOrt, AES-N/ARMv8-Crypto extensions   |
| Hybrid Cloud | AWS/Azure/GCp vpC peering with lPsec VPN   |



### Security Credentials
- TLS CA Certificate (ECDSA P-384)
- JWT Signing Key (RS512)
- Hardware Security Module (HSM) for production

## 3. Deployment Steps

### 3.1 Single-Node Deployment
For development/testing environments:
```
# Clone the repository  
git clone https://github.com/nanex-agent/nanex-core.git  
cd nanex-core  

# Generate TLS certificates (dev mode)  
make certs-dev  

# Start the core services  
docker-compose -f deploy/docker-compose.yml up \  
  --detach \  
  --scale agent=3 \  
  --scale aggregator=1  

# Verify deployment  
curl -k https://localhost:8443/health | jq .
```

### 3.2 Multi-Cluster Deployment
For enterprise Kubernetes (EKS/GKE/AKS):
```
# Add Helm repository  
helm repo add yoo https://charts.nanex-agent.io  
helm repo update  

# Install with zero-trust defaults  
helm install nanex-agent nanex/nanex-agent \  
  --namespace nanex-system \  
  --create-namespace \  
  --set global.mtls.enabled=true \  
  --set global.federation.enabled=true \  
  --set-file global.tls.caCert=./ca.pem  

# Apply network policies  
kubectl apply -f https://raw.githubusercontent.com/nanex-agent/networking/v1.0.0/zero-trust.yaml
```

### 3.3 Edge Device Deployment
For ARM64/x86_64 edge nodes:
```
# Download the edge bundle  
curl -LO https://edge.nanex-agent.io/install.sh  
chmod +x install.sh  

# Install with resource constraints  
sudo ./install.sh \  
  --memory-limit 512MB \  
  --storage-path /opt/yoo \  
  --tls-cert /etc/yoo/certs/fullchain.pem \  
  --tls-key /etc/yoo/certs/privkey.pem  

# Start as a systemd service  
sudo systemctl enable nanex-agent-edge  
sudo systemctl start nanex-agent-edge
```

## 4. Configuration
Core Configuration File (yoo.yml)
```
security:  
  mtls:  
    caCert: /etc/nanex/certs/ca.pem  
    revocationCheck: ocsp  
  jwt:  
    algorithm: RS512  
    publicKey: /etc/nanex/jwks/public.pem  

federation:  
  aggregator:  
    address: "aggregator.nanex-system.svc.cluster.local:443"  
    protocol: grpc  
  homomorphic:  
    scheme: ckks  
    params:  
      logN: 14  
      logQ: 438  

edge:  
  resourceLimits:  
    memory: 768MB  
    priorityClassName: "nanex-critical"
```

## 5. Validation
### Health Check
```
curl --cacert /etc/nanex/certs/ca.pem \  
  --cert /etc/nanex/certs/client.pem \  
  --key /etc/nanex/certs/client-key.pem \  
  https://nanex-agent.local:8443/health
```

### Prometheus Metrics
```
# Query agent memory usage  
nanex_agent_memory_bytes{container="agent", instance=~"edge-node-.*"}
```

## 6. Scaling
### Horizontal Pod Autoscaling (Kubernetes)
```
apiVersion: autoscaling/v2  
kind: HorizontalPodAutoscaler  
metadata:  
  name: nanex-agent-autoscaler  
spec:  
  scaleTargetRef:  
    apiVersion: apps/v1  
    kind: Deployment  
    name: nanex-agent  
  minReplicas: 3  
  maxReplicas: 50  
  metrics:  
  - type: Resource  
    resource:  
      name: cpu  
      target:  
        type: Utilization  
        averageUtilization: 70
```

## 7. Security Hardening
### Mandatory Actions
1. Certificate Rotation:
```
kubectl rollout restart deployment/nanex-agent -n nanex-system
```

2. Vulnerability Scanning:
```
trivy image --severity HIGH,CRITICAL nanex-agent/core:1.0.0
```

3. Audit Log Archiving:
```
yooctl audit --export --since 24h > audit-$(date +%s).log  
gpg --encrypt --recipient security@yoo-agent.io audit-*.log
```
