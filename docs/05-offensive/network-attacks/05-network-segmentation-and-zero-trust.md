# 05 - Network Segmentation & Zero Trust

## VLAN Isolation
VLANs group devices at Layer 2, separating them regardless of physical switch topology. 
- Prevents broadcasts from traversing the entire network.
- Requires a router or Layer 3 switch to route traffic between VLANs (where ACLs can be applied).

## 802.1X NAC Authentication
Network Access Control (NAC) using IEEE 802.1X ensures that any device plugging into a port or connecting to Wi-Fi must authenticate before gaining network access.
- **Supplicant:** The client device.
- **Authenticator:** The switch or AP.
- **Authentication Server:** A RADIUS server validating credentials.

## Microsegmentation Policies
Microsegmentation takes segmentation to the workload level. In a data center or Kubernetes cluster, policies dictate exactly which container can talk to which container, denying everything else.

*Example Kubernetes Network Policy:*
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

## Software-Defined Perimeters (SDP)
SDPs dynamically create 1:1 network connections between users and the resources they access. 
- Infrastructure is invisible ("Dark Cloud").
- Authentication and device posture are verified *before* access is granted.
