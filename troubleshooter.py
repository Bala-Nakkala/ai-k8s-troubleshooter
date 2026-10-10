from kubernetes import client, config
from kubernetes.client.exceptions import ApiException


def load_kubernetes_config():
    """Load Kubernetes configuration."""
    try:
        config.load_kube_config()
        print("Connected to Kubernetes cluster.\n")
    except Exception as error:
        print(f"Failed to load Kubernetes config: {error}")
        raise


def diagnose_pods():
    """Find pods that are not fully running."""
    v1 = client.CoreV1Api()

    try:
        pods = v1.list_pod_for_all_namespaces().items
    except ApiException as error:
        print(f"Failed to list pods: {error}")
        return

    print("=== Kubernetes Pod Health Report ===\n")

    problem_count = 0

    for pod in pods:
        namespace = pod.metadata.namespace
        name = pod.metadata.name
        phase = pod.status.phase or "Unknown"

        waiting_reasons = []

        for container_status in pod.status.container_statuses or []:
            state = container_status.state

            if state and state.waiting:
                waiting_reasons.append(
                    state.waiting.reason or "Waiting"
                )

            if state and state.terminated:
                waiting_reasons.append(
                    state.terminated.reason or "Terminated"
                )

        is_problem = (
            phase != "Running"
            or bool(waiting_reasons)
            or any(
                status.restart_count > 0
                for status in (pod.status.container_statuses or [])
            )
        )

        if is_problem:
            problem_count += 1

            print(f"Namespace : {namespace}")
            print(f"Pod       : {name}")
            print(f"Phase     : {phase}")
            print(
                "Restarts  : "
                + str(
                    sum(
                        status.restart_count
                        for status in (pod.status.container_statuses or [])
                    )
                )
            )

            if waiting_reasons:
                print(f"Container issues: {', '.join(waiting_reasons)}")

            print("-" * 50)

    if problem_count == 0:
        print("No pods with detected issues.")

    print(f"\nTotal pods with detected issues: {problem_count}")


if __name__ == "__main__":
    load_kubernetes_config()
    diagnose_pods()
