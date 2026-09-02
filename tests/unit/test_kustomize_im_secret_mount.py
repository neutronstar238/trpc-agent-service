from pathlib import Path

import yaml

_IM_ROLES = {
    "trpc-gateway",
    "trpc-worker",
    "trpc-channel-dispatcher",
    "trpc-wecom-connector",
}


def _deployments() -> dict[str, dict]:
    manifest = Path(__file__).resolve().parents[2] / "deploy/kustomize/base/deployments.yaml"
    documents = yaml.safe_load_all(manifest.read_text(encoding="utf-8"))
    return {
        document["metadata"]["name"]: document
        for document in documents
        if isinstance(document, dict) and document.get("kind") == "Deployment"
    }


def test_im_secret_is_optional_read_only_and_scoped_to_im_roles() -> None:
    deployments = _deployments()
    assert _IM_ROLES <= deployments.keys()

    for name, deployment in deployments.items():
        pod_spec = deployment["spec"]["template"]["spec"]
        container = pod_spec["containers"][0]
        secret_volumes = [
            volume
            for volume in pod_spec.get("volumes", [])
            if volume.get("name") == "trpc-im-secrets"
        ]
        secret_mounts = [
            mount
            for mount in container.get("volumeMounts", [])
            if mount.get("name") == "trpc-im-secrets"
        ]

        if name in _IM_ROLES:
            assert secret_volumes == [
                {
                    "name": "trpc-im-secrets",
                    "secret": {
                        "secretName": "trpc-im-secrets",
                        "optional": True,
                        "defaultMode": 0o400,
                    },
                }
            ]
            assert secret_mounts == [
                {
                    "name": "trpc-im-secrets",
                    "mountPath": "/run/secrets",
                    "readOnly": True,
                }
            ]
        else:
            assert secret_volumes == []
            assert secret_mounts == []

        # Credentials are never projected through environment variables.
        assert all(entry.get("name") != "trpc-im-secrets" for entry in container.get("env", []))
        assert all(entry.get("name") != "trpc-im-secrets" for entry in container.get("envFrom", []))
