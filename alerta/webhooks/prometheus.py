import datetime
from typing import Any, Dict

from flask import current_app

from alerta.app import alarm_model
from alerta.exceptions import ApiError
from alerta.models.alert import Alert

from . import WebhookBase

JSON = Dict[str, Any]
dt = datetime.datetime

def customer_def(cloud_name):
    if ((cloud_name == "eu-production-mos") or (cloud_name == "presales-mos") or (cloud_name == "eu-mos-tf-region")):
        return "Mirantis IT"
    elif ((cloud_name == "mcc-mke-demo-prod") or (cloud_name == "mcc-mke-demo-stage")):
        return "Pre-sales demo Equinix"
    else:
        return None

def mgmt_def(cloud_id):
    if (cloud_id == "8752eb49-cbe2-4a15-9171-084f5fc44e2f"):
        return "Pre-sales MGMT", "Mirantis IT"
    elif (cloud_id == "d4a94878-140c-469a-b210-ad076ffbb2fa"):
        return "EU MGMT", "Mirantis IT"
    elif (cloud_id == "51f45b9f-6e0f-4654-a880-f269e9c50c64"):
        return "Demo Equinix MGMT", "Pre-sales demo Equinix"
    return "MGMT", None

def parse_prometheus(alert: JSON, external_url: str) -> Alert:

    status = alert.get('status', 'firing')

    # Allow labels and annotations to use python string formats that refer to
    # other labels eg. runbook = 'https://internal.myorg.net/wiki/alerts/{app}/{alertname}'
    # See https://github.com/prometheus/prometheus/issues/2818

    labels = {}
    for k, v in alert['labels'].items():
        try:
            labels[k] = v.format(**alert['labels'])
        except Exception:
            labels[k] = v

    annotations = {}
    for k, v in alert['annotations'].items():
        try:
            annotations[k] = v.format(**labels)
        except Exception:
            annotations[k] = v

    if status == 'firing':
        severity = labels.pop('severity', 'warning')
    elif status == 'resolved':
        severity = alarm_model.DEFAULT_NORMAL_SEVERITY
    else:
        severity = 'unknown'

    # labels
    resource = labels.pop('exported_instance', None) or labels.pop('instance', 'n/a')
    event = labels.pop('event', None) or labels.pop('alertname')
    #environment = labels.pop('environment', current_app.config['DEFAULT_ENVIRONMENT'])
    
    ## customer and environment fields

    try:
        env = labels.get('cluster_id', current_app.config['DEFAULT_ENVIRONMENT']).split('/')
        env_name = env[1]
        env_id = env[2]
        if (env_name == "kaas-mgmt"):
            environment, resource = mgmt_def(env_id)
        else:
            environment = env_name
            resource = customer_def(env_name)
    except Exception:
        environment = labels.get('environment', current_app.config['DEFAULT_ENVIRONMENT']
        resource = None
    
    customer = labels.pop('customer', None)
    correlate = labels.pop('correlate').split(',') if 'correlate' in labels else None
    service = labels.pop('service', '').split(',')
    group = labels.pop('group', None) or labels.pop('job', 'Prometheus')
    origin = 'prometheus/' + labels.pop('monitor', '-')

    try:
        timeout = int(labels.pop('timeout', 0)) or None
    except ValueError:
        timeout = None

    tags = [f'{k}={v}' for k, v in labels.items()]  # any labels left over are used for tags

    # annotations
    value = annotations.pop('value', None)
    summary = annotations.pop('summary', None)
    description = annotations.pop('description', None)
    text = description or summary or f'{severity.upper()}: {resource} is {event}'

    if external_url:
        annotations['externalUrl'] = external_url  # needed as raw URL for bi-directional integration
    if 'generatorURL' in alert:
        annotations['moreInfo'] = f"<a href=\"{alert['generatorURL']}\" target=\"_blank\">Prometheus Graph</a>"

    # attributes
    attributes = {
        'startsAt': alert['startsAt'],
        'endsAt': alert['endsAt']
    }
    attributes.update(annotations)  # any annotations left over are used for attributes

    return Alert(
        resource=resource,
        event=event,
        environment=environment,
        customer=customer,
        severity=severity,
        correlate=correlate,
        service=service,
        group=group,
        value=value,
        text=text,
        attributes=attributes,
        origin=origin,
        event_type='prometheusAlert',
        timeout=timeout,
        raw_data=alert,
        tags=tags
    )


class PrometheusWebhook(WebhookBase):
    """
    Prometheus Alertmanager webhook receiver
    See https://prometheus.io/docs/operating/integrations/#alertmanager-webhook-receiver
    """

    def incoming(self, path, query_string, payload):

        if payload and 'alerts' in payload:
            external_url = payload.get('externalURL')
            return [parse_prometheus(alert, external_url) for alert in payload['alerts']]
        else:
            raise ApiError('no alerts in Prometheus notification payload', 400)
