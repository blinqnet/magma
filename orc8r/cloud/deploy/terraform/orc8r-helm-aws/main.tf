################################################################################
# Copyright 2020 The Magma Authors.

# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

data "terraform_remote_state" "current" {
  backend = var.state_backend
  config  = var.state_config

  defaults = {
    orc8r_tag = "latest"
  }
}

locals {
  orc8r_tag = var.orc8r_tag == "" ? data.terraform_remote_state.current.outputs.orc8r_tag : var.orc8r_tag
}

resource "helm_release" "orc8r" {
  name                = var.helm_deployment_name
  namespace           = kubernetes_namespace.orc8r.metadata[0].name
  repository          = var.helm_repo
  repository_username = var.helm_user
  repository_password = var.helm_pass
  chart               = "orc8r"
  version             = var.orc8r_chart_version
  keyring             = ""
  timeout             = 600
  values              = [data.template_file.orc8r_values.rendered]

  set_sensitive {
    name  = "controller.spec.database.pass"
    value = var.orc8r_db_pass
  }
}

resource "helm_release" "lte-orc8r" {
  count = (
    var.orc8r_deployment_type == "fwa" ||
    var.orc8r_deployment_type == "federated_fwa" ||
    var.orc8r_deployment_type == "all"
  ) ? 1 : 0

  name                = "lte-orc8r"
  namespace           = kubernetes_namespace.orc8r.metadata[0].name
  repository          = var.helm_repo
  repository_username = var.helm_user
  repository_password = var.helm_pass
  chart               = "lte-orc8r"
  version             = var.lte_orc8r_chart_version
  keyring             = ""
  timeout             = 600
  values              = [data.template_file.orc8r_values.rendered]

  set_sensitive {
    name  = "controller.spec.database.pass"
    value = var.orc8r_db_pass
  }
}

resource "helm_release" "feg-orc8r" {
  count = (
    var.orc8r_deployment_type == "federated_fwa" ||
    var.orc8r_deployment_type == "all"
  ) ? 1 : 0

  name                = "feg-orc8r"
  namespace           = kubernetes_namespace.orc8r.metadata[0].name
  repository          = var.helm_repo
  repository_username = var.helm_user
  repository_password = var.helm_pass
  chart               = "feg-orc8r"
  version             = var.feg_orc8r_chart_version
  keyring             = ""
  timeout             = 600
  values              = [data.template_file.orc8r_values.rendered]

  set_sensitive {
    name  = "controller.spec.database.pass"
    value = var.orc8r_db_pass
  }
}

resource "helm_release" "cwf-orc8r" {
  count               = var.orc8r_deployment_type == "all" ? 1 : 0
  name                = "cwf-orc8r"
  namespace           = kubernetes_namespace.orc8r.metadata[0].name
  repository          = var.helm_repo
  repository_username = var.helm_user
  repository_password = var.helm_pass
  chart               = "cwf-orc8r"
  version             = var.cwf_orc8r_chart_version
  keyring             = ""
  timeout             = 600
  values              = [data.template_file.orc8r_values.rendered]

  set_sensitive {
    name  = "controller.spec.database.pass"
    value = var.orc8r_db_pass
  }
}


resource "helm_release" "fbinternal-orc8r" {
  count = var.orc8r_deployment_type == "all" ? 1 : 0

  name                = "fbinternal-orc8r"
  namespace           = kubernetes_namespace.orc8r.metadata[0].name
  repository          = var.helm_repo
  repository_username = var.helm_user
  repository_password = var.helm_pass
  chart               = "fbinternal-orc8r"
  version             = var.fbinternal_orc8r_chart_version
  keyring             = ""
  timeout             = 600
  values              = [data.template_file.orc8r_values.rendered]

  set_sensitive {
    name  = "controller.spec.database.pass"
    value = var.orc8r_db_pass
  }
}

resource "helm_release" "dp-orc8r" {
  count = var.orc8r_deployment_type == "all" ? 1 : 0

  name                = "domain-proxy"
  namespace           = kubernetes_namespace.orc8r.metadata[0].name
  repository          = var.helm_repo
  repository_username = var.helm_user
  repository_password = var.helm_pass
  chart               = "domain-proxy"
  version             = var.dp_orc8r_chart_version
  keyring             = ""
  timeout             = 600
  values              = [data.template_file.orc8r_values.rendered]

  set_sensitive {
    name  = "controller.spec.database.pass"
    value = var.orc8r_db_pass
  }
}

data "template_file" "orc8r_values" {
  template = file("${path.module}/templates/orc8r-values.tpl")
  vars = {
    orc8r_chart_version = var.orc8r_chart_version
    image_pull_secret   = kubernetes_secret.artifactory.metadata.0.name
    docker_registry     = var.docker_registry
    docker_tag          = local.orc8r_tag

    magma_uuid     = var.magma_uuid
    certs_secret   = kubernetes_secret.orc8r_certs.metadata.0.name
    configs_secret = kubernetes_secret.orc8r_configs.metadata.0.name
    envdir_secret  = kubernetes_secret.orc8r_envdir.metadata.0.name
    # We need to define this variable so the template renders properly, but the
    # right k8s secret won't exist unless deploy_nms is set to true.
    # So if deploy_nms is set to false, we'll just this secret name to the
    # orc8r certs secret
    nms_certs_secret = var.deploy_nms ? kubernetes_secret.nms_certs.0.metadata.0.name : kubernetes_secret.orc8r_certs.metadata.0.name

    controller_replicas = var.orc8r_controller_replicas
    nginx_replicas      = var.orc8r_proxy_replicas
    nginx_metrics       = var.orc8r_nginx_metrics

    controller_hostname = format("controller.%s", var.orc8r_domain_name)
    api_hostname        = format("api.%s", var.orc8r_domain_name)
    nms_hostname        = format("*.nms.%s", var.orc8r_domain_name)

    orc8r_db_name    = var.orc8r_db_name
    orc8r_db_host    = var.orc8r_db_host
    orc8r_db_port    = var.orc8r_db_port
    orc8r_db_dialect = var.orc8r_db_dialect
    orc8r_db_user    = var.orc8r_db_user
    orc8r_db_pass    = var.orc8r_db_pass

    deploy_nms = var.deploy_nms

    metrics_pvc_promcfg  = kubernetes_persistent_volume_claim.storage["promcfg"].metadata.0.name
    metrics_pvc_promdata = kubernetes_persistent_volume_claim.storage["promdata"].metadata.0.name

    create_usergrafana             = true
    user_grafana_hostname          = format("%s-user-grafana:3000", var.helm_deployment_name)
    grafana_pvc_grafanaData        = kubernetes_persistent_volume_claim.storage["grafanadata"].metadata.0.name
    grafana_pvc_grafanaDatasources = kubernetes_persistent_volume_claim.storage["grafanadatasources"].metadata.0.name
    grafana_pvc_grafanaProviders   = kubernetes_persistent_volume_claim.storage["grafanaproviders"].metadata.0.name
    grafana_pvc_grafanaDashboards  = kubernetes_persistent_volume_claim.storage["grafanadashboards"].metadata.0.name

    prometheus_cache_hostname = format("%s-prometheus-cache", var.helm_deployment_name)
    alertmanager_hostname     = format("%s-alertmanager", var.helm_deployment_name)
    alertmanager_url          = format("%s-alertmanager:9093", var.helm_deployment_name)
    prometheus_url            = format("%s-prometheus:9090", var.helm_deployment_name)

    additional_payload_mount_path = var.additional_payload_mount_path
    private_key_mount_path        = var.private_key_mount_path
    public_key_mount_path         = var.public_key_mount_path

    prometheus_configurer_version   = var.prometheus_configurer_version
    alertmanager_configurer_version = var.alertmanager_configurer_version

    dp_enabled          = var.dp_enabled
    dp_sas_endpoint_url = var.dp_sas_endpoint_url

    thanos_enabled        = var.thanos_enabled
    thanos_bucket         = var.thanos_enabled ? aws_s3_bucket.thanos_object_store_bucket[0].bucket : ""
    thanos_aws_access_key = var.thanos_enabled ? aws_iam_access_key.thanos_s3_access_key[0].id : ""
    thanos_aws_secret_key = var.thanos_enabled ? aws_iam_access_key.thanos_s3_access_key[0].secret : ""

    thanos_compact_selector = var.thanos_compact_node_selector != "" ? format("compute-type: %s", var.thanos_compact_node_selector) : "{}"
    thanos_query_selector   = var.thanos_query_node_selector != "" ? format("compute-type: %s", var.thanos_query_node_selector) : "{}"
    thanos_store_selector   = var.thanos_store_node_selector != "" ? format("compute-type: %s", var.thanos_store_node_selector) : "{}"

    region = var.region

    nginx_worker_connections = var.nginx_worker_connections

    nginx_node_selector                   = var.nginx_node_selector != {} ? jsonencode(var.nginx_node_selector) : "{}"
    prometheus_node_selector              = var.prometheus_node_selector != {} ? jsonencode(var.prometheus_node_selector) : "{}"
    usergrafana_node_selector             = var.usergrafana_node_selector != {} ? jsonencode(var.usergrafana_node_selector) : "{}"
    nms_node_selector                     = var.nms_node_selector != {} ? jsonencode(var.nms_node_selector) : "{}"
    nms_nginx_node_selector               = var.nms_nginx_node_selector != {} ? jsonencode(var.nms_nginx_node_selector) : "{}"
    dp_node_selector                      = var.dp_node_selector != {} ? jsonencode(var.dp_node_selector) : "{}"
    accessd_controller_node_selector      = var.accessd_controller_node_selector != {} ? jsonencode(var.accessd_controller_node_selector) : "{}"
    analytics_controller_node_selector    = var.analytics_controller_node_selector != {} ? jsonencode(var.analytics_controller_node_selector) : "{}"
    ctraced_controller_node_selector      = var.ctraced_controller_node_selector != {} ? jsonencode(var.ctraced_controller_node_selector) : "{}"
    device_controller_node_selector       = var.device_controller_node_selector != {} ? jsonencode(var.device_controller_node_selector) : "{}"
    directoryd_controller_node_selector   = var.directoryd_controller_node_selector != {} ? jsonencode(var.directoryd_controller_node_selector) : "{}"
    dispatcher_controller_node_selector   = var.dispatcher_controller_node_selector != {} ? jsonencode(var.dispatcher_controller_node_selector) : "{}"
    eventd_controller_node_selector       = var.eventd_controller_node_selector != {} ? jsonencode(var.eventd_controller_node_selector) : "{}"
    obsidian_controller_node_selector     = var.obsidian_controller_node_selector != {} ? jsonencode(var.obsidian_controller_node_selector) : "{}"
    bootstrapper_controller_node_selector = var.bootstrapper_controller_node_selector != {} ? jsonencode(var.bootstrapper_controller_node_selector) : "{}"
    streamer_controller_node_selector     = var.streamer_controller_node_selector != {} ? jsonencode(var.streamer_controller_node_selector) : "{}"
    tenants_controller_node_selector      = var.tenants_controller_node_selector != {} ? jsonencode(var.tenants_controller_node_selector) : "{}"
    certifier_controller_node_selector    = var.certifier_controller_node_selector != {} ? jsonencode(var.certifier_controller_node_selector) : "{}"
    configurator_controller_node_selector = var.configurator_controller_node_selector != {} ? jsonencode(var.configurator_controller_node_selector) : "{}"
    state_controller_node_selector        = var.state_controller_node_selector != {} ? jsonencode(var.state_controller_node_selector) : "{}"
    lte_controller_node_selector          = var.lte_controller_node_selector != {} ? jsonencode(var.lte_controller_node_selector) : "{}"
    metricsd_controller_node_selector     = var.metricsd_controller_node_selector != {} ? jsonencode(var.metricsd_controller_node_selector) : "{}"
    orchestrator_controller_node_selector = var.orchestrator_controller_node_selector != {} ? jsonencode(var.orchestrator_controller_node_selector) : "{}"
    cwf_controller_node_selector          = var.cwf_controller_node_selector != {} ? jsonencode(var.cwf_controller_node_selector) : "{}"
    feg_controller_node_selector          = var.feg_controller_node_selector != {} ? jsonencode(var.feg_controller_node_selector) : "{}"
    controller_node_selector              = var.controller_node_selector != {} ? jsonencode(var.controller_node_selector) : "{}"
  }
}
