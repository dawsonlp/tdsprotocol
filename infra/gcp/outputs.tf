output "inventory" {
  value = { for role, vm in google_compute_instance.lab : role => {
    name        = vm.name, zone = vm.zone, internal_ip = vm.network_interface[0].network_ip,
    external_ip = vm.network_interface[0].access_config[0].nat_ip
  } }
}
output "expires_at" { value = var.expires_at }
output "project_id" { value = var.project_id }
output "campaign_id" { value = var.campaign_id }
