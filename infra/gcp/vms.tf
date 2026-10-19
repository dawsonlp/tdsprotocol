resource "google_compute_instance" "lab" {
  for_each     = local.roles
  name         = "${local.prefix}-${each.key}"
  machine_type = "e2-standard-2"
  zone         = var.zone
  labels       = local.labels
  tags         = [local.prefix, "${local.prefix}-${each.key}"]
  boot_disk {
    auto_delete = true
    initialize_params {
      image  = each.value.windows ? var.windows_image : var.linux_image
      size   = each.value.disk
      type   = "pd-standard"
      labels = local.labels
    }
  }
  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
    network_ip = each.value.address
    access_config {}
  }
  service_account {
    email  = google_service_account.guest.email
    scopes = []
  }
  scheduling {
    provisioning_model          = "STANDARD"
    termination_time            = var.expires_at
    instance_termination_action = "DELETE"
  }
  metadata = merge({
    enable-guest-attributes = "TRUE"
    block-project-ssh-keys  = "TRUE"
    enable-oslogin          = "FALSE"
    }, each.value.windows ? {
    sysprep-specialize-script-ps1 = templatefile("${path.module}/scripts/bootstrap.ps1", { public_key = trimspace(var.ssh_public_key) })
    windows-startup-script-ps1    = templatefile("${path.module}/scripts/bootstrap.ps1", { public_key = trimspace(var.ssh_public_key) })
    } : {
    ssh-keys       = "tds:${trimspace(var.ssh_public_key)}"
    startup-script = file("${path.module}/scripts/bootstrap.sh")
  })
  depends_on = [terraform_data.guard, google_compute_firewall.internal, google_compute_firewall.ssh]
}
