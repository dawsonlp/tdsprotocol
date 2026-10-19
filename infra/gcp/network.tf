resource "google_compute_network" "lab" {
  name                    = local.prefix
  auto_create_subnetworks = false
  depends_on              = [terraform_data.guard]
}
resource "google_compute_subnetwork" "lab" {
  name          = local.prefix
  network       = google_compute_network.lab.id
  ip_cidr_range = "10.43.1.0/24"
  region        = var.region
}
resource "google_compute_firewall" "internal" {
  name          = "${local.prefix}-internal"
  network       = google_compute_network.lab.name
  source_ranges = [google_compute_subnetwork.lab.ip_cidr_range]
  target_tags   = [local.prefix]
  allow { protocol = "tcp" }
  allow { protocol = "udp" }
  allow { protocol = "icmp" }
}
resource "google_compute_firewall" "ssh" {
  name          = "${local.prefix}-developer-ssh"
  network       = google_compute_network.lab.name
  source_ranges = [var.client_cidr]
  target_tags   = ["${local.prefix}-linux"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}
resource "google_compute_firewall" "sql" {
  name          = "${local.prefix}-developer-sql"
  network       = google_compute_network.lab.name
  source_ranges = [var.client_cidr]
  target_tags   = ["${local.prefix}-sql"]
  allow {
    protocol = "tcp"
    ports    = ["1433"]
  }
  allow {
    protocol = "udp"
    ports    = ["1434"]
  }
}
