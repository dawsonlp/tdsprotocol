locals {
  prefix = "tds-${var.campaign_id}"
  labels = { purpose = "tds-rust-auth", campaign = var.campaign_id, temporary = "true" }
  roles = merge({
    dc    = { windows = true, address = "10.43.1.4", disk = 64 }
    sql   = { windows = true, address = "10.43.1.5", disk = 64 }
    linux = { windows = false, address = "10.43.1.6", disk = 30 }
    }, var.enable_windows_runner ? {
    windows = { windows = true, address = "10.43.1.7", disk = 64 }
  } : {})
}

resource "terraform_data" "guard" {
  input = var.expires_at
  lifecycle {
    precondition {
      condition     = timecmp(var.expires_at, timestamp()) > 0 && timecmp(var.expires_at, timeadd(timestamp(), "4h")) <= 0
      error_message = "Safety expiry must be in the future and within four hours."
    }
    precondition {
      # Reserve $4 for the maximum four-hour VM window at $1/h, $1 for
      # transfer/uncertainty and $2 for cleanup. lab.py also checks actual plans.
      condition     = var.prior_cost_upper_bound_usd + 4 + 1 + 2 <= 10
      error_message = "Prior attempts plus this window and reserves exceed $10."
    }
  }
}

resource "google_service_account" "guest" {
  account_id   = local.prefix
  display_name = "Disposable lab guests - no IAM roles"
}
