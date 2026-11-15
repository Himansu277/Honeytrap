# ==============================================================================
# HoneyTrap - Puppet Main Site Manifest (site.pp)
# Enforces desired state and self-corrects drift across nodes
# ==============================================================================

# Default node policy (Applies to Single-Server EC2 deployment)
node default {
  notify { 'HoneyTrap Node Configuration':
    message => "Applying baseline security and hardening policy to node ${::fqdn}",
  }

  class { 'hardening':
    ssh_port          => 2222,
    permit_root_login => 'prohibit-password',
    password_auth     => 'no',
    enable_fail2ban   => false, # fail2ban is disabled by default on AL2023 to avoid epel requirement
    enable_auditd     => true,
  }
}

# 1. Cowrie Honeypot Node
node /.*honeypot.*/ {
  class { 'cowrie':
    fake_hostname => 'srv-prod-db01',
    listen_port   => 2223,
    lure_port     => 22,
  }

  class { 'nrpe':
    allowed_hosts => '127.0.0.1,10.0.1.0/24',
    is_honeypot   => true,
  }
}

# 2. Protected Production Node
node /.*production.*/ {
  class { 'hardening':
    ssh_port               => 2222,
    permit_root_login      => 'prohibit-password',
    password_auth          => 'no',
    enable_fail2ban        => true,
    enable_auditd          => true,
  }

  class { 'nrpe':
    allowed_hosts => '127.0.0.1,10.0.1.0/24',
    is_honeypot   => false,
  }
}

# 3. Management / Bastion Node
node /.*management.*/ {
  class { 'hardening':
    ssh_port               => 2222,
    permit_root_login      => 'prohibit-password',
    password_auth          => 'no',
    enable_fail2ban        => true,
    enable_auditd          => true,
  }
}
