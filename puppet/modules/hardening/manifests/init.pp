# ==============================================================================
# HoneyTrap - Puppet Module: Hardening
# Hardens SSH, installs fail2ban, and enables auditd system logging
# ==============================================================================

class hardening (
  Integer $ssh_port          = 2222,
  String  $permit_root_login = 'prohibit-password',
  String  $password_auth     = 'no',
  Boolean $enable_fail2ban   = true,
  Boolean $enable_auditd     = true,
) {

  # 1. SSH Hardening
  file_line { 'sshd_config_port':
    path   => '/etc/ssh/sshd_config',
    line   => "Port ${ssh_port}",
    match  => '^#?Port\s+',
    notify => Service['ssh'],
  }

  file_line { 'sshd_config_root_login':
    path   => '/etc/ssh/sshd_config',
    line   => "PermitRootLogin ${permit_root_login}",
    match  => '^#?PermitRootLogin\s+',
    notify => Service['ssh'],
  }

  file_line { 'sshd_config_password_auth':
    path   => '/etc/ssh/sshd_config',
    line   => "PasswordAuthentication ${password_auth}",
    match  => '^#?PasswordAuthentication\s+',
    notify => Service['ssh'],
  }

  service { 'ssh':
    ensure     => running,
    enable     => true,
    hasrestart => true,
  }

  # 2. Fail2ban setup for brute-force protection
  if $enable_fail2ban {
    package { 'fail2ban':
      ensure => installed,
    }

    service { 'fail2ban':
      ensure  => running,
      enable  => true,
      require => Package['fail2ban'],
    }
  }

  # 3. Auditd setup for system event tracking
  if $enable_auditd {
    package { 'auditd':
      ensure => installed,
    }

    service { 'auditd':
      ensure  => running,
      enable  => true,
      require => Package['auditd'],
    }

    # Audit rule to monitor shadow file modifications
    file { '/etc/audit/rules.d/honeytrap_audit.rules':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0640',
      content => "-w /etc/shadow -p wa -k shadow_tamper\n-w /etc/passwd -p wa -k passwd_tamper\n",
      notify  => Service['auditd'],
      require => Package['auditd'],
    }
  }
}
