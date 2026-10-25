# ==============================================================================
# HoneyTrap - Puppet Module: Cowrie Honeypot
# Manages Cowrie fake SSH service, deceptive banners, and log pipelines
# ==============================================================================

class cowrie (
  String  $fake_hostname = 'srv-prod-db01',
  String  $fake_version  = 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5',
  Integer $listen_port   = 2223,
  Integer $lure_port     = 22,
) {

  # 1. Dedicated service user
  user { 'cowrie':
    ensure     => present,
    home       => '/home/cowrie',
    managehome => true,
    shell      => '/bin/bash',
    system     => true,
  }

  # 2. Required packages
  $packages = [
    'git', 'python3-pip', 'python3-venv', 'libssl-dev',
    'libffi-dev', 'build-essential', 'iptables-persistent', 'jq'
  ]

  package { $packages:
    ensure => installed,
  }

  # 3. Log directories
  file { ['/home/cowrie/cowrie', '/home/cowrie/cowrie/var', '/home/cowrie/cowrie/var/log', '/home/cowrie/cowrie/var/log/cowrie']:
    ensure  => directory,
    owner   => 'cowrie',
    group   => 'cowrie',
    mode    => '0750',
    require => User['cowrie'],
  }

  # 4. Deploy Cowrie configuration
  file { '/home/cowrie/cowrie/etc':
    ensure  => directory,
    owner   => 'cowrie',
    group   => 'cowrie',
    require => User['cowrie'],
  }

  file { '/home/cowrie/cowrie/etc/cowrie.cfg':
    ensure  => file,
    owner   => 'cowrie',
    group   => 'cowrie',
    mode    => '0640',
    content => template('cowrie/cowrie.cfg.erb'),
    notify  => Service['cowrie'],
    require => File['/home/cowrie/cowrie/etc'],
  }

  # 5. Systemd Service Unit
  file { '/etc/systemd/system/cowrie.service':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => "[Unit]\nDescription=Cowrie Honeypot Service\nAfter=network.target\n\n[Service]\nType=simple\nUser=cowrie\nGroup=cowrie\nWorkingDirectory=/home/cowrie/cowrie\nExecStart=/home/cowrie/cowrie/cowrie-env/bin/cowrie start -n\nRestart=always\n\n[Install]\nWantedBy=multi-user.target\n",
  }

  service { 'cowrie':
    ensure     => running,
    enable     => true,
    hasrestart => true,
    require    => File['/etc/systemd/system/cowrie.service'],
  }
}
