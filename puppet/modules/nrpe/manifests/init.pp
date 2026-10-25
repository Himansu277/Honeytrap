# ==============================================================================
# HoneyTrap - Puppet Module: Nagios NRPE Agent
# Deploys Nagios NRPE server and custom inspection plugins
# ==============================================================================

class nrpe (
  String  $allowed_hosts = '127.0.0.1,10.0.1.0/24',
  Boolean $is_honeypot   = false,
) {

  package { ['nagios-nrpe-server', 'nagios-plugins']:
    ensure => installed,
  }

  file { '/etc/nagios/nrpe.cfg':
    ensure  => file,
    owner   => 'root',
    group   => 'root',
    mode    => '0644',
    content => template('nrpe/nrpe.cfg.erb'),
    notify  => Service['nagios-nrpe-server'],
    require => Package['nagios-nrpe-server'],
  }

  if $is_honeypot {
    file { '/usr/lib/nagios/plugins/check_cowrie_activity.sh':
      ensure  => file,
      owner   => 'root',
      group   => 'root',
      mode    => '0755',
      content => "#!/usr/bin/env bash\nLOG_FILE=\"/home/cowrie/cowrie/var/log/cowrie/cowrie.json\"\nSTATE_FILE=\"/tmp/cowrie_check_last_lines.txt\"\n[ ! -f \"\$LOG_FILE\" ] && { echo \"OK: Cowrie running, no logs\"; exit 0; }\nTOTAL=\$(wc -l < \"\$LOG_FILE\" | tr -d ' ')\nLAST=0\n[ -f \"\$STATE_FILE\" ] && LAST=\$(cat \"\$STATE_FILE\")\necho \"\$TOTAL\" > \"\$STATE_FILE\"\nif [ \"\$TOTAL\" -gt \"\$LAST\" ]; then\n  DIFF=\$((TOTAL - LAST))\n  ATTACKS=\$(tail -n \"\$DIFF\" \"\$LOG_FILE\" | grep -E 'cowrie.login|cowrie.command' | wc -l)\n  if [ \"\$ATTACKS\" -gt 0 ]; then\n    EVENT=\$(tail -n \"\$DIFF\" \"\$LOG_FILE\" | grep -E 'cowrie.login|cowrie.command' | tail -n 1)\n    echo \"CRITICAL: Attack detected: \$EVENT\"\n    exit 2\n  fi\nfi\necho \"OK: Cowrie normal | total_logs=\$TOTAL\"\nexit 0\n",
      require => Package['nagios-plugins'],
    }
  }

  service { 'nagios-nrpe-server':
    ensure     => running,
    enable     => true,
    hasrestart => true,
    require    => Package['nagios-nrpe-server'],
  }
}
