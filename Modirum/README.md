# Modirum audit/bsmtrace framework
These are the core bits of our auditing and IDS framework It is built around tools that ship with FreeBSD or, in the case of [`bsmtrace(1)`](https://github.com/openbsm/bsmtrace), come from [TrustedBSD](http://www.trustedbsd.org/).

Much of this consists of various kludges written at various points of my 15+ year FreeBSD "carreer". Parts, both old and new, bear resemblence of what a 4-year-old might produce. Which is, I believe, par for the course.

## Moving parts
### `etc/security/audit_warn`
This is the script that is run whenever audit logs are rotated (see cron jobs). It will, in roughly this order:
1. If called directly from `auditd(8)` (using `audit -n`), launch a copy of itself in the background
2. The background process will fetch current supporting scripts from Puppet, then
3. ship logs to the log server, and finally
4. notify if anything went wrong (via syslog)

### `root/hostaudit.sh`
This is the supporting script mentioned above. It performs a number of tasks, depending on invocation. Some of the key functions are
- Update the `bsmtrace(1)` configuration based on currently running jails
- Checksum and sync audit logs to log server
- Run freebsd-audit IDS and pkg check -s on host and in jails
- Scan files on disk for card numbers and (optionally) track data

Output from the IDS functions is piped directly to output files on the log server. Audit log files are checksummed, with the checksum written directly to files on the logserver, then compressed and shipped.


### `usr/local/etc/bsmtrace.conf`
Generated automagically from corresponding `bsmtrace.conf.template` by `hostaudit.sh` when called from `audit_warn`. The script adds trusted directories for currently-running jails.

### Log server
Scripts on the log server periodically compare output from IDS runs to "known good" runs and notifies accordingly.
Other scripts on the log server periodically verify the checksums of previous audit log files and also verify file ages and such.

These scripts, syslog config, notification mechanisms, etc. is currently outside the scope of this particular project/repo.
