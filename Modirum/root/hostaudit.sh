#!/bin/sh

export UNAME_r=12.1-RELEASE
rsync='/usr/local/bin/rsync'
cmd="${rsync} -a --exclude *.not_terminated"
if [ ! -f $rsync ] ; then
	export PACKAGESITE="PACKAGESITE"
	pkg install -y -q rsync
fi

loghost='LOGSERVER'
loguser='audit'
logpath="/home/audit/logs"
logs="${loguser}@${loghost}:${logpath}/$(hostname)"
idslogs="${loguser}@${loghost}:${logpath}/$(hostname)/ids"

stagedir=`mktemp -t "$(basename ${0})_${1}" -d -u`

bsmtrace_conf() {
    execdirs=""
    trusted="bin
             sbin
             usr/bin
             usr/sbin
             usr/local/bin
             usr/local/sbin
             libexec
             usr/libexec
             usr/local/libexec
             usr/local/libexec/nagios
             etc/rc.d
             etc/periodic
             usr/local/etc/periodic
             usr/local/etc/rc.d
             usr/local/openjdk8
             root/pkg2dw/src
             "

    for i in $trusted ; do
        if echo "$i" | grep -q "^/" ; then
            if [ -d "${i}" ] ; then
                execdirs="$execdirs, ${i}"
            fi
        fi
    done
    for jailroot in `/usr/sbin/jls path` $_NEW_JAIL ; do
        for i in $trusted ; do
            if ! (echo "$i" | grep -q "^/") && [ -d "${jailroot}/${i}" ] ; then
                execdirs="$execdirs, ${jailroot}/${i}"
            fi
        done
    done
    sed s%"EXECDIRS"%"$execdirs"%g < /usr/local/etc/bsmtrace.conf.template > /usr/local/etc/bsmtrace.conf

	/usr/local/etc/rc.d/bsmtrace restart >/dev/null
}

logsync() {
    bsmtrace_conf
    logger -p security.warn "making directories.."
	ssh ${loguser}@${loghost} "mkdir -p ${logpath}/$(hostname)/ids"
    logger -p security.warn "checksumming.."
	for i in `ls /var/audit/ | grep -v 'dist$\|remote$\|not_terminated\|.bz2\|current'` ; do
		sha256 /var/audit/$i | ssh ${loguser}@${loghost} "cat > ${logpath}/$(hostname)/$(basename ${i}).sha256"
		bzip2 /var/audit/$i
	done
    logger -p security.warn "rsyncing.."
    ls /var/audit | grep '\.bz2$' | $cmd --files-from=- /var/audit ${logs}/ && find /var/audit -name '*.bz2' -and -not -newerct '7 days ago' -delete -print
	##$cmd /var/audit/*.bz2 ${logs}/ && find /var/audit -name '*.bz2' -and -not -newerct '7 days ago' -delete -print
	rc=$?
    logger -p security.warn "done."
	return $rc
}

ids_jail() {
    local jail=$1
    if [ -x "${jail}/usr/sbin/freebsd-update" ] ; then
        IFS=`printf "\n\r"`
        echo "Running freebsd-update IDS in ${jail} .."
        jailname=`basename "$(dirname ${jail})"`
        # Clean stage dir for copied files
        rm -Rf "${stagedir}/${jailname}" ; mkdir -p "${stagedir}/${jailname}"

        # Run freebsd-update ids in jail, catch output and write to log server
        output=`/usr/sbin/freebsd-update -b ${jail} -d ${jail}/var/db/freebsd-update IDS --currently-running $(/bin/sh ${jail}/bin/freebsd-version -u) | grep SHA256`
        echo "${output}" | ssh ${loguser}@${loghost} "cat > ${logpath}/$(hostname)/ids/jail-${jailname}.IDS"

        # For each line in output, check if text file && copy to stage dir
        for f in `echo "${output}"|cut -f 1 -w` ; do
            if [ -f "${jail}${f}" ] && [ "$COPY_ALL_FILES" = 'yes' -o `file -b -e soft -i "${jail}${f}" | cut -f 1 -d /` = 'text' ] ; then
                mkdir -p "${stagedir}/jail-${jailname}/files$(dirname ${f})"
                cp "${jail}${f}" "${stagedir}/jail-${jailname}/files${f}"
            fi
        done

        echo "Running pkg check in ${jail} .."
        # Run pkg check in jail, loop through lines of output
        output=''
        for j in `(chroot ${jail} /usr/local/sbin/pkg-static check -s 2>&1 | grep -v stdout.log | tee /tmp/pkginfo.${jailname}.err) | grep "checksum"` ; do
            f=`expr "$j" : ".*mismatch for \(.*\)$"`
            sha256=`sha256 -q ${jail}${f}`
            # Append modified output to variable
            output="${output}$(echo)${j} (found checksum: ${sha256})"
            # For each line in output, check if text file && copy to stage dir
            if [ -f "${jail}${f}" ] && [ "$COPY_ALL_FILES" = 'yes' -o `file -b -e soft -i "${jail}${f}" | cut -f 1 -d /` = 'text' ] ; then
                mkdir -p "${stagedir}/jail-${jailname}/files$(dirname ${f})"
                cp "${jail}${f}" "${stagedir}/jail-${jailname}/files${f}"
            fi
            done
        # Send output to log server
        echo "${output}" | ssh ${loguser}@${loghost} "cat > ${logpath}/$(hostname)/ids/jail-${jailname}.PKGINFO"

        # rsync staged files to log server
        $rsync -a -m --delete "${stagedir}/jail-${jailname}" "${idslogs}/" && rm -Rf "${stagedir}/jail-${jailname}"
        fi
}

ids() {
    IFS=`printf "\n\r"`
    echo "Running freebsd-update IDS on host .."
    ssh ${loguser}@${loghost} "mkdir -p ${logpath}/$(hostname)/ids"
    # Run freebsd-update ids, catch output and write to log server
    output=`/usr/sbin/freebsd-update IDS | grep SHA256`
    echo "${output}" | ssh ${loguser}@${loghost} "cat > ${logpath}/$(hostname)/ids/host.IDS"

    # For each line in output, check if text file && copy to stage dir
    for f in `echo "${output}"|cut -f 1 -w` ; do
        if [ -f "${f}" ] && [ "$COPY_ALL_FILES" = 'yes' -o `file -b -e soft -i "${f}" | cut -f 1 -d /` = 'text' ] ; then
            mkdir -p "${stagedir}/files$(dirname ${f})"
            cp "${f}" "${stagedir}/files${f}"
        fi
    done

    echo "Running pkg check on host .."
    # Run pkg check, loop through lines of output
    output=''
    for j in `/usr/local/sbin/pkg-static check -s 2>&1 | grep -v stdout.log | tee /tmp/pkginfo.err | grep "checksum"` ; do
        f=`expr "$j" : ".*mismatch for \(.*\)$"`
        sha256=`sha256 -q ${f}`
        # Append modified output to variable
        output="${output}$(echo)${j} (found checksum: ${sha256})"
        # For each line in output, check if text file && copy to stage dir
        if [ -f "${f}" ] && [ "$COPY_ALL_FILES" = 'yes' -o `file -b -e soft -i "${f}" | cut -f 1 -d /` = 'text' ] ; then
            mkdir -p "${stagedir}/files$(dirname ${f})"
            cp "${f}" "${stagedir}/files${f}"
        fi
    done
    # Send output to log server
    echo "${output}" | ssh ${loguser}@${loghost} "cat > ${logpath}/$(hostname)/ids/host.PKGINFO"

    # Loop through paths of running jails
    for i in `/usr/sbin/jls path` ; do
        if [ "$IDS_PARALLEL" ] ; then
            # to parallelize...
            echo "Launching in background ...."
            ids_jail $i &
            while [ `ps ax|grep "freebsd-update\|pkg-static"|wc -l` -gt $IDS_PARALLEL ] ; do
                echo "Waiting for ${IDS_PARALLEL} workers before adding more..."
                sleep 5
            done
        else
            # ...or not to parallelize..
            ids_jail $i
        fi
    done
    # ...that is the question
    wait

    # rsync staged files to log server
    $rsync -a -m --delete ${stagedir}/* "${idslogs}/"
    rm -Rf ${stagedir}
    unset IFS
}

logscan() {
	safe=""
    safe="$safe *.jpg *.png *.svg *.pdf"
    safe="$safe *.css *.html"
    safe="$safe *.jar *.war *.java *.class"
    safe="$safe *.zip *.gz *.tar *.tbz *.tgz *.bz2 *.xz *.txz *.lz4"
    safe="$safe *.crt *.key *.pem *.pkcs12 *.p12 *.bin *.der"
    safe="$safe *.yml *.yaml *.json *.conf *.cfg *.xml *.wml *.rb"
    safe="$safe *sampledata.sql"
    safe="$safe .git"
	safe="$safe bin"
	safe="$safe lib"
	safe="$safe libexec"
	safe="$safe sbin"
	safe="$safe compat"
    safe="$safe var/log/logscan.chd"
    safe="$safe var/log/sudo-io"
    safe="$safe var/log/tomcat"
    safe="$safe var/log/nginx"
	safe="$safe var/spool"
	safe="$safe var/mail"
	safe="$safe var/db"
    safe="$safe var/cache"
    safe="$safe var/puppet"
    safe="$safe etc/ssh"
	safe="$safe usr/bin"
	safe="$safe usr/include"
	safe="$safe usr/lib"
	safe="$safe usr/libdata"
	safe="$safe usr/libexec"
	safe="$safe usr/sbin"
	safe="$safe usr/share"
	safe="$safe usr/local/bin"
	safe="$safe usr/local/include"
	safe="$safe usr/local/lib"
	safe="$safe usr/local/libdata"
	safe="$safe usr/local/libexec"
	safe="$safe usr/local/sbin"
	safe="$safe usr/local/share"
	safe="$safe usr/local/info"
	safe="$safe usr/local/man"
    safe="$safe usr/local/etc"
    safe="$safe usr/local/openjdk*"
    safe="$safe usr/local/acs"
    safe="$safe usr/local/apache-tomcat*/webapps"
    safe="$safe usr/local/apache-tomcat*/logs/*.log.*"
    safe="$safe usr/local/apache-tomcat*/logs/*/*.log.*"
    safe="$safe home/*/.bash_history"
    safe="$safe home/*/.lesshst"

    exclude=""
    set -o noglob
    for i in $safe ; do
        [ -n "$exclude" ] && exclude="$exclude -or"
        exclude="$exclude -path '*/${i}/*' -or -path '*/${i}'"
    done
    set +o noglob

	#pan_re="\([456][0-9]\{5\}\)\([0-9]\{6\}\)\([0-9]\{4\}\)"
    pan_re='((4[0-9]{15})|(5[1-5][0-9]{14})|(6(011|5[0-9]{2})[0-9]{12})|(3[47][0-9]{13})|(3(0[0-5]|[68][0-9])[0-9]{11})|((2131|1800|35[0-9]{3})[0-9]{11}))'
    pcre_pan_re='(?:(4[0-9]{12}(?:[0-9]{3})?)|(5[1-5][0-9]{14})|(6(?:011|5[0-9]{2})[0-9]{12})|(3[47][0-9]{13})|(3(?:0[0-5]|[68][0-9])[0-9]{11})|((?:2131|1800|35[0-9]{3})[0-9]{11}))'

	track1_re="\(%B[45][0-9]\{12,17\}\^.\{0,27\}\^[0-9]\{0,32\}\?\)"
	track2_re="\(\;[45][0-9]\{15\}\=[0-9]\{20\}\?\)"

    cmd="find /data/jails/*/root/* -type f -and -not \( $exclude \) -print0 | xargs -0 -P8 grep -m 1 -I -H -E \"${pan_re}\""
#    cmd="find /data/jails/*/root/* -type f -and -not \( $exclude \) -print0 | xargs -0 -P8 pcregrep -I -H \"${pcre_pan_re}\""
    sh -c "$cmd" 2>&1 | tee /var/log/logscan.chd | ssh ${loguser}@${loghost} "cat > ${logpath}/$(hostname)/logscan.chd"

    #files=`sh -c "$cmd"`
    #IFS=`printf "\n\r"`
    #for f in $files ; do
    #    pcregrep -H --line-buffered "${pcre_pan_re}" "${f}" | head -1
    #done | tee /var/log/logscan.chd | ssh ${loguser}@${loghost} "cat > ${logpath}/$(hostname)/logscan.chd"
    #unset IFS

#	find . -type f -exec grep -m 1 -H "${pan_re}\|${track1_re}\|${track2_re}" {} ";"
#	find . -type f -exec grep -m 1 -H "${pan_re}" {} ";"
#	find . -type f -exec grep -m 1 -H "${track1_re}" {} ";"
#	find . -type f -exec grep -m 1 -H "${track2_re}" {} ";"
}

while [ -n "$1" ] ; do
    echo "Calling hostaudit function $1"
    $1
    shift
done
