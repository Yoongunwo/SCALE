awk -F'[,:}]' '{
  for(i=1;i<=NF;i++){
    if($i ~ /"EvokedRT"/)  ev=$(i+1);
    if($i ~ /"CollectedRT"/) col=$(i+1);
  }
  if(ev && col){ d=(col-ev)*1000; sum+=d; n++; if(d>max)max=d; ev=col=0;
  }
} END{ if(n) printf("count=%d, avg_ms=%.3f, max_ms=%.3f\n", n, sum/n, max); else print "no data"; }' \
/var/log/audit/audisp_ts.log


# disable audisp_ts on exit
sed -i 's/^active *= *.*/active = no/' /etc/audit/plugins.d/audisp_ts.conf 2>/dev/null \
  || sudo sed -i 's/^active *= *.*/active = no/' /etc/audisp/plugins.d/audisp_ts.conf 2>/dev/null

# reapply to auditd
pkill -HUP auditd