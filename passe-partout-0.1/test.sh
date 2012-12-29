#!/bin/sh

AGENT="ssh-agent"
DUMPER="./passe-partout"

if [ -f id_dsa ] ; then
    echo "Found dsa private key file" ;
else
    ssh-keygen -t dsa -f id_dsa -N "" ;
fi 

if [ -f id_rsa ] ; then
    echo "Found rsa private key file" ;
else
    ssh-keygen -t rsa -f id_rsa -N "" ;
fi 

eval `$AGENT`

ssh-add id_dsa
ssh-add id_rsa

ssh-add -l

rm $DUMPER $DUMPER.o
make

cat > gdbcmd.txt <<EOF
run -v $SSH_AGENT_PID
bt
list
quit
EOF

sudo gdb -q -batch $DUMPER -x gdbcmd.txt

sudo chmod go+rw *key

rm gdbcmd.txt

eval `$AGENT -k`

for suff in id_rsa id_dsa; do
		for i in $suff*.key; do
				echo -n "Comparing $suff and $i: "
				diff -s $suff $i;
		done;
done;
