#! /bin/bash


PORT="5000"
NODES="4"
CLUSTERS="4"
CLUSTER_DIST="100"

SESS="ods_demo"

tmux kill-server
#tmux new-session -d -n $SESS

for i in $(seq 1 $CLUSTERS);
do
	echo starting cluster $i
	echo starting node 1 in cluster $i
	tmux new-session -d -n "cluster$i" "cargo run 1 $PORT $CLUSTERS $i $NODES $CLUSTER_DIST;bash"
	for j in $(seq 2 $NODES);
	do
		echo starting node $j in cluster $i
		tmux splitw -t "cluster$i" -h "cargo run $j $PORT $CLUSTERS $i $NODES $CLUSTER_DIST;bash"
		#tmux neww -a -n "c$i-node$j" bash
		#tmux send-keys -t "c$i-node$j" "cargo run $j $PORT $CLUSTERS $i $NODES $CLUSTER_DIST"
	done
done

tmux a
