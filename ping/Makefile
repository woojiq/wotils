# Kills `ping` process with SIGINT to emulate packete loss.
# Run this script with `sudo` since `ping` runs with sudo too.
.SILENT: sigint
sigint:
	while true; do
	  p=$$(pidof "ping")
	  if [ "$$p" ]; then
	    kill -INT "$$p"
	    break
	  fi
	done

.ONESHELL:
