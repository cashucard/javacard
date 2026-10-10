#!/usr/bin/env bash
# Run the card simulator bridge from source. The dev command; CI and the app
# repos may run the shaded jar instead:
#   mvn -B -f tools/cardsim/pom.xml package && java -jar tools/cardsim/target/cardsim.jar
set -euo pipefail
exec mvn -q -f "$(dirname "$0")/pom.xml" compile exec:java -Dexec.args="$*"
