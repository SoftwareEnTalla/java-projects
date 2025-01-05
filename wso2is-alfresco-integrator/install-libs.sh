#!/bin/bash

LIBS_DIR="./libs"
for file in "$LIBS_DIR"/*.jar "$LIBS_DIR"/*.amp "$LIBS_DIR"/*.zip; do
  if [[ -f "$file" ]]; then
    FILENAME=$(basename -- "$file")
    EXT="${FILENAME##*.}"
    BASENAME="${FILENAME%.*}"

    echo "Installing $file to local Maven repository..."
    mvn install:install-file \
      -Dfile="$file" \
      -DgroupId=custom.libs \
      -DartifactId="${BASENAME}" \
      -Dversion=1.0.0 \
      -Dpackaging="${EXT}"
      -X
  fi
done

