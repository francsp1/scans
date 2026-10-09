#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_parent="$(dirname -- "$repo_dir")"
repo_name="$(basename -- "$repo_dir")"
origem="$repo_dir"
destino="${repo_parent}/${repo_name}-$(date +%Y%m%d-%H%M%S)-$$.zip"

if ! command -v zip >/dev/null 2>&1; then
    printf 'Erro: instale o comando zip antes de executar este script.\n' >&2
    exit 1
fi

umask 077
cd "$origem"
# Usar . inclui também os arquivos e diretórios ocultos.
# -y preserva links simbólicos; -MM falha se algum arquivo não puder ser lido.
zip -r -y -MM "$destino" .
printf '\nZIP criado em:\n%s\n' "$destino"
