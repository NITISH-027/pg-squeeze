#!/bin/bash
cd "$(dirname "$0")/dashboard"
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi
echo "Starting PG-SQUEEZE Dashboard..."
npm run dev
