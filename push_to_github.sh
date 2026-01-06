#!/bin/bash

# Copyright 2026 CCR <chenchunrun@gmail.com>
#
# Script to push Security Triage System to GitHub
# This script handles the git push operation with retry logic

echo "================================"
echo "Security Triage System - Git Push"
echo "================================"
echo ""

# Check if we're in the right directory
if [ ! -f "docker-compose.yml" ]; then
    echo "❌ Error: Please run this script from the project root directory"
    exit 1
fi

echo "📊 Current Git Status:"
echo ""
git status --short
echo ""

# Show commit info
echo "📝 Latest Commit:"
git log -1 --oneline
echo ""

echo "🚀 Attempting to push to GitHub..."
echo ""

# Try to push
if git push origin main; then
    echo ""
    echo "✅ Successfully pushed to GitHub!"
    echo ""
    echo "📦 Repository: https://github.com/chenchunrun/security"
    echo ""
else
    EXIT_CODE=$?
    echo ""
    echo "❌ Push failed with exit code: $EXIT_CODE"
    echo ""
    echo "Possible solutions:"
    echo ""
    echo "1. Check your internet connection"
    echo "2. Verify your GitHub credentials"
    echo "3. If using 2FA, use a Personal Access Token instead of password"
    echo "4. Try: git push origin main --verbose"
    echo ""
    echo "To configure proxy (if needed):"
    echo "  export https_proxy=http://proxy.example.com:8080"
    echo "  export http_proxy=http://proxy.example.com:8080"
    echo "  git push origin main"
    echo ""
    exit $EXIT_CODE
fi
