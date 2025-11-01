#!/usr/bin/env bash
node -e 'localStorage=null; console.log("Use URL #minimal or set localStorage.appMode=\"minimal\" in devtools")' 2>/dev/null || true
echo "Tip: 在控制台执行 localStorage.setItem(\"appMode\",\"minimal\");  或者在地址栏加 #minimal"
