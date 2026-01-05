#!/usr/bin/env python3
"""测试LLM API连接"""
import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from langchain_openai import ChatOpenAI
from src.utils.config import config

# Load environment variables
load_dotenv()

print("=" * 80)
print("🔍 LLM API Connection Test")
print("=" * 80)
print()

# 显示当前配置
print("📋 Current Configuration:")
print(f"   Model:        {config.llm_model}")
print(f"   Temperature:  {config.llm_temperature}")
print(f"   API Key:      {config.llm_api_key[:10]}...{config.llm_api_key[-4:] if config.llm_api_key else 'NOT SET'}")
print(f"   Base URL:     {config.llm_base_url or 'OpenAI Default'}")
print()

# Check if API key is set
if not config.llm_api_key:
    print("❌ LLM_API_KEY not set!")
    print()
    print("Please configure your API key in .env file:")
    print()
    print("For Qwen (通义千问):")
    print("  LLM_API_KEY=sk-your-qwen-key")
    print("  LLM_BASE_URL=https://dashscope.aliyuncs.com/compatible-mode/v1")
    print()
    print("For OpenAI:")
    print("  LLM_API_KEY=sk-your-openai-key")
    print("  LLM_BASE_URL=")
    sys.exit(1)

# Test connection
print("🔌 Testing API connection...")
print()

try:
    # Initialize LLM
    llm = ChatOpenAI(
        model=config.llm_model,
        temperature=config.llm_temperature,
        api_key=config.llm_api_key,
        base_url=config.llm_base_url,
        timeout=config.get("agents.timeout", 300)
    )

    # Send test message
    print("📤 Sending test message...")
    test_message = "你好！请用一句话介绍一下你自己。"

    response = llm.invoke(test_message)

    print()
    print("✅ API Connection Successful!")
    print()
    print(f"📥 Response:")
    print(f"   {response.content}")
    print()
    print("=" * 80)
    print("✅ Your API is configured correctly!")
    print("=" * 80)
    print()
    print("Next steps:")
    print("  1. Run: python3 test_system.py  # Test system components")
    print("  2. Run: python3 main.py --sample # Run full system")
    print()

except Exception as e:
    print()
    print("❌ API Connection Failed!")
    print()
    print(f"Error: {str(e)}")
    print()
    print("Troubleshooting:")
    print("  1. Check your API key in .env file")
    print("  2. Verify base URL is correct")
    print("  3. Check your network connection")
    print("  4. Ensure you have sufficient API quota")
    print()
    print("For detailed help, see: LLM_API_CONFIG.md")
    sys.exit(1)
