# tests/test_google_cli.py
import pytest
import sys
from pathlib import Path
from unsealer.google import cli

def test_google_cli_deduplication_and_export(mocker):
    """验证 Google CLI 能正确处理重复数据并导出报告"""
    # 模拟输入两个相同的 URI，验证去重逻辑
    uri = "otpauth-migration://offline?data=ChkKCHBhc3N3b3JkEgR1c2VyGgdzZXJ2aWNl"
    mocker.patch.object(sys, "argv", ["unsealer", "google", uri, uri, "-o", "report.md"])
    
    # Mock 解密返回
    mock_acc = {"issuer": "service", "name": "user", "totp_secret": "GEZDGNBVGY3TQOI=", "algorithm": "SHA1"}
    mocker.patch("unsealer.google.cli.decrypt_google_auth_uri", return_value=[mock_acc])
    
    # Mock 报告保存逻辑
    mock_save = mocker.patch("unsealer.google.cli._save_report")
    mocker.patch("rich.console.Console.print")

    cli.main()

    # 验证最终只保留了一个账号（去重成功）
    mock_save.assert_called_once()
    final_accounts = mock_save.call_args[0][0]
    assert len(final_accounts) == 1
    assert mock_save.call_args[0][1] == Path("report.md")

def test_google_cli_interactive_mode(mocker):
    """测试当不提供参数时，程序进入交互模式"""
    mocker.patch.object(sys, "argv", ["unsealer", "google"])
    
    # 模拟用户先输入一个路径，然后直接回车结束
    mock_prompt = mocker.patch("rich.prompt.Prompt.ask", side_effect=["/tmp/fake_qr.png", ""])
    # 模拟路径扫描返回了一个 URI
    mocker.patch("unsealer.google.cli.extract_uris_from_path", return_value={"otpauth-migration://test"})
    mocker.patch("unsealer.google.cli.decrypt_google_auth_uri", return_value=[])

    cli.main()
    assert mock_prompt.call_count == 2