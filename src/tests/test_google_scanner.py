# src/tests/test_google_scanner.py
import pytest
from pathlib import Path
from unsealer.google import scanner

def test_extract_uris_from_path_filtering(mocker):
    """验证扫描器只处理支持的图片后缀并能正确收集 URI"""
    # 模拟一个包含多种文件的文件夹
    mock_path_class = mocker.patch("unsealer.google.scanner.Path")
    
    mock_instance = mock_path_class.return_value
    mock_instance.exists.return_value = True
    mock_instance.is_file.return_value = False
    
    file_png = mocker.MagicMock()
    file_png.suffix = ".png"
    file_txt = mocker.MagicMock()
    file_txt.suffix = ".txt"
    
    mock_instance.iterdir.return_value = [file_png, file_txt]
    
    # Mock 图片打开和 QR 解码
    mocker.patch("PIL.Image.open")
    mock_decode = mocker.patch("unsealer.google.scanner.decode")
    
    # 模拟识别到一个有效的迁移 URI
    mock_obj = mocker.MagicMock()
    mock_obj.data.decode.return_value = "otpauth-migration://found_data"
    mock_decode.return_value = [mock_obj]

    results = scanner.extract_uris_from_path("/mock/path")
    
    assert "otpauth-migration://found_data" in results
    assert len(results) == 1
    # 确保只尝试解析了 .png，跳过了 .txt
    assert mock_decode.call_count == 1

def test_extract_uris_corrupted_image(mocker):
    """验证当图片损坏时，扫描器不会崩溃而是继续工作"""
    mocker.patch("pathlib.Path.exists", return_value=True)
    mocker.patch("pathlib.Path.is_file", return_value=True)
    mocker.patch("pathlib.Path.suffix", ".jpg")
    
    # 模拟图片读取失败（抛出异常）
    mocker.patch("PIL.Image.open", side_effect=RuntimeError("Corrupted"))
    
    results = scanner.extract_uris_from_path("bad_image.jpg")
    assert results == set() # 应该返回空集合而不是抛出异常