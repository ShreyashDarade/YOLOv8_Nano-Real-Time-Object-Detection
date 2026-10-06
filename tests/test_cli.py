import pytest

from yolo_nano import cli


def test_overrides_skip_unset_flags():
    args = cli.build_parser().parse_args(["train", "--epochs", "3", "--device", "cpu"])
    assert cli.overrides_from_args(args) == {
        "model": {"device": "cpu"},
        "train": {"epochs": 3},
    }


def test_realtime_no_show_and_source():
    args = cli.build_parser().parse_args(["realtime", "--source", "v.mp4", "--no-show"])
    out = cli.overrides_from_args(args)
    assert out["realtime"] == {"source": "v.mp4", "show": False}


def test_export_format_flag():
    args = cli.build_parser().parse_args(["export", "--format", "onnx", "--half"])
    out = cli.overrides_from_args(args)
    assert out["export"] == {"format": "onnx", "half": True}


def test_bad_config_returns_exit_code_2(capsys):
    assert cli.main(["train", "--imgsz", "100"]) == 2
    assert "multiple of 32" in capsys.readouterr().err


def test_command_required():
    with pytest.raises(SystemExit):
        cli.main([])


def test_dispatch_eval(monkeypatch, capsys):
    from yolo_nano import core

    monkeypatch.setattr(core, "evaluate", lambda cfg: {"mAP50": 0.5})
    assert cli.main(["eval"]) == 0
    assert '"mAP50": 0.5' in capsys.readouterr().out
