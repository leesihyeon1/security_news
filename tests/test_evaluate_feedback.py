import evaluate_feedback as ef


def _event(event_id, score, alerted=True, title="t"):
    return {
        "id": "asec:{}".format(event_id),
        "source": "asec",
        "title": title,
        "importance": {"score": score},
        "delivery": {"email_sent": alerted},
    }


def test_print_alerted_noise_mismatches_filters_and_orders(capsys):
    pairs = [
        ("noise", _event(1, score=90, alerted=True, title="high score noise")),
        ("useful", _event(2, score=80, alerted=True, title="useful one, should not appear")),
        ("noise", _event(3, score=30, alerted=False, title="not alerted, should not appear")),
        ("noise", _event(4, score=60, alerted=True, title="mid score noise")),
    ]

    ef.print_alerted_noise_mismatches(pairs)
    out = capsys.readouterr().out

    assert "high score noise" in out
    assert "mid score noise" in out
    assert "useful one" not in out
    assert "not alerted" not in out
    # 점수 내림차순 정렬 확인
    assert out.index("high score noise") < out.index("mid score noise")


def test_print_alerted_noise_mismatches_respects_limit(capsys):
    pairs = [("noise", _event(i, score=100 - i, alerted=True, title="event{}".format(i))) for i in range(15)]
    ef.print_alerted_noise_mismatches(pairs, limit=5)
    out = capsys.readouterr().out
    assert "event0" in out  # 가장 점수 높은 것(=id가 작을수록 점수 높게 만듦)
    assert "...외 10건" in out


def test_print_alerted_noise_mismatches_no_output_when_no_mismatches(capsys):
    pairs = [("useful", _event(1, score=90))]
    ef.print_alerted_noise_mismatches(pairs)
    out = capsys.readouterr().out
    assert out == ""
