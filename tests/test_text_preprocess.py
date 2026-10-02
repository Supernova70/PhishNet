"""Tests for the shared train/inference text cleaner."""

from app.engines.text_preprocess import clean_text


def test_strips_html_tags_and_unescapes_entities():
    out = clean_text("Your order &amp; payment <b>receipt</b> is ready")
    assert "<b>" not in out
    assert "receipt" in out
    assert "&amp;" not in out
    # entity decoded to '&' then dropped by the final charset filter
    assert "order payment" in out


def test_removes_script_and_style_blocks_whole():
    html = "<style>p{color:red}</style><p>Verify your account</p><script>alert(1)</script>"
    out = clean_text(html)
    assert "color" not in out
    assert "alert" not in out
    assert "verify your account" in out


def test_drops_html_artifacts_that_drove_false_positives():
    html = '<td width="100%">Hi&nbsp;there</td><style>body{font-size:10pt;}</style>'
    out = clean_text(html)
    for artifact in ("nbsp", "width", "font", "size", "100"):
        assert artifact not in out.split()
    assert "hi there" in out


def test_urls_and_emails_become_model_tokens():
    out = clean_text("Visit https://evil.example/verify or mail a@b.com now")
    assert "[url]" in out
    assert "[email]" in out
    assert "evil.example" not in out


def test_output_is_lowercased_and_whitespace_collapsed():
    text = "The meeting is at 3pm tomorrow. Please update your calendars."
    out = clean_text(text)
    assert out == "the meeting is at 3pm tomorrow. please update your calendars."


def test_empty_input():
    assert clean_text("") == ""
    assert clean_text(None) == ""
