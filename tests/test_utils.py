from spraymaster.core.utils import load_combo_list, load_list


def test_load_list_strips_blank_and_comment_lines(tmp_path):
    f = tmp_path / "wordlist.txt"
    f.write_text(
        "\n".join(
            [
                "admin",
                "",
                "# this is a comment",
                "root",
                "   ",
                "guest",
            ]
        ),
        encoding="utf-8",
    )

    assert load_list(str(f)) == ["admin", "root", "guest"]


def test_load_list_trims_surrounding_whitespace(tmp_path):
    f = tmp_path / "spaced.txt"
    f.write_text("  alice  \n\tbob\t\n", encoding="utf-8")

    assert load_list(str(f)) == ["alice", "bob"]


def test_load_combo_list_parses_user_colon_pass(tmp_path):
    f = tmp_path / "combo.txt"
    f.write_text(
        "\n".join(
            [
                "admin:password",
                "root:toor",
                "# header",
                "noseparator",
                "",
                "guest:guest:extra",
            ]
        ),
        encoding="utf-8",
    )

    pairs = load_combo_list(str(f))

    assert pairs == [
        ("admin", "password"),
        ("root", "toor"),
        ("guest", "guest:extra"),
    ]


def test_load_combo_list_empty_file(tmp_path):
    f = tmp_path / "empty.txt"
    f.write_text("", encoding="utf-8")

    assert load_combo_list(str(f)) == []
