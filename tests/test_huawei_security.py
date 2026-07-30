from __future__ import annotations

from collectors.huawei_security.collector import FetchParams, HuaweiCollector


class FakeResponse:
    def __init__(self, body: dict):
        self.body = body

    def raise_for_status(self) -> None:
        return None

    def json(self) -> dict:
        return self.body


class FakeSession:
    def __init__(self, pages: dict[int, dict]):
        self.pages = pages
        self.headers = {}
        self.requested_pages: list[int] = []

    def post(self, _url: str, *, params: dict, json: dict, timeout: int) -> FakeResponse:
        del json, timeout
        page_index = int(params["pageIndex"])
        self.requested_pages.append(page_index)
        return FakeResponse(self.pages[page_index])


def item(sasn_no: str, *, all_path: str | None = None, lang: str = "en") -> dict:
    return {
        "allPath": all_path,
        "lang": lang,
        "publishDate": "2026-07-30",
        "sasnNo": sasn_no,
        "severity": "Critical",
        "summary": "summary",
        "title": sasn_no,
        "vul": [],
    }


def test_normalize_derives_canonical_detail_url_when_api_omits_path() -> None:
    collector = HuaweiCollector(session=FakeSession({}))
    normalized = collector.normalize(item("huawei-sa-ABC", lang="en"))

    assert normalized["source"]["origin_url"] == (
        "https://securitybulletin.huawei.com/enterprise/en/sa/detail/huawei-sa-ABC"
    )


def test_normalize_prefers_and_absolutizes_api_path() -> None:
    collector = HuaweiCollector(session=FakeSession({}))
    normalized = collector.normalize(
        item("huawei-sa-ABC", all_path="/enterprise/en/sa/detail/huawei-sa-ABC")
    )

    assert normalized["source"]["origin_url"] == (
        "https://securitybulletin.huawei.com/enterprise/en/sa/detail/huawei-sa-ABC"
    )


def test_collect_follows_pages_until_previous_cursor() -> None:
    session = FakeSession(
        {
            1: {"page": {"totalPages": 3}, "data": [item("new-2"), item("new-1")]},
            2: {"page": {"totalPages": 3}, "data": [item("new-0"), item("old-1")]},
            3: {"page": {"totalPages": 3}, "data": [item("older-1")]},
        }
    )
    collector = HuaweiCollector(session=session)

    bulletins = collector.collect(FetchParams(page_size=2), stop_at_external_id="old-1")

    assert [entry["source"]["external_id"] for entry in bulletins] == [
        "new-2",
        "new-1",
        "new-0",
        "old-1",
    ]
    assert session.requested_pages == [1, 2]
