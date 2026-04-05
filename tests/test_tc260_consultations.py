from __future__ import annotations

import unittest

from bs4 import BeautifulSoup

from collectors.tc260_consultations.collector import (
    _extract_attachments,
    _parse_portal_list_items,
)


LIST_HTML = """
<div class="item" style="display: flex;justify-content: space-between;">
  <a target="_blank" onclick="jumpDetail('3bb57023c00a464faf4c2f7b9a5524c7','2026-04-12')">
    关于国家标准《数据安全技术 个人信息保护合规审计专业机构能力要求》征求意见稿征求意见的通知
  </a>
  <span>2026-02-11</span>
</div>
"""


DETAIL_HTML = """
<div class="info">
  <p>各相关单位和专家：</p>
  <p>恳切希望您对该标准提出宝贵意见。</p>
</div>
<div class="list">
  <ul>
    <li>
      <label>征求意见稿：</label>
      <a href="/sysFile/downloadFile/e83fb6ca44834427bb498c5a090d33d4" target="_blank">
        《数据安全技术 个人信息保护合规审计专业机构能力要求》标准征求意见稿文本.pdf
      </a>
    </li>
    <li>
      <label>编制说明：</label>
      <a href="/sysFile/downloadFile/7381e1e3bff5405ab6dfc1eb943abc9e" target="_blank">
        《数据安全技术 个人信息保护合规审计专业机构能力要求》标准编制说明.pdf
      </a>
    </li>
  </ul>
</div>
"""


class Tc260PortalParsingTests(unittest.TestCase):
    def test_parse_portal_list_items(self) -> None:
        soup = BeautifulSoup(LIST_HTML, "html.parser")

        items = _parse_portal_list_items(soup)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["suggestion_id"], "3bb57023c00a464faf4c2f7b9a5524c7")
        self.assertEqual(items[0]["deadline"], "2026-04-12")
        self.assertEqual(items[0]["published_raw"], "2026-02-11")
        self.assertEqual(
            items[0]["detail_url"],
            "https://www.tc260.org.cn/portal/suggestion-detail/3bb57023c00a464faf4c2f7b9a5524c7",
        )

    def test_extract_attachments(self) -> None:
        soup = BeautifulSoup(DETAIL_HTML, "html.parser")

        attachments = _extract_attachments(soup)

        self.assertEqual(len(attachments), 2)
        self.assertEqual(attachments[0]["label"], "征求意见稿")
        self.assertEqual(attachments[0]["file_ext"], "pdf")
        self.assertEqual(
            attachments[0]["url"],
            "https://www.tc260.org.cn/sysFile/downloadFile/e83fb6ca44834427bb498c5a090d33d4",
        )
        self.assertEqual(attachments[1]["label"], "编制说明")
        self.assertEqual(attachments[1]["file_id"], "7381e1e3bff5405ab6dfc1eb943abc9e")


if __name__ == "__main__":
    unittest.main()
