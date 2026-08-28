"""WeChat process detection and version resolution."""

from wc_chat_reader.wechat.process_detector import (
    WeChatProcess,
    find_wechat_processes,
    select_primary_process,
)

__all__ = ["WeChatProcess", "find_wechat_processes", "select_primary_process"]
