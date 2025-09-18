def parse_user_agent(user_agent: str) -> str:
    """解析用户代理字符串，返回操作系统和浏览器"""
    os = "未知操作系统"
    browser = "未知浏览器"

    if "Windows NT" in user_agent:
        os = "Windows"
    elif "Mac OS X" in user_agent:
        os = "MacOS"
    elif "Android" in user_agent:
        os = "Android"
    elif "Linux" in user_agent:
        os = "Linux"
    elif "iPhone" in user_agent or "iPad" in user_agent:
        os = "iOS"

    if "Chrome" in user_agent and "Edge" not in user_agent:
        browser = "Chrome"
    elif "Safari" in user_agent and "Chrome" not in user_agent:
        browser = "Safari"
    elif "Firefox" in user_agent:
        browser = "Firefox"
    elif "MSIE" in user_agent or "Trident" in user_agent:
        browser = "IE"
    elif "Edge" in user_agent:
        browser = "Edge"

    return f"{os} | {browser}"


def get_mime_type(file_extension: str | None) -> str:
    """获取文件的MIME类型"""
    if not file_extension:
        return "application/octet-stream"

    mime_map = {
        "pdf": "application/pdf",
        "doc": "application/msword",
        "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "ppt": "application/vnd.ms-powerpoint",
        "pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "xls": "application/vnd.ms-excel",
        "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "zip": "application/zip",
        "rar": "application/x-rar-compressed",
        "7z": "application/x-7z-compressed",
        "txt": "text/plain",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "gif": "image/gif",
        "mp4": "video/mp4",
        "mp3": "audio/mpeg",
    }

    return mime_map.get(file_extension.lower(), "application/octet-stream")
