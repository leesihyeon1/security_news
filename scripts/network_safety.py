# -*- coding: utf-8 -*-
"""요청받은 URL을 실제로 가져오기 전에, 그 주소가 우리 쪽 사설망을 가리키지 않는지 본다.

왜 필요한가
    /api/analyze는 인증 없는 공개 엔드포인트다(대시보드 "심층분석" 버튼이 부르지만,
    누구나 그 요청 형태를 그대로 흉내 낼 수 있다). 거기 실린 url을 그대로 큐에
    넣고, 이 저장소의 analysis_worker.py가 사용자의 PC에서 requests.get(url)로
    가져온다 — url 값에 아무 검증이 없었다(실측 2026-09-22: `new URL(url)`로 문법만
    확인).

    그래서 누구든 http://169.254.169.254/…(클라우드 메타데이터), http://127.0.0.1:PORT/…
    (PC에서 도는 다른 서비스), http://192.168.x.x/…(같은 네트워크의 다른 장비) 같은
    주소를 url로 넣어 큐에 올릴 수 있었다. 워커가 그걸 그대로 받아 오면 (1) 그
    응답이 "기사 원문"으로 분석돼 인증 없는 공개 API(insights.js)에 그대로 실리고
    (2) 사용자의 PC가 공격자 대신 사설망을 스캔해 주는 셈이 된다.

    리다이렉트도 같은 문제다 — 겉보기엔 공개 주소인 url이 301/302로 사설 주소로
    안내할 수 있어서, 첫 주소만 검사하고 requests의 기본 자동 리다이렉트를 그대로
    따라가면 이 검사를 우회당한다.

무엇을 하나
    scheme은 http/https만 허용한다. 호스트명을 실제로 DNS 조회해서 나온 IP 전부가
    공인 IP인지 본다(사설·루프백·링크로컬·예약·멀티캐스트·미지정 대역은 전부 거부) —
    문자열이 아니라 실제 연결될 주소를 본다. requests에는 자동 리다이렉트를 끄게
    하고, 이 모듈이 리다이렉트 응답을 받을 때마다 다음 주소도 같은 검사를 거쳐서만
    따라간다.

무엇을 하지 않나
    호스트 이름 자체를 막지 않는다(도메인 차단 목록이 아니다) — DNS가 가리키는
    실제 주소만 본다. 그래서 이 검사를 통과한 뒤에도 그 사이트가 나중에 DNS를
    사설 IP로 바꾸는 TOCTOU는 막지 못한다(흔치 않고, 매 리다이렉트마다 재조회하는
    것으로 그 창을 최대한 좁힌다).
"""

import ipaddress
import socket
import urllib.parse

import requests

ALLOWED_SCHEMES = {"http", "https"}
MAX_REDIRECTS = 5


class UnsafeUrlError(ValueError):
    """요청한 주소가 우리 사설망(또는 그에 준하는 대역)을 가리킬 때."""


def _is_unsafe_ip(raw_ip):
    try:
        addr = ipaddress.ip_address(raw_ip)
    except ValueError:
        return True  # 파싱조차 안 되면 안전하다고 볼 근거가 없다 — 막는다
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return (addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _resolve_all(hostname):
    """이 호스트명이 실제로 가리키는 IP 전부. DNS 라운드로빈·이중 스택 대비."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as error:
        raise UnsafeUrlError("DNS 조회 실패: {}".format(error))
    ips = {info[4][0] for info in infos}
    if not ips:
        raise UnsafeUrlError("DNS 조회 결과가 없습니다")
    return ips


def check_public_url(url):
    """url이 공인 주소를 가리키면 그대로 돌려준다. 아니면 UnsafeUrlError를 낸다."""
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeUrlError("허용되지 않는 scheme: {}".format(scheme or "(없음)"))
    hostname = parsed.hostname
    if not hostname:
        raise UnsafeUrlError("호스트명이 없습니다")
    for ip in _resolve_all(hostname):
        if _is_unsafe_ip(ip):
            raise UnsafeUrlError("사설·예약 대역으로 확인됨: {} -> {}".format(hostname, ip))
    return url


def safe_get(url, **kwargs):
    """requests.get과 같은 자리에 쓴다 — 매 리다이렉트마다 사설망 여부를 다시 본다.

    requests의 allow_redirects=True(기본값)는 첫 주소만 검사하고 그 뒤로는 무엇이든
    따라간다. 그래서 여기서는 자동 리다이렉트를 끄고, 응답이 3xx면 Location을 직접
    검사한 뒤에만 따라간다.
    """
    kwargs = dict(kwargs)
    kwargs["allow_redirects"] = False
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        check_public_url(current)
        response = requests.get(current, **kwargs)
        if getattr(response, "is_redirect", False) or getattr(response, "is_permanent_redirect", False):
            location = response.headers.get("Location")
            if not location:
                return response
            current = urllib.parse.urljoin(current, location)
            continue
        return response
    raise UnsafeUrlError("리다이렉트가 {}회를 넘었습니다".format(MAX_REDIRECTS))
