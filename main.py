#!/usr/bin/env python3
"""
WiFi Auto Test -- automated Wi-Fi PMKID vulnerability testing.
Entry point. DI container initialization + web server + orchestrator.
"""

import argparse
import os
import signal
import sys

from wifi_auto_test.ap_manager import LinuxAPManager
from wifi_auto_test.attack import HcxdumpAttack, AirodumpAttack, HybridAttack
from wifi_auto_test.config import JsonConfigStore
from wifi_auto_test.core.orchestrator import Orchestrator
from wifi_auto_test.logger import FileWebSocketLogger
from wifi_auto_test.scanner import WashScanner, WashParser
from wifi_auto_test.state import SqliteStateRepository
from wifi_auto_test.utils import ProcessRunner
from wifi_auto_test.web.server import create_app
from wifi_auto_test.web.ws_manager import WebSocketManager


def detect_installer():
    if os.path.exists("/etc/os-release"):
        with open("/etc/os-release") as f:
            content = f.read().lower()
            if "arch" in content:
                from wifi_auto_test.installer import PacmanInstaller
                return PacmanInstaller()
            elif "debian" in content or "ubuntu" in content:
                from wifi_auto_test.installer import AptInstaller
                return AptInstaller()
    return None


def main():
    parser = argparse.ArgumentParser(description="WiFi Auto Test")
    parser.add_argument("--test-interface", help="Interface for testing")
    parser.add_argument("--ap-interface", help="Interface for AP")
    parser.add_argument("--ap-ssid", help="AP SSID")
    parser.add_argument("--ap-password", help="AP password")
    parser.add_argument("--install-deps", action="store_true", help="Install dependencies")
    parser.add_argument("--headless", action="store_true", help="Do not start AP")
    parser.add_argument("--config", default="settings.json", help="Config path")
    args = parser.parse_args()

    config = JsonConfigStore(args.config)

    if args.test_interface:
        config.set("test_interface", args.test_interface)
    if args.ap_interface:
        config.set("ap_interface", args.ap_interface)
    if args.ap_ssid:
        config.set("ap_ssid", args.ap_ssid)
    if args.ap_password:
        config.set("ap_password", args.ap_password)
    config.save()

    # 1. Create logger (without WS first)
    logger = FileWebSocketLogger(log_dir="./logs")

    # 2. Create WS manager
    ws_manager = WebSocketManager()

    # 3. Wire them together after both exist
    logger.set_ws_manager(ws_manager)

    if args.install_deps:
        installer = detect_installer()
        if installer:
            logger.info("Installing dependencies...")
            if installer.install_all():
                logger.info("Dependencies installed")
            else:
                logger.error("Dependency installation failed")
                sys.exit(1)
        else:
            logger.warning("Could not detect package manager")

    test_iface = config.get("test_interface")
    ap_iface = config.get("ap_interface")

    if not test_iface:
        logger.error("test_interface not specified (--test-interface)")
        sys.exit(1)

    runner = ProcessRunner()
    scanner = WashScanner(
        interface=test_iface,
        parser=WashParser(),
        process_runner=runner,
        scan_interval=config.get("scan_interval_seconds"),
    )

    hcxdump = HcxdumpAttack(
        interface=test_iface,
        output_dir=config.get("output_dir"),
        timeout=config.get("attack_timeout_seconds"),
        process_runner=ProcessRunner(),
        logger=logger.info,
    )
    airodump = AirodumpAttack(
        interface=test_iface,
        output_dir=config.get("output_dir"),
        timeout=config.get("attack_timeout_seconds"),
        process_runner=ProcessRunner(),
        logger=logger.info,
    )
    attack = HybridAttack(hcxdump=hcxdump, airodump=airodump)

    repo = SqliteStateRepository()

    orchestrator = Orchestrator(
        scanner=scanner,
        attack_engine=attack,
        state_repo=repo,
        config=config,
        logger=logger.info,
    )

    ap_manager = None
    if not args.headless and ap_iface:
        ap_manager = LinuxAPManager(logger=logger.info)
        ap_manager.setup_ap(
            interface=ap_iface,
            ssid=config.get("ap_ssid"),
            password=config.get("ap_password"),
            ip_cidr=config.get("ap_ip"),
            dhcp_range=config.get("ap_dhcp_range"),
        )

    app = create_app(
        orchestrator=orchestrator,
        state_repo=repo,
        logger=logger,
        ws_manager=ws_manager,
    )

    shutdown_in_progress = False

    def on_signal(signum, frame):
        nonlocal shutdown_in_progress
        if shutdown_in_progress:
            os._exit(1)
        shutdown_in_progress = True
        logger.info("Received shutdown signal")
        orchestrator.shutdown()
        if ap_manager:
            ap_manager.stop_ap()
        os._exit(0)

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    orchestrator.start()

    import uvicorn
    host = config.get("web_host")
    port = config.get("web_port")
    logger.info(f"Web server: http://{host}:{port}/")
    uvicorn.run(app, host=host, port=port, log_level="warning")


if __name__ == "__main__":
    main()
