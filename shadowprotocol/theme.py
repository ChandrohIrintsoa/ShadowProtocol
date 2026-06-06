"""
Theme System - RK_Pairip aesthetic (Production Grade)
"""

class Colors:
    """ANSI Color codes - RK_Pairip palette"""
    CYAN = '\033[96m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    GREY = '\033[90m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RESET = '\033[0m'


class Box:
    """Unicode box drawing"""
    TL = '\u250c'
    TR = '\u2510'
    BL = '\u2514'
    BR = '\u2518'
    H = '\u2500'
    V = '\u2502'


class Theme:
    """Terminal theme configuration"""

    @staticmethod
    def banner(title: str, width: int = 80) -> str:
        """Generate banner"""
        line = Box.H * width
        return f"""{Colors.CYAN}{Box.TL}{line}{Box.TR}{Colors.RESET}
{Colors.CYAN}{Box.V}{Colors.RESET} {Colors.BOLD}{Colors.CYAN}{title.center(width-2)}{Colors.RESET}{Colors.CYAN} {Box.V}{Colors.RESET}
{Colors.CYAN}{Box.BL}{line}{Box.BR}{Colors.RESET}"""

    @staticmethod
    def section(title: str, width: int = 80) -> str:
        """Generate section header"""
        return f"\n{Colors.CYAN}> {Colors.BOLD}{title}{Colors.RESET}\n{Colors.GREY}{'\u2500'*width}{Colors.RESET}\n"

    @staticmethod
    def error(msg: str) -> str:
        """Format error message"""
        return f"{Colors.RED}{Colors.BOLD}[!] ERROR{Colors.RESET} {msg}"

    @staticmethod
    def success(msg: str) -> str:
        """Format success message"""
        return f"{Colors.GREEN}{Colors.BOLD}[+]{Colors.RESET} {msg}"

    @staticmethod
    def info(msg: str) -> str:
        """Format info message"""
        return f"{Colors.CYAN}{Colors.BOLD}[*]{Colors.RESET} {msg}"

    @staticmethod
    def warning(msg: str) -> str:
        """Format warning message"""
        return f"{Colors.YELLOW}{Colors.BOLD}[!]{Colors.RESET} {msg}"

    @staticmethod
    def prompt(msg: str) -> str:
        """Format input prompt"""
        return f"{Colors.CYAN}> {Colors.RESET}{msg}"

    @staticmethod
    def stat(label: str, value: str) -> str:
        """Format stat line"""
        return f"{Colors.GREY}{label.ljust(20)}{Colors.RESET} {Colors.CYAN}{Colors.BOLD}{value}{Colors.RESET}"


class Banner:
    """ASCII Banners - RK_Pairip style"""

    SHADOWPROTOCOL = f"""{Colors.CYAN}{Colors.BOLD}
\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
\u2551  ShadowProtocol - Binary Patcher Pro v3.0  \u2551
\u2551  Radare2 + Flutter + APK + 6 Modes        \u2551
\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255d
{Colors.RESET}"""

    MODE_A = f"{Colors.GREEN}{Colors.BOLD}[MODE A]{Colors.RESET} {Colors.CYAN}Manual Assisted (pptool){Colors.RESET}"
    MODE_B = f"{Colors.GREEN}{Colors.BOLD}[MODE B]{Colors.RESET} {Colors.CYAN}Auto-Patching{Colors.RESET}"
    MODE_C = f"{Colors.GREEN}{Colors.BOLD}[MODE C]{Colors.RESET} {Colors.CYAN}Raw Radare2{Colors.RESET}"
    MODE_D = f"{Colors.GREEN}{Colors.BOLD}[MODE D]{Colors.RESET} {Colors.CYAN}Flutter Patcher{Colors.RESET}"
    MODE_E = f"{Colors.GREEN}{Colors.BOLD}[MODE E]{Colors.RESET} {Colors.CYAN}Find Functions{Colors.RESET}"
    MODE_F = f"{Colors.GREEN}{Colors.BOLD}[MODE F]{Colors.RESET} {Colors.CYAN}Manifest Patcher{Colors.RESET}"
