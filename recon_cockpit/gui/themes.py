"""Local desktop palette based on the owner's Swiss Industrial references."""

THEMES = {
    "dark": {
        "background": "#0D1721", "surface": "#14212D", "raised": "#1A2B39",
        "border": "#304452", "text": "#F0F4F8", "muted": "#AEC0CD",
        "input": "#101C26", "accent": "#FF7B2C", "accent_text": "#16100C",
        "selection": "#354D5F", "success": "#74DAB1", "warning": "#FFC27D",
        "error": "#FFACAD", "rail": "#09131C", "rail_text": "#CAD6DF",
        "rail_muted": "#94AABB", "badge": "#233D36",
    },
    "light": {
        "background": "#EDF0F2", "surface": "#FFFFFF", "raised": "#F5F7F8",
        "border": "#CAD2D9", "text": "#17212B", "muted": "#526373",
        "input": "#FFFFFF", "accent": "#F57625", "accent_text": "#17100A",
        "selection": "#D9E8F2", "success": "#176546", "warning": "#875017",
        "error": "#A52B32", "rail": "#18222C", "rail_text": "#DEE5EB",
        "rail_muted": "#ADBDC9", "badge": "#E2F3EB",
    },
}


def palette(name):
    """Return detached colors, keeping theme changes local to the view."""
    if name not in THEMES:
        raise ValueError("unknown_desktop_theme")
    return dict(THEMES[name])
