from spake2plus import __version__

def banner():
    print(
        f"""
███████ ██████   █████  ██   ██ ███████ ██████  ██████  ██      ██    ██ ███████ 
██      ██   ██ ██   ██ ██  ██  ██           ██ ██   ██ ██      ██    ██ ██      
███████ ██████  ███████ █████   █████    █████  ██████  ██      ██    ██ ███████ 
     ██ ██      ██   ██ ██  ██  ██      ██      ██      ██      ██    ██      ██ 
███████ ██      ██   ██ ██   ██ ███████ ███████ ██      ███████  ██████  ███████
                                                                          v{__version__} 
    """
    )