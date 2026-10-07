# Safety, setup, and scope

These are single-player PC research projects. Back up saves before testing. Do not use these tables in multiplayer, competitive modes, or anti-cheat-protected sessions.

1. Match the game edition and executable to the table. Offsets are not guaranteed across updates.
2. Start Cheat Engine and select the correct game process. Review the table's embedded scripts before allowing Lua execution.
3. Load only one version at a time. Enable its initialization entry if provided, then test one feature at a time.
4. Disable damage, freeze, speed, and timer modifiers around tutorials, bosses, scripted encounters, and cutscenes until proven safe.
5. If a problem appears, disable the feature. Restart the game for a clean comparison: disabling a memory edit does not always reverse its effects.
6. Teleports do not guarantee collision-safe destinations. Where available, save a safe position first and use Undo Teleport if necessary.

Development scripts are not needed to use a distributed .CT. They may read or WRITE another process's memory. Review parameters and source before running them. Some research scripts require third-party dependencies or tools which are deliberately not bundled here.

The Python and PowerShell research files retain their original working layout under development/work. Embedded Auto Assembler and Lua scripts are preserved inside the .CT files. Experimental research tools are not polished end-user commands. Historical absolute installation paths and local dependency assumptions may need adjustment.

This is a source/artifact archive, not a verbatim transcript or a complete recovery of every intermediate edit. A missing version is reported as missing rather than recreated.